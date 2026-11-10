package app

import (
	"context"
	"errors"
	"time"
)

// Run 启动定时流水线：刷新 → 探测 → 纯净度，外加定时落盘。
//
// 为什么是链式而不是三个独立定时器：探测的对象来自刷新结果，
// 纯净度又希望优先覆盖「本轮新出现的 IP」。三个各自跑的定时器会带来
// 「探测到一半，名单换了」和「同一段时间里连着打上游」两个问题。
// 定时器只负责「到点了就叫一声」，真正能不能开工由各 busy 闸门决定。
func (a *App) Run(ctx context.Context) {
	// 开机先按容量上限裁一次：上限可能在程序停着的时候被改小（改了配置，或者旧版本
	// 升上来时池子已经涨过上限），别让第一轮探测按超标的池子排班。
	//
	// 放在 Run 而不是 New：`sources` 这类只读命令也走 New()，不该随手删节点写盘。
	// 走到这里已经是常驻进程，裁完直接落盘，免得每次启动都重裁一遍。
	if n := a.trimToCapacity(); n > 0 {
		a.log.Printf("[app] 启动时按容量上限裁掉 %d 个节点", n)
		if err := a.store.Save(); err != nil {
			a.log.Printf("[app] 启动裁剪后保存节点池失败: %v", err)
		}
	}

	intervals := []struct {
		name    string
		current func() time.Duration
		fn      func()
	}{
		{"refresh", func() time.Duration { return a.Config().Sources.RefreshInterval() }, a.tickRefresh},
		{"purity", func() time.Duration { return a.Config().Purity.Interval() }, a.tickPurity},
		{saveTick, func() time.Duration { return time.Minute }, a.tickSave},
	}
	for _, it := range intervals {
		if it.current() <= 0 {
			continue
		}
		go loop(ctx, it.current, it.fn)
	}

	go a.probeLoop(ctx)

	// 启动序列：池子是空的就先刷一轮，让界面开起来就有东西看；
	// 已有数据（重启场景）则沿用磁盘上的，等到点再刷。
	go func() {
		if a.store.Count() == 0 {
			a.tickRefresh()
		} else {
			a.log.Printf("[app] 沿用磁盘节点池（%d 个节点），等定时器到点再刷新", a.store.Count())
		}
		a.tickProbe()
		// 补测轮要等一小时，不能挡住纯净度扫描，所以另起一个 goroutine。
		go a.probeRetry(ctx)
		a.tickPurity()
	}()

	<-ctx.Done()
	// 退出前尽力落盘一次。任务本身由各自的 ctx 取消（见 Cancel/busy）。
	if a.store.Dirty() || a.purity.CacheSize() > 0 {
		if err := a.SaveState(); err != nil {
			a.log.Printf("[app] 退出前保存失败: %v", err)
		}
	}
	a.log.Printf("[app] 调度器已停止")
}

const saveTick = "save"

// loop 每隔「current() 当场算出来的时长」调一次 fn。间隔是每圈重读的，不是开局
// 定死：界面上改了刷新/纯净度间隔，下一圈就按新值等，不用重启进程。
// 填 0（关掉）就每分钟重查一次，重新打开后能自己恢复。
func loop(ctx context.Context, current func() time.Duration, fn func()) {
	for {
		d := current()
		if d <= 0 {
			d = time.Minute
		}
		if !sleepCtx(ctx, d) {
			return
		}
		fn()
	}
}

// sleepCtx 睡到 d 过去或 ctx 结束；返回 false 表示该退了。
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (a *App) tickRefresh() {
	if _, err := a.Refresh(context.Background()); err != nil {
		a.logTask("定时刷新", err)
	}
	// 刷新完顺手测一轮：新名单里的节点此刻还没有任何本地观测。
	if a.Config().Probe.Enabled {
		if _, err := a.ProbeRound(context.Background(), ProbeOptions{}); err != nil {
			a.log.Printf("[app] 刷新后探测跳过: %v", err)
		}
	}
}

func (a *App) tickProbe() {
	if !a.Config().Probe.Enabled {
		return
	}
	if _, err := a.ProbeRound(context.Background(), ProbeOptions{}); err != nil {
		a.logTask("定时探测", err)
	}
}

// probeLoop 是探测自己的节拍：到点跑一轮，然后隔 unknown_retry_minutes 补测一轮。
//
// 不用通用的 loop：一轮里包含「等一小时再补测」，把它塞进通用循环会把
// 下一次探测的节拍拖偏（变成 6h+1h）；所以补测另起 goroutine，这里只管等。
// 间隔每轮重读：界面上把探测间隔从 6 小时改成 1 小时，下一轮就是 1 小时。
func (a *App) probeLoop(ctx context.Context) {
	for {
		cfg := a.Config()
		interval := cfg.Probe.Interval()
		if !cfg.Probe.Enabled || interval <= 0 {
			// 关掉就每分钟重查，界面上重新打开后下一轮自动恢复。
			if !sleepCtx(ctx, time.Minute) {
				return
			}
			continue
		}
		if !sleepCtx(ctx, interval) {
			return
		}
		a.tickProbe()
		go a.probeRetry(ctx)
	}
}

// probeRetry 隔 unknown_retry_minutes 对「说不清」的 TCP 节点补测一轮。
// 对齐 mirror 的「unknown 结果可以用富余容量在一小时后重试」；这一轮不计入
// 淘汰用的连续失败轮数，否则一轮被算两轮、节点会提前一倍被删掉。
//
// 只补 TCP：UDP 节点对硬重置探测基本就是不回包，补一百次也还是 unknown。
func (a *App) probeRetry(ctx context.Context) {
	wait := a.Config().Probe.UnknownRetry()
	if !a.Config().Probe.Enabled || wait <= 0 {
		return
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	if _, err := a.ProbeRound(ctx, ProbeOptions{
		RetryPass: true,
		Selection: "suspect",
		Protocols: []string{"tcp"},
	}); err != nil {
		// 「已经有一轮探测在跑」是正常撞车，不算故障。
		if errors.Is(err, context.Canceled) || err.Error() == "已经有一轮探测在跑" {
			return
		}
		a.log.Printf("[app] unknown 补测跳过: %v", err)
	}
}

func (a *App) tickPurity() {
	if !a.Config().Purity.Enabled {
		return
	}
	if _, err := a.PurityScan(context.Background(), PurityOptions{}); err != nil {
		a.logTask("定时纯净度扫描", err)
	}
}

// logTask 区分「被取消」和「真失败」：界面上点一下取消按钮不该在日志里
// 留一条看起来像故障的记录。
func (a *App) logTask(what string, err error) {
	if errors.Is(err, context.Canceled) {
		a.log.Printf("[app] %s已取消", what)
		return
	}
	a.log.Printf("[app] %s失败: %v", what, err)
}

func (a *App) tickSave() {
	if !a.store.Dirty() {
		return
	}
	if err := a.SaveState(); err != nil {
		a.log.Printf("[app] 定时保存失败: %v", err)
	}
}
