package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/config"
)

func pi(v int) *int { return &v }

func ptrBool(v bool) *bool { return &v }

// 界面上的数值项（最长缺席天数、最大失败轮数、探测间隔/并发/两个超时、纯净度限流）
// 必须三件事都成立：改得动、落得了盘、越界的值被拒且**不碰内存里那份**。
// 落盘最容易被忘 —— 界面显示已改，一重启又回到默认值，比不給改更糟。
func TestPatchConfigNumbers(t *testing.T) {
	a := testApp(t)

	cfg, err := a.PatchConfig(ConfigPatch{
		KeepDays:               pi(30),
		PurgeFailRounds:        pi(5),
		MaxNodes:               pi(1200),
		ProbeIntervalMinutes:   pi(120),
		ProbeConcurrency:       pi(128),
		ProbeTCPTimeoutSeconds: pi(8),
		ProbeUDPTimeoutSeconds: pi(6),
		PurityRPM:              pi(90),
	})
	if err != nil {
		t.Fatalf("改数值项失败: %v", err)
	}
	want := []struct {
		what   string
		got    int
		expect int
	}{
		{"sources.keep_days", cfg.Sources.KeepDays, 30},
		{"sources.purge_fail_rounds", cfg.Sources.PurgeFailRounds, 5},
		{"sources.max_nodes", cfg.Sources.MaxNodes, 1200},
		{"probe.interval_minutes", cfg.Probe.IntervalMinutes, 120},
		{"probe.concurrency", cfg.Probe.Concurrency, 128},
		{"probe.tcp_timeout_seconds", cfg.Probe.TCPTimeoutSeconds, 8},
		{"probe.udp_timeout_seconds", cfg.Probe.UDPTimeoutSeconds, 6},
		{"purity.requests_per_minute", cfg.Purity.RequestsPerMinute, 90},
	}
	for _, w := range want {
		if w.got != w.expect {
			t.Errorf("%s = %d，期望 %d", w.what, w.got, w.expect)
		}
	}

	// 落盘并读回来对一遍：确认写的就是刚改的这些值。
	path := cfg.Path()
	if path == "" {
		t.Fatal("PatchConfig 之后没有配置文件路径，说明没落盘")
	}
	back, err := config.Load(path)
	if err != nil {
		t.Fatalf("读回配置文件失败: %v", err)
	}
	if back.Sources.KeepDays != 30 || back.Probe.Concurrency != 128 || back.Purity.RequestsPerMinute != 90 {
		t.Errorf("磁盘上的配置不对: keep_days=%d concurrency=%d rpm=%d",
			back.Sources.KeepDays, back.Probe.Concurrency, back.Purity.RequestsPerMinute)
	}
	if back.Sources.MaxNodes != 1200 {
		t.Errorf("磁盘上的 max_nodes = %d，期望 1200", back.Sources.MaxNodes)
	}

	// 越界一律拒，而且拒了以后内存里那份不能被改动一半。
	for _, bad := range []ConfigPatch{
		{KeepDays: pi(0)},         // 缺席 0 天等于「本轮没出现就删」，太危险
		{KeepDays: pi(500)},       // 明显是填错
		{PurgeFailRounds: pi(0)},  // 连负 0 轮就删，等于缺席即删
		{PurgeFailRounds: pi(99)}, // 永远碰不到，等于这功能失效
		{MaxNodes: pi(-1)},        // 要「不限」得写 0，负数是填错
		{MaxNodes: pi(200000)},    // 多打几个 0：探测一轮就是几个小时
		{ProbeIntervalMinutes: pi(0)},
		{ProbeIntervalMinutes: pi(100000)},
		{ProbeConcurrency: pi(0)},
		{ProbeConcurrency: pi(5000)}, // 512 以上就是在自己机器上制造 SYN 风暴
		{ProbeTCPTimeoutSeconds: pi(0)},
		{ProbeUDPTimeoutSeconds: pi(600)},
		{PurityRPM: pi(0)},
		{PurityRPM: pi(5000)}, // 免费源会被限流到整轮失败
	} {
		if _, err := a.PatchConfig(bad); err == nil {
			t.Errorf("越界补丁没被拒: %+v", bad)
		}
	}
	cur := a.Config()
	if cur.Sources.KeepDays != 30 || cur.Probe.Concurrency != 128 || cur.Purity.RequestsPerMinute != 90 {
		t.Errorf("被拒的补丁动到了内存配置: keep_days=%d concurrency=%d rpm=%d",
			cur.Sources.KeepDays, cur.Probe.Concurrency, cur.Purity.RequestsPerMinute)
	}

	// 补测轮不能顶到下一轮头上：把探测间隔改得比补测等待还短时，
	// Validate 会把补测等待折半，否则同一轮会被算两次连负。
	cfg2, err := a.PatchConfig(ConfigPatch{ProbeIntervalMinutes: pi(30)})
	if err != nil {
		t.Fatalf("改探测间隔失败: %v", err)
	}
	if cfg2.Probe.UnknownRetryMinutes >= cfg2.Probe.IntervalMinutes {
		t.Errorf("补测等待 %v 没短于探测间隔 %v", cfg2.Probe.UnknownRetry(), cfg2.Probe.Interval())
	}
}

// 探测间隔要能被「当场读到」：定时器每圈重读配置，界面改成 10 分钟就等于下一轮
// 10 分钟，而不是等进程重启。这条测的就是那个「每圈重读」。
func TestLoopRereadsInterval(t *testing.T) {
	var mu sync.Mutex
	gap := 10 * time.Millisecond
	var hits []time.Time
	done := make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		loop(ctx,
			func() time.Duration {
				mu.Lock()
				defer mu.Unlock()
				return gap
			},
			func() {
				mu.Lock()
				hits = append(hits, time.Now())
				n := len(hits)
				if n == 1 {
					gap = 300 * time.Millisecond // 模拟界面上把间隔改大
				}
				mu.Unlock()
			})
		close(done)
	}()

	time.Sleep(800 * time.Millisecond)
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(hits) < 3 {
		t.Fatalf("只跑了 %d 次，测试窗口不够长", len(hits))
	}
	first := hits[1].Sub(hits[0])
	if first < 200*time.Millisecond {
		t.Errorf("改了间隔后第二圈只等了 %v，说明间隔是开局定死的", first)
	}
}

// 间隔填 0（界面上关掉）时循环不能退出，也不能空转：每圈重查一次（实现里是每分钟），
// 重新打开后自己恢复。「恢复」那一段不在单测里等完整一分钟，下面那条用例只钉
// 「关着就不跑」和「循环还活着」两点。
func TestLoopWaitsWhenIntervalDisabled(t *testing.T) {
	var mu sync.Mutex
	on := false
	calls := 0
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		loop(ctx, func() time.Duration {
			mu.Lock()
			defer mu.Unlock()
			if !on {
				return 0 // 界面上关掉了
			}
			return time.Millisecond
		}, func() {
			mu.Lock()
			calls++
			mu.Unlock()
		})
		close(done)
	}()

	time.Sleep(120 * time.Millisecond)
	mu.Lock()
	quiet := calls
	mu.Unlock()
	if quiet != 0 {
		t.Errorf("关着的时候还是跑了 %d 次", quiet)
	}

	// 循环本体还活着：没因为间隔为 0 就 return。
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("取消后 loop 没退出来")
	}
}

// 官方主站是必开来源：接口不该接受把它关掉的请求（ConfigPatch 里就没这个字段）。
// 「两个来源全关」这条守卫现在只剩配置文件里把主站也关了才碰得到 —— 这里就是测那条。
func TestPatchConfigKeepsVpngateOn(t *testing.T) {
	a := testApp(t)

	// 界面把镜像关掉：允许，主站还在。
	cfg, err := a.PatchConfig(ConfigPatch{MirrorsEnabled: ptrBool(false)})
	if err != nil {
		t.Fatalf("关掉镜像站应允许: %v", err)
	}
	if !cfg.Sources.Vpngate.Enabled {
		t.Error("官方主站应一直开着")
	}

	// 配置文件里把主站也关了（连不上 www.vpngate.net 的部署），这时再把镜像站关掉要拦住。
	a.setCfg(func(c *config.Config) { c.Sources.Vpngate.Enabled = false })
	if _, err := a.PatchConfig(ConfigPatch{MirrorsEnabled: ptrBool(false)}); err == nil {
		t.Error("两个来源全关应被拒绝")
	} else if !strings.Contains(err.Error(), "不能全关") {
		t.Errorf("错误信息不好懂: %q", err)
	}
	// 被拒的那次应当整个不做：内存里还是「两个都关」的原样，没有被改成半个状态。
	if cur := a.Config(); cur.Sources.Vpngate.Enabled || cur.Sources.Mirrors.Enabled {
		t.Errorf("被拒的补丁改动了内存配置: %+v", cur.Sources)
	}
}

// 界面上把容量上限改小：当场裁一次，不用等下一轮刷新。否则用户改完数字看到的
// 还是旧池子，只能得出「这功能没生效」的结论。
func TestPatchConfigTrimsOnCapacityChange(t *testing.T) {
	a := testApp(t)
	seed(t, a,
		node("v1:a", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:b", "8.8.8.2", "JP", "tcp", 1194),
		node("v1:c", "8.8.8.3", "JP", "tcp", 1194),
		node("v1:d", "8.8.8.4", "JP", "tcp", 1194),
		node("v1:e", "8.8.8.5", "JP", "tcp", 1194),
	)
	if got := a.Store().Count(); got != 5 {
		t.Fatalf("种子池 = %d，期望 5", got)
	}

	if _, err := a.PatchConfig(ConfigPatch{MaxNodes: pi(2)}); err != nil {
		t.Fatalf("改上限失败: %v", err)
	}
	if got := a.Store().Count(); got != 2 {
		t.Errorf("上限改到 2 后池子 = %d，期望当场裁到 2", got)
	}

	// 改大不该删任何东西。
	if _, err := a.PatchConfig(ConfigPatch{MaxNodes: pi(50)}); err != nil {
		t.Fatalf("放宽上限失败: %v", err)
	}
	if got := a.Store().Count(); got != 2 {
		t.Errorf("放宽上限后池子 = %d，期望还是 2", got)
	}

	// 0 = 不限：也不该删。
	if _, err := a.PatchConfig(ConfigPatch{MaxNodes: pi(0)}); err != nil {
		t.Fatalf("设成不限失败: %v", err)
	}
	if got := a.Store().Count(); got != 2 {
		t.Errorf("不限时池子 = %d，期望还是 2", got)
	}

	// 非法值要拒，且不能动配置。
	if _, err := a.PatchConfig(ConfigPatch{MaxNodes: pi(-5)}); err == nil {
		t.Error("负数上限该被拒")
	}
	if got := a.Config().Sources.MaxNodes; got != 0 {
		t.Errorf("被拒的补丁改了上限: %d", got)
	}
}

// 上限是在程序停着的时候改的（旧版本攒下的池子已经涨过上限）：常驻启动就得先裁一次，
// 上限是在程序停着的时候改的（旧版本攒下的池子已经涨过上限）：常驻启动就得先裁一次，
// 否则第一轮探测要按超标的池子排班。
//
// 探测和纯净度在这里全关掉：Run 的启动序列会顺手跑一轮，测试不该在临时目录里
// 留下没人等的写入（t.TempDir 的清理会撞上它，CI 上就是 directory not empty）。
func TestRunTrimsOverCapacityPool(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = dir
	cfg.Probe.Enabled = false
	cfg.Purity.Enabled = false
	cfg.Sources.MaxNodes = 0 // 旧版本没这个概念：先把池子攒起来
	a, err := New(cfg, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	seed(t, a,
		node("v1:a", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:b", "8.8.8.2", "JP", "tcp", 1194),
		node("v1:c", "8.8.8.3", "JP", "tcp", 1194),
		node("v1:d", "8.8.8.4", "JP", "tcp", 1194),
		node("v1:e", "8.8.8.5", "JP", "tcp", 1194),
	)
	if err := a.SaveState(); err != nil {
		t.Fatal(err)
	}
	if got := a.Store().Count(); got != 5 {
		t.Fatalf("不限时应攒到 5 个，实得 %d", got)
	}

	cfg.Sources.MaxNodes = 2
	b, err := New(cfg, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	// New 不动手：`sources` 这类只读命令也走它，删节点得等到常驻启动。
	if got := b.Store().Count(); got != 5 {
		t.Errorf("New 不应当裁节点，实得 %d", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		b.Run(ctx)
		close(done)
	}()
	waitForCount(t, b, 2)
	// 裁过要落盘：否则每次启动都重裁一遍，日志里永远是同一句。
	// 直接读快照而不是再开一个 App：多开一处写入就多一处跟临时目录清理打架的地方。
	waitForPoolNodes(t, dir, 2)
	cancel()
	<-done // Run 退出前还会尽力落一次盘，等它写完再让临时目录收尾

	cfg.Sources.MaxNodes = 0
	c, err := New(cfg, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Store().Count(); got != 2 {
		t.Errorf("重读磁盘后池子 = %d，期望那次裁剪已经落盘", got)
	}
}

// waitForPoolNodes 等磁盘上的快照里节点数变成 want。写盘是 tmp + rename，
// 所以能读到就是写完了。
func waitForPoolNodes(t *testing.T, dir string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if blob, err := os.ReadFile(filepath.Join(dir, "pool.json")); err == nil {
			var doc struct {
				Nodes map[string]json.RawMessage `json:"nodes"`
			}
			if err := json.Unmarshal(blob, &doc); err == nil && len(doc.Nodes) == want {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("等磁盘上的池子变成 %d 超时", want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitForCount 等常驻流水线把池子裁到 want：Run 里的裁剪是同步的，但测试把它
// 跑在 goroutine 里，所以得轮一下而不是赌顺序。
func waitForCount(t *testing.T, a *App, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for a.Store().Count() != want && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := a.Store().Count(); got != want {
		t.Fatalf("池子 = %d，期望裁到 %d", got, want)
	}
}
