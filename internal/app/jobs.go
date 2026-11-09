package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/model"
	"github.com/gebaolei/vpngate-agg/internal/probe"
	"github.com/gebaolei/vpngate-agg/internal/purity"
	"github.com/gebaolei/vpngate-agg/internal/store"
)

// ProbeOptions 是一轮探测的筛选参数。零值走配置默认。
type ProbeOptions struct {
	Limit     int
	Selection string   // all | fresh | suspect（空=用 probe.selection）
	Countries []string // 大写国家码
	Protocols []string // tcp | udp
	IDs       []string // 只测这些节点（界面「测这一个/测选中」）
	Force     bool     // 忽略「刚测过」和「长期失败就跳过」
	// RetryPass 标出这是「说不清」节点的补测轮：它不计入淘汰用的连续失败轮数。
	// mirror 的规则是「连续三轮有效的六小时探测失败」，一轮里数两次会把删除提前一倍。
	RetryPass   bool
	Handshake   *bool // 覆盖 probe.handshake（快速模式传 false）
	Concurrency int   // 覆盖 probe.concurrency
}

// Target 是一次探测的目标端点（probe.Target 的别名，方便界面/CLI 直接用）。
type Target = probe.Target

// Targets 按条件挑出待探测的端点，同时返回各类被跳过的数量。
//
// 挑选顺序很关键：一轮只能测 MaxNodesPerRound 个，谁先进这一轮要有一个稳定的、
// 讲得出口的理由。这里的优先级是：
//  1. 从没测过的（信息增量最大）
//  2. 最久没测的（结论最陈旧）
//  3. 推荐分高的（同等待遇下先测更值得关心的）
func (a *App) Targets(o ProbeOptions) (targets []Target, skipped map[string]int) {
	skipped = map[string]int{}
	all := a.store.All()
	// 整轮用同一份配置快照：这个循环每个节点都要读几个参数，边跑边读既浪费，
	// 也可能中途被界面改了开关、一半节点按新规则筛、另一半按旧的。
	cfg := a.Config()
	countries := upperSet(o.Countries)
	protos := lowerSet(o.Protocols)
	ids := map[string]bool{}
	for _, id := range o.IDs {
		ids[id] = true
	}
	selection := o.Selection
	if selection == "" {
		selection = cfg.Probe.Selection
	}
	if len(ids) > 0 {
		selection = "ids"
	}
	now := time.Now()

	var cands []*model.Node
	for _, n := range all {
		if len(ids) > 0 && !ids[n.ID] {
			continue
		}
		if len(countries) > 0 {
			code := n.CountryCode
			if code == "" {
				code = "?"
			}
			if !countries[code] {
				skipped["国家不符"]++
				continue
			}
		}
		if len(protos) > 0 && !protos[n.Proto] {
			skipped["协议不符"]++
			continue
		}
		switch selection {
		case "fresh":
			if !(n.InLatestSource != nil && *n.InLatestSource) {
				skipped["不在本轮官方名单"]++
				continue
			}
		case "suspect":
			switch model.HealthLevel(n.Health) {
			case "down", "unknown", "flaky":
			default:
				skipped["状态良好，本轮跳过"]++
				continue
			}
		case "all", "ids":
		default:
			skipped["未知 selection，按 all 处理"]++
		}

		host, port, proto := n.Addr()
		if host == "" {
			skipped["缺主机地址"]++
			continue
		}
		if port <= 0 || port > 65535 {
			skipped["端口未知"]++
			continue
		}
		if proto != "tcp" && proto != "udp" {
			skipped["proto 异常"]++
			continue
		}
		// 刚测过的不重复测：界面上连点两次、或者定时器撞上手动触发，
		// 不该把同一个端口在 10 分钟内打两遍。
		if !o.Force && !n.Health.LastTry.IsZero() && now.Sub(n.Health.LastTry) < 10*time.Minute {
			skipped["10 分钟内刚测过"]++
			continue
		}
		// 连着失败且很久没恢复的节点先放一放，把额度留给有变化的。
		// 用 LastOK 而不是 LastTry 判断：LastOK 为零表示从没成功过，那更要测。
		if !o.Force && cfg.Probe.SkipDownForHours > 0 && n.Health.FailStreak >= 2 &&
			n.Health.LastOK.IsZero() == false &&
			now.Sub(n.Health.LastOK) > time.Duration(cfg.Probe.SkipDownForHours)*time.Hour {
			skipped["长期失败，暂缓"]++
			continue
		}
		if !o.Force && cfg.Probe.SkipDownForHours > 0 && n.Health.FailStreak >= 3 &&
			n.Health.LastOK.IsZero() && !n.Health.LastTry.IsZero() &&
			now.Sub(n.Health.LastTry) < time.Duration(cfg.Probe.SkipDownForHours)*time.Hour {
			// 从没成功过、而且刚试过：这轮先放过
			skipped["从未成功且刚试过"]++
			continue
		}
		cands = append(cands, n)
	}

	limit := o.Limit
	if limit <= 0 {
		limit = cfg.Probe.MaxNodesPerRound
	}
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		// 没测过的优先
		if (a.Health.Tests == 0) != (b.Health.Tests == 0) {
			return a.Health.Tests == 0
		}
		if !a.Health.LastTry.Equal(b.Health.LastTry) {
			if a.Health.LastTry.IsZero() {
				return true
			}
			if b.Health.LastTry.IsZero() {
				return false
			}
			return a.Health.LastTry.Before(b.Health.LastTry)
		}
		if s1, s2 := store.RecommendScore(a, "best"), store.RecommendScore(b, "best"); s1 != s2 {
			return s1 > s2
		}
		return a.ID < b.ID
	})
	if limit > 0 && len(cands) > limit {
		skipped["超出本轮上限"] += len(cands) - limit
		cands = cands[:limit]
	}

	seen := map[string]bool{}
	for _, n := range cands {
		host, port, proto := n.Addr()
		key := proto + "|" + host + ":" + fmt.Sprint(port)
		if seen[key] {
			skipped["同端点重复"]++
			continue
		}
		seen[key] = true
		targets = append(targets, Target{ID: n.ID, Host: host, Port: port, Proto: proto, Reason: selection})
	}
	return targets, skipped
}

// ProbeRound 跑一轮探测。同一时刻只允许一轮。
func (a *App) ProbeRound(ctx context.Context, o ProbeOptions) (*model.JobState, error) {
	ctx, done, ok := a.busy("probe")
	if !ok {
		return nil, errors.New("已经有一轮探测在跑")
	}
	defer done()

	targets, skipped := a.Targets(o)
	// 本轮开始时间：跑完之后要用它把「本轮明确失败」结算成连续失败轮数。
	roundStart := time.Now().UTC()
	opt := probe.RoundOptions{
		Concurrency: a.Config().Probe.Concurrency,
		HistoryKeep: a.Config().Probe.HistoryKeep,
		BatchSize:   32,
		BatchDelay:  1500 * time.Millisecond,
	}
	if o.Concurrency > 0 {
		opt.Concurrency = o.Concurrency
	}
	handshake := a.Config().Probe.Handshake
	if o.Handshake != nil {
		handshake = *o.Handshake
	}
	prober := probe.New(probe.Options{
		TCPTimeout:       time.Duration(a.Config().Probe.TCPTimeoutSeconds) * time.Second,
		UDPTimeout:       time.Duration(a.Config().Probe.UDPTimeoutSeconds) * time.Second,
		HandshakeTimeout: time.Duration(a.Config().Probe.HandshakeSeconds) * time.Second,
		Handshake:        handshake,
		Retries:          a.Config().Probe.Retries,
		AllowPrivateIPs:  a.Config().Sources.Vpngate.AllowPrivateIPs,
	})

	msg := fmt.Sprintf("目标 %d", len(targets))
	if o.RetryPass {
		msg = "补测轮：" + msg
	}
	if len(skipped) > 0 {
		msg += "（跳过 " + summarize(skipped) + "）"
	}
	job := &model.JobState{Kind: "probe", Status: "running", StartedAt: time.Now().UTC(), Total: len(targets), Message: msg}
	a.store.SetJob("probe", job)
	a.bus.Publish("probe:start", map[string]any{
		"total": len(targets), "skipped": skipped, "retry": o.RetryPass,
	})

	if len(targets) == 0 {
		job.Status = "done"
		job.EndedAt = time.Now().UTC()
		job.Message += "；本轮没有目标"
		a.store.SetJob("probe", job)
		a.bus.Publish("probe:done", map[string]any{"ok": true, "stats": a.store.Stats()})
		return job, nil
	}

	var lastPublish time.Time
	var lastDone int
	res, err := probe.RunRound(ctx, prober, targets, opt,
		func(batch map[string]*model.ProbeResult) {
			a.store.ApplyProbeResults(batch, a.Config().Probe.HistoryKeep)
		},
		func(d, okCount int, last string) {
			job.Done, job.OK, job.LastNode = d, okCount, last
			// 进度事件按时间节流：500ms 或每 20 个一条，不然 SSE 会被刷屏。
			if time.Since(lastPublish) < 500*time.Millisecond && d-lastDone < 20 {
				return
			}
			lastPublish, lastDone = time.Now(), d
			a.bus.Publish("probe:progress", map[string]any{
				"done": d, "total": len(targets), "ok": okCount, "last": last,
			})
		})
	if res != nil {
		job = res
	}
	if job.Message == "" {
		job.Message = msg
	} else {
		job.Message = msg + "；" + job.Message
	}
	a.store.SetJob("probe", job)
	// 结算本轮的「连续明确失败轮数」：提前淘汰就看这个数，补测轮不计。
	a.store.UpdateFailRounds(roundStart, !o.RetryPass)
	if err := a.SaveState(); err != nil {
		a.log.Printf("[app] 探测后保存失败: %v", err)
	}
	a.bus.Publish("probe:done", map[string]any{
		"ok": job.Status == "done", "status": job.Status,
		"ok_count": job.OK, "failed": job.Failed, "unknown": job.Skipped,
		"stats": a.store.Stats(),
	})
	a.log.Printf("[app] 探测完成: %s（成功 %d / 明确失败 %d / 不确定 %d）", job.Message, job.OK, job.Failed, job.Skipped)
	return job, err
}

// ProbeOne 测单个节点，结果同样进历史。界面上的「测一下」按钮走这里。
func (a *App) ProbeOne(ctx context.Context, id string) (*model.ProbeResult, error) {
	n, ok := a.store.Get(id)
	if !ok {
		return nil, errors.New("节点不存在")
	}
	host, port, proto := n.Addr()
	if port <= 0 {
		return nil, errors.New("这个节点没有可探测的端口")
	}
	prober := probe.New(probe.Options{
		TCPTimeout:       time.Duration(a.Config().Probe.TCPTimeoutSeconds) * time.Second,
		UDPTimeout:       time.Duration(a.Config().Probe.UDPTimeoutSeconds) * time.Second,
		HandshakeTimeout: time.Duration(a.Config().Probe.HandshakeSeconds) * time.Second,
		Handshake:        a.Config().Probe.Handshake,
		Retries:          a.Config().Probe.Retries,
		AllowPrivateIPs:  a.Config().Sources.Vpngate.AllowPrivateIPs,
	})
	res := prober.Probe(ctx, Target{ID: id, Host: host, Port: port, Proto: proto})
	a.store.ApplyProbeResults(map[string]*model.ProbeResult{id: res}, a.Config().Probe.HistoryKeep)
	a.bus.Publish("probe:one", map[string]any{"id": id, "ok": res.OK, "rtt_ms": res.RTTMS, "service": res.Service})
	return res, nil
}

// PurityOptions 是一轮纯净度扫描的筛选参数。
type PurityOptions struct {
	Limit     int
	Selection string // all | fresh | unchecked（空=用 purity.selection）
	Countries []string
	IPs       []string // 只查这些 IP
	Force     bool     // 忽略 TTL 重查
}

// PurityScan 扫一批 IP。按 IP 而不是按节点：同一 IP 上多个节点共享结论。
func (a *App) PurityScan(ctx context.Context, o PurityOptions) (*model.JobState, error) {
	ctx, done, ok := a.busy("purity")
	if !ok {
		return nil, errors.New("已经有一轮纯净度扫描在跑")
	}
	defer done()

	queries, skipped := a.purityQueries(o)
	job := &model.JobState{
		Kind: "purity", Status: "running", StartedAt: time.Now().UTC(), Total: len(queries),
		Message: fmt.Sprintf("待查 IP %d（跳过 %s）", len(queries), summarize(skipped)),
	}
	a.store.SetJob("purity", job)
	a.bus.Publish("purity:start", map[string]any{"total": len(queries), "sources": a.purity.Enabled()})

	if len(queries) == 0 {
		job.Status = "done"
		job.EndedAt = time.Now().UTC()
		job.Message += "；本轮没有目标（可能都已新鲜）"
		a.store.SetJob("purity", job)
		a.bus.Publish("purity:done", map[string]any{"ok": true, "stats": a.store.Stats()})
		return job, nil
	}

	var lastPublish time.Time
	var lastDone int
	// onResult 是在查询线程里被调用的（多个），所以计数交给 CheckIPs 自己做，
	// 这里只负责写回节点和推事件 —— 自己再数一遍会数出竞态来的结果。
	okCount, failCount := a.purity.CheckIPs(ctx, queries, a.Config().Purity.Concurrency,
		func(q purity.Query, r *model.PurityResult, err error) {
			if r == nil {
				return
			}
			// 结论按 IP 广播到该 IP 上的所有节点。
			a.store.ApplyPurity(r)
			a.bus.Publish("purity:result", map[string]any{
				"ip": r.IP, "score": r.Score, "level": r.Level, "type": r.IPType,
				"confidence": r.Confidence, "err": errText(err),
			})
		},
		func(d, total, ok, fail int, last string) {
			job.Done, job.OK, job.Failed, job.LastNode = d, ok, fail, last
			// 进度事件按时间节流：500ms 或每 5 个一条。
			if time.Since(lastPublish) < 500*time.Millisecond && d-lastDone < 5 {
				return
			}
			lastPublish, lastDone = time.Now(), d
			a.bus.Publish("purity:progress", map[string]any{"done": d, "total": total, "ok": ok, "failed": fail})
		})

	job.EndedAt = time.Now().UTC()
	switch {
	case ctx.Err() != nil:
		job.Status = "cancelled"
	default:
		job.Status = "done"
	}
	job.OK, job.Failed = okCount, failCount
	job.Message += fmt.Sprintf("；成功 %d，失败 %d", okCount, failCount)
	// 家宽判定要用到纯净度，扫完顺手刷一遍。
	a.RefreshResidential()
	a.store.SetJob("purity", job)
	if n := a.purity.Prune(); n > 0 {
		a.log.Printf("[app] 清理过期纯净度缓存 %d 条", n)
	}
	if err := a.SaveState(); err != nil {
		a.log.Printf("[app] 纯净度扫描后保存失败: %v", err)
	}
	a.bus.Publish("purity:done", map[string]any{
		"ok": job.Status == "done", "checked": okCount, "failed": failCount,
		"stats": a.store.Stats(), "sources": a.purity.Stats(),
	})
	a.log.Printf("[app] 纯净度扫描完成: %s", job.Message)
	return job, ctx.Err()
}

// purityQueries 挑出要查的 IP。
func (a *App) purityQueries(o PurityOptions) ([]purity.Query, map[string]int) {
	skipped := map[string]int{}
	countries := upperSet(o.Countries)
	selection := o.Selection
	if selection == "" {
		selection = a.Config().Purity.Selection
	}
	if len(o.IPs) > 0 {
		selection = "ips"
	}
	byID := map[string]bool{}
	for _, ip := range o.IPs {
		byID[ip] = true
	}
	limit := o.Limit
	if limit <= 0 {
		limit = a.Config().Purity.MaxNodesPerRound
	}

	seen := map[string]bool{}
	var out []purity.Query
	for _, n := range a.store.All() {
		if n.IP == "" {
			skipped["缺 IP"]++
			continue
		}
		if seen[n.IP] {
			continue
		}
		if len(byID) > 0 && !byID[n.IP] {
			skipped["IP 不在指定列表"]++
			continue
		}
		if len(countries) > 0 {
			code := n.CountryCode
			if code == "" {
				code = "?"
			}
			if !countries[code] {
				continue
			}
		}
		switch selection {
		case "fresh":
			if !(n.InLatestSource != nil && *n.InLatestSource) {
				skipped["不在本轮官方名单"]++
				continue
			}
		case "unchecked":
			if cached := a.purity.Cached(n.IP); cached != nil && !o.Force {
				skipped["缓存仍然新鲜"]++
				// 缓存还在，但节点上可能还没落结论（新出现的同 IP 节点）：补一下。
				a.store.ApplyPurity(cached)
				// 同 IP 的其他节点不算第二笔：计数按 IP，界面才能跟总数对得上。
				seen[n.IP] = true
				continue
			}
		case "all", "ips":
		default:
			skipped["未知 selection，按 unchecked 处理"]++
		}
		seen[n.IP] = true
		out = append(out, purity.Query{IP: n.IP, HostName: n.HostName, Force: o.Force})
		if limit > 0 && len(out) >= limit {
			skipped["达到本轮上限"]++
			break
		}
	}
	return out, skipped
}

// CheckPurityForIP 查单个 IP（界面的「查纯净度」按钮）。
func (a *App) CheckPurityForIP(ctx context.Context, ip, hostname string, force bool) (*model.PurityResult, error) {
	r, err := a.purity.Check(ctx, purity.Query{IP: ip, HostName: hostname, Force: force})
	if r != nil {
		a.store.ApplyPurity(r)
		a.RefreshResidential()
		a.bus.Publish("purity:result", map[string]any{"ip": r.IP, "score": r.Score, "level": r.Level, "type": r.IPType})
	}
	return r, err
}

// CheckPurityForNode 查某个节点的出口 IP。
func (a *App) CheckPurityForNode(ctx context.Context, id string, force bool) (*model.PurityResult, error) {
	n, ok := a.store.Get(id)
	if !ok {
		return nil, errors.New("节点不存在")
	}
	return a.CheckPurityForIP(ctx, n.IP, n.HostName, force)
}

// ---------- 小工具 ----------

func upperSet(xs []string) map[string]bool {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		// 必须 trim：界面传过来的国家码带空格时，筛不中又不报错，
		// 用户只会看到「筛选没反应」。
		if x = strings.ToUpper(strings.TrimSpace(x)); x != "" {
			m[x] = true
		}
	}
	return m
}

func lowerSet(xs []string) map[string]bool {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		if x = strings.ToLower(strings.TrimSpace(x)); x != "" {
			m[x] = true
		}
	}
	return m
}

// summarize 把「原因 → 数量」压成一行，按数量降序，日志和任务消息都用它。
func summarize(m map[string]int) string {
	type kv struct {
		k string
		v int
	}
	list := make([]kv, 0, len(m))
	for k, v := range m {
		if v > 0 {
			list = append(list, kv{k, v})
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})
	out := ""
	for i, e := range list {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("%s %d", e.k, e.v)
	}
	if out == "" {
		return "0"
	}
	return out
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
