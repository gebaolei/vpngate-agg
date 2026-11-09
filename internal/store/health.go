package store

import (
	"time"

	"github.com/gebaolei/vpngate-agg/internal/model"
)

// ComputeHealth 从探测历史算可信用指标。
//
// 「可达 / 不可达 / 未知」必须分开，这是整个工具的判断基准：
//   - 连上并（可选）拿到服务回包 → 可达
//   - 明确收到 RST（refused）或网络层不可达 → 不可达
//   - 超时、UDP 无回包 → 未知
//
// 超时不能算死亡：跨境链路上丢一个 SYN 太常见，把「我们这边看不到」写成
// 「节点死了」会让界面上一轮刷新就杀掉一半节点。实测 UDP 节点对硬重置包
// 基本不响应（SoftEther 的行为），它们会长期落在未知，这是设计如此。
func ComputeHealth(samples []model.ProbeSample, keep int) model.ProbeHealth {
	if keep > 0 && len(samples) > keep {
		samples = samples[len(samples)-keep:]
	}
	h := model.ProbeHealth{Tests: len(samples)}
	if len(samples) == 0 {
		return h
	}
	var ewma float64
	var ewmaStarted bool
	for _, s := range samples {
		if s.OK {
			h.Successes++
			if h.LastOK.IsZero() || s.At.After(h.LastOK) {
				h.LastOK = s.At
			}
			if s.RTTMS > 0 {
				if !ewmaStarted {
					ewma = float64(s.RTTMS)
					ewmaStarted = true
				} else {
					// α=0.4：一两次抖动不会被抹平，链路变差也能在一两轮内反映出来。
					ewma = 0.4*float64(s.RTTMS) + 0.6*ewma
				}
			}
		}
		if s.At.After(h.LastTry) {
			h.LastTry = s.At
		}
	}
	if ewmaStarted {
		h.EWMAPingMS = int64(ewma + 0.5)
	}
	h.SuccessPct = 100 * float64(h.Successes) / float64(h.Tests)

	// 连续失败次数从最新往回数。
	for i := len(samples) - 1; i >= 0; i-- {
		if samples[i].OK {
			break
		}
		h.FailStreak++
	}

	last := samples[len(samples)-1]
	switch {
	case last.OK:
		t := true
		h.Alive = &t
	case last.Service == model.ServiceRefused || last.Service == model.ServiceUnreachable ||
		last.Service == model.ServiceBlocked:
		f := false
		h.Alive = &f
	default:
		// timeout / no-reply / 认不出的失败：结论未知
		h.Alive = nil
	}
	// 置信度：证据数量 × 新鲜度。界面用它决定要不要把结论显示成「已确认」。
	evidence := float64(h.Tests) / 3.0
	if evidence > 1 {
		evidence = 1
	}
	age := time.Since(h.LastTry)
	var fresh float64
	switch {
	case h.LastTry.IsZero():
		fresh = 0
	case age <= 6*time.Hour:
		fresh = 1
	case age <= 24*time.Hour:
		fresh = 0.6
	case age <= 72*time.Hour:
		fresh = 0.35
	default:
		fresh = 0.15
	}
	h.Confidence = evidence * fresh
	// 展示档位同步算好存起来：界面徽章、?level= 筛选、推荐分都读这一个值，
	// 免得前后端各推一遍、推出两套结论（表格里标着已挂、按已挂筛却筛不出）。
	h.Level = model.HealthLevel(h)
	return h
}

// cloneNode 返回一份可安全交给 HTTP 层的深拷贝。
// 池子里的对象会被探测线程改，直接把指针给 encoder 会撞上数据竞争。
func cloneNode(n *model.Node) *model.Node {
	c := *n
	// 档位重新算一遍：老快照里没有 health.level 这个字段，缺了就只能让界面
	// 自己推一套规则，容易出现「显示」和「筛选」两套结论。
	c.Health.Level = model.HealthLevel(c.Health)
	if n.Probe != nil {
		p := *n.Probe
		c.Probe = &p
	}
	if n.Probes != nil {
		c.Probes = append([]model.ProbeSample(nil), n.Probes...)
	}
	if n.Purity != nil {
		p := *n.Purity
		if n.Purity.Providers != nil {
			p.Providers = append([]model.ProviderVerdict(nil), n.Purity.Providers...)
		}
		p.Reasons = append([]string(nil), n.Purity.Reasons...)
		c.Purity = &p
	}
	if n.CFProbe != nil {
		p := *n.CFProbe
		c.CFProbe = &p
	}
	if n.Notes != nil {
		c.Notes = append([]string(nil), n.Notes...)
	}
	if n.Residential != nil {
		v := *n.Residential
		c.Residential = &v
	}
	if n.InLatestSource != nil {
		v := *n.InLatestSource
		c.InLatestSource = &v
	}
	return &c
}
