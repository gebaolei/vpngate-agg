package store

import (
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gebaolei/vpngate-agg/internal/model"
)

// Filter 是列表查询条件。零值表示「不限制」。
type Filter struct {
	Q               string   // 模糊匹配 hostname / IP / 运营商 / 留言 / 国家
	Countries       []string // 国家码，"?" 表示未知
	Protocols       []string // tcp / udp
	Levels          []string // stable reachable unknown flaky down untested
	MinPurity       *int
	MaxPurity       *int
	MaxPing         *int64 // 单位 ms，按 PingSource 选的那个口径
	PingSource      string // best(默认) / local / upstream / cloudflare
	ResidentialOnly bool
	PurityOnly      bool
	FreshOnly       bool // 只看最新官方快照里还在的
	HasProbeLog     bool
	Sort            string
	Desc            bool
	Offset          int
	Limit           int
	IDs             []string // 精确取一批（导出选中用）
}

// ListResult 是一次列表查询的结果。
type ListResult struct {
	Total  int           `json:"total"`
	Offset int           `json:"offset"`
	Limit  int           `json:"limit"`
	Items  []*model.Node `json:"items"`
	Level  string        `json:"-"` // 内部用：本次生效的排序口径
}

// List 按条件过滤 + 排序 + 分页。返回的是深拷贝，可以直接给 HTTP 层序列化。
func (s *Store) List(f Filter) ListResult {
	s.mu.RLock()
	src := make([]*model.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		src = append(src, n)
	}
	s.mu.RUnlock()

	wantIDs := map[string]bool{}
	for _, id := range f.IDs {
		wantIDs[id] = true
	}
	q := strings.ToLower(strings.TrimSpace(f.Q))
	countries := lowerSet(f.Countries)
	protos := lowerSet(f.Protocols)
	levels := lowerSet(f.Levels)

	var items []*model.Node
	for _, n := range src {
		if len(wantIDs) > 0 && !wantIDs[n.ID] {
			continue
		}
		if len(countries) > 0 {
			code := n.CountryCode
			if code == "" {
				code = "?"
			}
			if !countries[strings.ToLower(code)] {
				continue
			}
		}
		if len(protos) > 0 && !protos[strings.ToLower(n.Proto)] {
			continue
		}
		if len(levels) > 0 && !levels[model.HealthLevel(n.Health)] {
			continue
		}
		if f.MinPurity != nil || f.MaxPurity != nil {
			if n.Purity == nil {
				continue // 没测过纯净度的节点不参与纯净度筛选，否则永远筛不出东西
			}
			if f.MinPurity != nil && n.Purity.Score < *f.MinPurity {
				continue
			}
			if f.MaxPurity != nil && n.Purity.Score > *f.MaxPurity {
				continue
			}
		}
		if f.PurityOnly && n.Purity == nil {
			continue
		}
		if f.ResidentialOnly && (n.Residential == nil || !*n.Residential) {
			continue
		}
		if f.FreshOnly && !(n.InLatestSource != nil && *n.InLatestSource) {
			continue
		}
		if f.HasProbeLog && n.Probe == nil {
			continue
		}
		if f.MaxPing != nil {
			p := pingSource(n, f.PingSource)
			if p <= 0 || p > *f.MaxPing {
				continue // 没延迟数据的同样不参与该筛选
			}
		}
		if q != "" && !matchQuery(n, q) {
			continue
		}
		items = append(items, n)
	}

	sortNodes(items, f.Sort, f.Desc, f.PingSource)

	total := len(items)
	if f.Offset > total {
		f.Offset = total
	}
	items = items[f.Offset:]
	if f.Limit > 0 && len(items) > f.Limit {
		items = items[:f.Limit]
	}
	out := make([]*model.Node, 0, len(items))
	for _, n := range items {
		out = append(out, cloneNode(n))
	}
	return ListResult{Total: total, Offset: f.Offset, Limit: f.Limit, Items: out}
}

// localPing 是本服务自己的观测：EWMA → 最近一次成功的 RTT，**不含官方 Ping**。
//
// 这就是界面上「延迟」列显示的那个数，也是 best 口径排序/筛选用的那个数：
// 两边必须是同一个值，否则会出现「列上写着待测试，排序却按官方 44ms 把它
// 排到前面」这种自相矛盾（和 level 那套「显示与筛选同一个值」是同一个道理）。
// 官方 Ping 只在调用方显式要 ping_source=upstream 时才参与。
func localPing(n *model.Node) int64 {
	if n.Health.EWMAPingMS > 0 {
		return n.Health.EWMAPingMS
	}
	if n.Probe != nil && n.Probe.OK && n.Probe.RTTMS > 0 {
		return n.Probe.RTTMS
	}
	return 0
}

// pingSource 按指定口径取延迟。三个口径不能混：官方 Ping 是别人那张网看到的，
// EWMA 是你这张网的实测，Cloudflare 的 connect_ms 是 mirror Worker 的观测。
//
// 已判定不可达（level=down）的节点一律返回 0。延迟数只由成功的探测喂出来，
// 不清空也不按时间衰减（见 ComputeHealth），留着就会出现两件坑人的事：
// 按延迟升序把已经挂掉的节点排到前面，以及 max_ping 把「历史上很快」当成
// 「现在满足条件」。返回 0 在这两条路径上的语义就是「这个指标上没有这个
// 节点」，和 min_purity 对没测过的处理是同一套约定；节点本身还在结果里，
// 只是不参与延迟这个维度。
func pingSource(n *model.Node, src string) int64 {
	// cloneNode 会算好 Level；手造/旧快照里的节点可能没这个字段，补一遍。
	level := n.Health.Level
	if level == "" {
		level = model.HealthLevel(n.Health)
	}
	if level == "down" {
		return 0
	}
	switch strings.ToLower(src) {
	case "upstream":
		return n.UpstreamPingMS
	case "local":
		if n.Probe != nil && n.Probe.OK {
			return n.Probe.RTTMS
		}
		return n.Health.EWMAPingMS
	case "cloudflare":
		if n.CFProbe != nil && n.CFProbe.ConnectMS != nil {
			return *n.CFProbe.ConnectMS
		}
		return 0
	default:
		// best：只看自己测的。官方 Ping 不兜底 —— 否则延迟列上写着
		// 「待测试」的节点会被官方那个数塞进排序前面。
		// （统计卡片和地图的国家中位延迟是另一套口径，见 store.pingOf。）
		return localPing(n)
	}
}

// matchQuery 做宽松的模糊匹配：空格分词，全部命中才算。
func matchQuery(n *model.Node, q string) bool {
	hay := strings.ToLower(strings.Join([]string{
		n.HostName, n.IP, n.Country, n.CountryCode, n.Operator, n.Message,
		n.Server, strconv.Itoa(n.Port), n.Cipher, n.LogType,
		providerOrg(n),
	}, " "))
	for _, term := range strings.FieldsFunc(q, func(r rune) bool { return unicode.IsSpace(r) }) {
		if !strings.Contains(hay, term) {
			return false
		}
	}
	return true
}

func providerOrg(n *model.Node) string {
	if n.Purity == nil {
		return ""
	}
	return strings.Join([]string{n.Purity.Org, n.Purity.ISP, n.Purity.ASN, n.Purity.Domain}, " ")
}

func lowerSet(xs []string) map[string]bool {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		x = strings.ToLower(strings.TrimSpace(x))
		if x != "" {
			m[x] = true
		}
	}
	return m
}

// sortNodes 排序。
//
// 两条规则是实战里最容易被忽略的：
//  1. 没测过的值一律排最后，不管升降序 —— 否则「按延迟升序」会把一堆没测过
//     的节点顶到最前面，看起来像它们最快。
//  2. 「越大越好」的字段（分数、速度、纯净度）内部先取负数归一成「越小越好」，
//     这样 desc 的含义在所有列上都是用户点的那个方向。
func sortNodes(items []*model.Node, key string, desc bool, pingSrc string) {
	key = strings.ToLower(key)
	if key == "" {
		key = "recommend"
	}

	// hostname 是唯一按字符串排的列，单独处理。
	if key == "hostname" {
		sort.Slice(items, func(i, j int) bool {
			a, b := strings.ToLower(items[i].HostName), strings.ToLower(items[j].HostName)
			if a != b {
				if desc {
					return a > b
				}
				return a < b
			}
			return items[i].ID < items[j].ID
		})
		return
	}

	type keyFn struct {
		has    func(*model.Node) bool
		val    func(*model.Node) float64
		invert bool // 原生值越大越好
	}
	var kf keyFn
	switch key {
	case "ping":
		kf = keyFn{has: func(n *model.Node) bool { return pingSource(n, pingSrc) > 0 },
			val: func(n *model.Node) float64 { return float64(pingSource(n, pingSrc)) }}
	case "rtt":
		kf = keyFn{has: func(n *model.Node) bool { return n.Probe != nil && n.Probe.OK },
			val: func(n *model.Node) float64 {
				if n.Probe == nil {
					return 0
				}
				return float64(n.Probe.RTTMS)
			}}
	case "purity":
		kf = keyFn{has: func(n *model.Node) bool { return n.Purity != nil },
			val: func(n *model.Node) float64 {
				if n.Purity == nil {
					return 0
				}
				return float64(n.Purity.Score)
			}, invert: true}
	case "score":
		kf = keyFn{has: func(n *model.Node) bool { return n.UpstreamScore > 0 },
			val: func(n *model.Node) float64 { return float64(n.UpstreamScore) }, invert: true}
	case "speed":
		kf = keyFn{has: func(n *model.Node) bool { return n.UpstreamSpeedBps > 0 },
			val: func(n *model.Node) float64 { return float64(n.UpstreamSpeedBps) }, invert: true}
	case "sessions":
		kf = keyFn{has: func(n *model.Node) bool { return n.Sessions > 0 },
			val: func(n *model.Node) float64 { return float64(n.Sessions) }, invert: true}
	case "tests":
		kf = keyFn{has: func(n *model.Node) bool { return n.Health.Tests > 0 },
			val: func(n *model.Node) float64 { return float64(n.Health.Tests) }, invert: true}
	case "cf":
		kf = keyFn{
			has: func(n *model.Node) bool { return n.CFProbe != nil },
			val: func(n *model.Node) float64 {
				if n.CFProbe == nil {
					return 0
				}
				// 状态 + 时间新旧：同样 reachable，越新的观测越靠前。
				switch n.CFProbe.Status {
				case "reachable":
					return 3 + freshness01(n.CFProbe.CheckedAt)
				case "unknown":
					return 2
				case "unreachable":
					return 1
				}
				return 0
			}, invert: true}
	case "seen":
		kf = keyFn{has: func(n *model.Node) bool { return !n.LastSeen.IsZero() },
			val: func(n *model.Node) float64 { return float64(-timeU(n.LastSeen)) }}
	case "recommend":
		kf = keyFn{has: func(*model.Node) bool { return true },
			val: func(n *model.Node) float64 { return -RecommendScore(n, pingSrc) }}
	default:
		kf = keyFn{has: func(*model.Node) bool { return true },
			val: func(n *model.Node) float64 { return -RecommendScore(n, pingSrc) }}
	}

	cmp := func(a, b *model.Node) bool {
		ha, hb := kf.has(a), kf.has(b)
		if ha != hb {
			return ha // 有数据的排前面，跟方向无关
		}
		va, vb := kf.val(a), kf.val(b)
		if kf.invert {
			va, vb = -va, -vb
		}
		if va != vb {
			if desc {
				return va > vb
			}
			return va < vb
		}
		return a.ID < b.ID
	}
	sort.Slice(items, func(i, j int) bool { return cmp(items[i], items[j]) })
}

// freshness01 把一个时间折算成 0~1 的新鲜度，用来在同状态内二次排序。
func freshness01(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	age := time.Since(t)
	switch {
	case age <= time.Hour:
		return 0.99
	case age <= 6*time.Hour:
		return 0.9
	case age <= 24*time.Hour:
		return 0.75
	case age <= 72*time.Hour:
		return 0.5
	default:
		return 0.2
	}
}

func timeU(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// RecommendScore 是一个 0-100 的「值不值得连」综合分，列表默认排序用它。
//
// 组合方式（权重写死在这里，界面上要解释得清）：
//   - 可达性 40：稳定 40 / 可达 32 / 未知 18 / 抖动 12 / 未测 10 / 挂了 4
//   - 延迟 30：≤80ms 30，≤150 26，≤300 20，≤600 12，>600 4，没数据 8
//   - 纯净度 30：score×0.3，没测过给 12（中性，不奖不罚）
//   - 加分：志愿者家宽 +8、Cloudflare 也观测到可达 +4（一周内的观测才算）
//   - 减分：VPN Gate 自营机房 −6、Cloudflare 观测不可达 −6（同上，一周内才算）、
//     超过 48 小时没被官方名单见过 −4
func RecommendScore(n *model.Node, pingSrc string) float64 {
	var sc float64
	switch model.HealthLevel(n.Health) {
	case "stable":
		sc += 40
	case "reachable":
		sc += 32
	case "unknown":
		sc += 18
	case "flaky":
		sc += 12
	case "untested":
		sc += 10
	case "down":
		sc += 4
	}
	switch p := pingSource(n, pingSrc); {
	case p <= 0:
		sc += 8
	case p <= 80:
		sc += 30
	case p <= 150:
		sc += 26
	case p <= 300:
		sc += 20
	case p <= 600:
		sc += 12
	default:
		sc += 4
	}
	if n.Purity != nil {
		sc += float64(n.Purity.Score) * 0.3
	} else {
		sc += 12
	}
	if n.Residential != nil && *n.Residential {
		sc += 8
	}
	// Cloudflare 观测来自已移除的第三方源，现在只读不写：只在一周内参与加减分。
	// 过期的观测留在盘上仅供查看，不能继续影响排名 —— 否则一个早已修好的节点
	// 会被一条半年前的结论按住。
	if cfFresh(n, time.Now().UTC()) {
		switch n.CFProbe.Status {
		case "reachable":
			sc += 4
		case "unreachable":
			sc -= 6
		}
	}
	if n.Purity != nil && n.Purity.IPType == model.TypeVpngateOwn {
		sc -= 6
	}
	if time.Since(n.LastSeen) > 48*time.Hour {
		sc -= 4
	}
	if sc < 0 {
		sc = 0
	}
	if sc > 100 {
		sc = 100
	}
	return sc
}

// cfProbeDays 是第三方 Cloudflare 观测的保质期（天）。
const cfProbeDays = 7

// cfFresh 判断这份 Cloudflare 观测还在不在有效期内。前端用同名的规则标灰，
// 两边口径要一致。
func cfFresh(n *model.Node, now time.Time) bool {
	if n == nil || n.CFProbe == nil || n.CFProbe.CheckedAt.IsZero() {
		return false
	}
	return now.Sub(n.CFProbe.CheckedAt) <= cfProbeDays*24*time.Hour
}
