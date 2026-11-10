package source

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/config"
	"github.com/gebaolei/vpngate-agg/internal/model"
)

// sourceWorkers 是多源并发的闸：一个波次拉完，最坏耗时就是一个单源超时。
// 并发比源数少就会分波次、最坏耗时翻倍；官方接口和镜像站都是缓存页，
// 六个并发对上游不构成压力，再多就成了我们给人刷流量了。
func sourceWorkers(slots int) int {
	if slots < 1 {
		return 1
	}
	if slots > 6 {
		return 6
	}
	return slots
}

// DefaultAPIURL 是官方主站的节点接口。
const DefaultAPIURL = config.DefaultAPI

// 源的优先级。合并时先到先得，但「谁更强」决定字段能不能覆盖。
const (
	kindVpngate = 0
	kindMirror  = 1
)

// Aggregated 是一轮刷新的产出。
type Aggregated struct {
	// Nodes 按身份 ID 去重后的节点，LastSeen 已经刷成本轮时间。
	Nodes map[string]*model.Node
	// Configs 是 sha256 → .ovpn 正文，跨节点去重（实测全站配置高度重复）。
	Configs map[string][]byte
	Stats   []model.SourceStat
	// CountsByURL 给下一轮做「数量骤减」判断。
	CountsByURL   map[string]int
	Mirrors       []model.MirrorEntry
	MirrorFetched time.Time
	MirrorErr     string
	Warnings      []string // 不影响可用性的告警（某站残缺、同源重复等）
	NewCount      int      // 本轮新增的身份数（相对调用方给的旧池）
}

// Aggregate 并发拉全部启用的源（官方主站 + 官方镜像站），按身份 ID 合并。
//
// 只要有一个源成功就返回结果；全部失败才报错，调用方据此保留上一轮的池子。
// prevByURL 是上一轮每个源各自返回的节点数（首轮传空 map）——不能用合并后的
// 总数当基准：主站只返 ~100 个，合并后是 300+，拿 300 去卡单源会把所有源
// 全判成异常。
func Aggregate(ctx context.Context, cfg config.SourcesConfig, client *Client, mirrors *MirrorStore, prevByURL map[string]int) (*Aggregated, error) {
	now := time.Now().UTC()
	agg := &Aggregated{
		Nodes:       map[string]*model.Node{},
		Configs:     map[string][]byte{},
		CountsByURL: map[string]int{},
	}

	type slot struct {
		name string
		url  string
		kind int
	}
	var slots []slot
	if cfg.Vpngate.Enabled {
		slots = append(slots, slot{"vpngate", cfgAPI(cfg), kindVpngate})
	}
	if urls := mirrors.Sources(ctx, cfg.Mirrors, now); len(urls) > 0 {
		for _, u := range urls {
			slots = append(slots, slot{"mirror:" + hostOf(u), u, kindMirror})
		}
	}
	agg.Mirrors, agg.MirrorFetched, agg.MirrorErr = mirrors.Summary()

	per := make([][]RawRow, len(slots))
	stats := make([]model.SourceStat, len(slots))
	var wg sync.WaitGroup
	sem := make(chan struct{}, sourceWorkers(len(slots)))

	for i, s := range slots {
		wg.Add(1)
		go func(i int, s slot) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			stats[i] = model.SourceStat{Name: s.name, URL: s.url, At: now}
			t0 := time.Now()
			rows, via, err := fetchCSV(ctx, client, cfg, s.kind, s.url, prevByURL[s.url])
			stats[i].MS = time.Since(t0).Milliseconds()
			if err != nil {
				stats[i].Err = err.Error()
				return
			}
			stats[i].Nodes = len(rows)
			stats[i].Via = via
			per[i] = rows
			agg.CountsByURL[s.url] = len(rows)
		}(i, s)
	}

	wg.Wait()

	for _, st := range stats {
		agg.Stats = append(agg.Stats, st)
	}

	// 合并顺序 = 优先级：主站 > 官方镜像。主站是实时生成的，镜像是缓存快照：
	// 实测同一节点在镜像里的 Score/Ping/Speed 可能是旧值，所以两边都有时用主站的。
	for _, list := range per {
		for _, row := range list {
			agg.merge(row, now)
		}
	}
	if len(agg.Nodes) == 0 {
		var msgs []string
		for _, s := range agg.Stats {
			if s.Err != "" {
				msgs = append(msgs, s.Name+": "+s.Err)
			}
		}
		if len(msgs) == 0 {
			return nil, errors.New("所有源都返回了 0 个可用节点")
		}
		return nil, fmt.Errorf("所有节点源都失败: %s", strings.Join(msgs, "; "))
	}
	return agg, nil
}

// merge 把一个源给的节点并入聚合结果。
//
// 先到先得，但不是「整条覆盖」：主站给的正文可能缺失（官方接口偶尔不返配置），
// 而镜像给的是另一份缓存。所以这里是「补字段」而不是「换对象」，同时保住
// 已经拿到的配置正文。
func (a *Aggregated) merge(row RawRow, now time.Time) {
	n := row.Node
	if n == nil || n.ID == "" {
		return
	}
	existing, ok := a.Nodes[n.ID]
	if !ok {
		clone := *n
		if clone.FirstSeen.IsZero() {
			clone.FirstSeen = now
		}
		clone.LastSeen = now
		a.Nodes[n.ID] = &clone
		if row.Config != nil && n.ConfigSHA256 != "" {
			a.Configs[n.ConfigSHA256] = row.Config
		}
		return
	}

	// 没带配置正文的来源：只补元数据，不碰连接参数。
	if row.Config == nil {
		if n.InLatestSource != nil {
			existing.InLatestSource = n.InLatestSource
		}
		if !n.FirstSeen.IsZero() && n.FirstSeen.Before(existing.FirstSeen) {
			existing.FirstSeen = n.FirstSeen
		}
		// 之前只见过元数据、连端点都没有，而现在这一路有端点：补上。
		if existing.Server == "" && n.Server != "" {
			existing.Server, existing.Port, existing.Proto = n.Server, n.Port, n.Proto
		}
		existing.LastSeen = now
		return
	}

	// 带配置正文的来源。
	if row.Config != nil && n.ConfigSHA256 != "" {
		if _, have := a.Configs[n.ConfigSHA256]; !have {
			a.Configs[n.ConfigSHA256] = row.Config
		}
	}
	if n.InLatestSource != nil {
		existing.InLatestSource = n.InLatestSource
	}
	if !n.FirstSeen.IsZero() && n.FirstSeen.Before(existing.FirstSeen) {
		existing.FirstSeen = n.FirstSeen
	}
	// 已有正文说明之前那一路更强或同级，连接参数与上游指标就不改了；
	// 只有「之前只在池子里见过、正文缺失」时才整体升级。
	if !existing.ConfigLocal {
		existing.ConfigLocal = true
		existing.ConfigSHA256 = n.ConfigSHA256
		existing.ConfigBytes = n.ConfigBytes
		existing.Server, existing.Port, existing.Proto = n.Server, n.Port, n.Proto
		existing.Cipher, existing.AuthAlgorithm = n.Cipher, n.AuthAlgorithm
		existing.Vendor, existing.HasCerts = n.Vendor, n.HasCerts
		existing.UpstreamScore = n.UpstreamScore
		existing.UpstreamPingMS = n.UpstreamPingMS
		existing.UpstreamSpeedBps = n.UpstreamSpeedBps
		existing.Sessions = n.Sessions
		existing.UptimeSeconds = n.UptimeSeconds
		existing.TotalUsers = n.TotalUsers
		existing.TotalTraffic = n.TotalTraffic
		if n.Country != "" {
			existing.Country, existing.CountryCode = n.Country, n.CountryCode
		}
		existing.Operator, existing.Message, existing.LogType = n.Operator, n.Message, n.LogType
		existing.Notes = appendUnique(nil, n.Notes...)
	}
	existing.LastSeen = now
	existing.LastSource = n.LastSource
	if len(n.Notes) > 0 {
		existing.Notes = appendUnique(existing.Notes, n.Notes...)
	}
}

// cfgAPI 取官方主站地址。留成函数是为了以后要支持多主站时只改一处。
func cfgAPI(cfg config.SourcesConfig) string { return DefaultAPIURL }

// fetchCSV 拉一个 CSV 源（官方主站或官方镜像站），解析 + 数量合理性检查。
//
// 返回的 via 用来告诉界面「数据到底是谁给的」：主站被墙、只有镜像通的时候，
// 这是唯一的线索。
func fetchCSV(ctx context.Context, client *Client, cfg config.SourcesConfig, kind int, u string, prevCount int) ([]RawRow, string, error) {
	src := config.MirrorSource{}
	minNodes, drop := 20, 0
	switch kind {
	case kindVpngate:
		minNodes, drop = cfg.Vpngate.MinNodes, cfg.Vpngate.MaxDropPct
		src.TimeoutSeconds = cfg.Vpngate.TimeoutSeconds
	case kindMirror:
		src = cfg.Mirrors
		minNodes, drop = src.MinNodes, 0 // 镜像轮换取用，数量本来就会变，不做骤减判断
	default:
		return nil, "", fmt.Errorf("未知的 CSV 源类型 %d", kind)
	}
	timeout := time.Duration(src.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 35 * time.Second
	}
	raw, err := client.Get(ctx, u, CSVMaxBytes, timeout)
	if err != nil {
		return nil, "", err
	}
	res, err := ParseCSV(raw)
	if err != nil {
		return nil, "", err
	}
	if err := countPlausible(len(res.Rows), minNodes, prevCount, drop); err != nil {
		return nil, "", err
	}
	via := "direct"
	if kind == kindMirror {
		via = "mirror-site"
	}
	rows := res.Rows
	// 同一源内部去重：完全相同的行合并，同 ID 但连接参数不同的留痕。
	out := make([]RawRow, 0, len(rows))
	seen := map[string]string{} // id → rowHash
	for _, r := range rows {
		id := r.Node.ID
		if id == "" {
			continue
		}
		if prev, ok := seen[id]; ok {
			if prev != r.RowHash {
				r.Node.Notes = appendUnique(r.Node.Notes, "同一源里出现了相同 ID、不同内容的行，保留先出现的那条")
			}
			continue
		}
		seen[id] = r.RowHash
		out = append(out, r)
	}
	if len(out) != len(rows) {
		res.Warnings = append(res.Warnings, fmt.Sprintf("同源重复行 %d 条已合并", len(rows)-len(out)))
	}
	return out, via, nil
}

// countPlausible 是数量合理性检查，不能省。
//
// 传输层中断时读体会报错；但上游给出一个「更短但完整」的响应时，ParseCSV
// 完全成功、不报错，残缺列表会直接覆盖掉好好的节点池。只能靠数量兜底。
// prev 是同一个源上一轮的数量（跨源比没意义）。
func countPlausible(n, min, prev, maxDropPct int) error {
	if min > 0 && n < min {
		return fmt.Errorf("节点数过少(%d < %d)，按异常处理", n, min)
	}
	if prev > 0 && maxDropPct > 0 && n*100 < prev*(100-maxDropPct) {
		return fmt.Errorf("节点数比上一轮(%d)下降超过 %d%%（现在 %d），按异常处理", prev, maxDropPct, n)
	}
	return nil
}

// hostOf 从 URL 里取 host:port，用来给镜像源起名字。
func hostOf(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	return parsed.Host
}

// sortedIDs 稳定顺序，方便日志与测试断言。
func sortedIDs(m map[string]*model.Node) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// appendUnique 追加去重，保持首次出现的顺序。
func appendUnique(dst []string, add ...string) []string {
	seen := make(map[string]bool, len(dst))
	for _, x := range dst {
		seen[x] = true
	}
	for _, x := range add {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		dst = append(dst, x)
	}
	return dst
}

// ipPortOf 拼展示用的地址串。
func ipPortOf(host string, port int) string { return net.JoinHostPort(host, fmt.Sprint(port)) }
