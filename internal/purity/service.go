package purity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/config"
	"github.com/gebaolei/vpngate-agg/internal/model"
)

// mergeVersion 是**汇总规则**的版本（不是文件格式版本）。规则一改，老缓存里的
// 结论就是旧规则算的：启动时拿缓存里已经存下来的各来源结论离线重算一遍，不联网。
// 不重算的后果很实在 —— 缓存 TTL 7 天，界面上会顶着「未知类型 / 不是家宽」整整一周，
// 哪怕新规则早就能判出来。
const mergeVersion = 2

// cacheCap 是缓存条目上限。按 IP 存而不是按节点存：同一 IP 上多个节点
// 共享一份结论（实测 VPN Gate 上换 hostname 不换 IP 的情况很常见）。
const cacheCap = 20000

// cacheFile 是磁盘上的缓存结构。
type cacheFile struct {
	Version int `json:"version"`
	// MergeVer 是这份缓存用哪一版汇总规则算出来的，见 mergeVersion。
	MergeVer  int                            `json:"merge_ver,omitempty"`
	SavedAt   time.Time                      `json:"saved_at"`
	Entries   map[string]*model.PurityResult `json:"entries"`
	PerSource []*SourceStat                  `json:"per_source,omitempty"`
}

// SourceStat 记录某个来源的成功/失败与最后一次错误，界面用它解释
// 「为什么这个 IP 只有一个来源」。
type SourceStat struct {
	Name     string    `json:"name"`
	Enabled  bool      `json:"enabled"`
	NeedsKey bool      `json:"needs_key"`
	HasKey   bool      `json:"has_key"`
	OK       int64     `json:"ok"`
	Failed   int64     `json:"failed"`
	LastErr  string    `json:"last_err,omitempty"`
	LastTry  time.Time `json:"last_try,omitempty"`
	LastMS   int64     `json:"last_ms,omitempty"`
}

// Service 负责查询、限流、缓存和汇总。可并发使用。
type Service struct {
	cfg config.PurityConfig
	h   *http.Client

	providers []Provider
	stats     map[string]*SourceStat

	path  string
	mu    sync.Mutex
	cache map[string]*model.PurityResult
	dirty bool
	// mergeVer 是磁盘上来的规则版本；升级后要落盘，不然每次启动都重算一遍。
	mergeVer int
	// upgradedAtLoad 记下 load 时离线重算改了多少条。必须留着：load 已经替调用方
	// 重算过了，UpgradeCache 再问一遍会看到「版本已最新」而返回 0，于是没人把新
	// 结论同步回节点池 —— 界面上还是旧的。
	upgradedAtLoad int

	// 每个来源一个令牌桶（按 Service 实例隔离，不共用包级变量：
	// 测试里会同时存在多个实例，共用桶会互相干扰）。
	bucketsMu sync.Mutex
	buckets   map[string]*bucket
}

// New 装配来源并读盘缓存。
//
// 免费源（ipquery）默认开；要 key 的来源只有配了 key 才开 ——
// 否则每轮都会攒一堆 401 错误，界面上看起来像坏了。
func New(cfg config.PurityConfig, dataDir string) *Service {
	if cfg.RawKeepBytes == 0 {
		cfg.RawKeepBytes = 900
	}
	s := &Service{
		cfg: cfg,
		h: &http.Client{
			Timeout:   providerTimeout + 2*time.Second,
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, MaxIdleConnsPerHost: 4},
		},
		stats:   map[string]*SourceStat{},
		path:    filepath.Join(dataDir, "purity.json"),
		cache:   map[string]*model.PurityResult{},
		buckets: map[string]*bucket{},
	}
	keys := cfg.Keys
	key := func(name string) string {
		if keys == nil {
			return ""
		}
		return strings.TrimSpace(keys[name])
	}
	candidates := []Provider{
		newBuiltin(),
		ipqueryProvider{key: key("ipquery")},
		ipinfoProvider{token: key("ipinfo")},
		ipregistryProvider{key: key("ipregistry")},
		scamalyticsProvider{key: key("scamalytics")},
		ipqsProvider{key: key("ipqualityscore")},
		abuseipdbProvider{key: key("abuseipdb")},
	}
	for _, p := range candidates {
		st := &SourceStat{Name: p.Name(), NeedsKey: p.NeedsKey(), HasKey: key(p.Name()) != ""}
		st.Enabled = cfg.ProviderEnabled(p.Name(), p.NeedsKey())
		s.stats[p.Name()] = st
		if !st.Enabled {
			continue
		}
		if p.NeedsKey() && !st.HasKey {
			continue
		}
		s.providers = append(s.providers, p)
	}
	if err := s.load(); err != nil {
		fmt.Printf("[purity] 读取缓存失败（忽略，重新查）: %v\n", err)
	}
	return s
}

// Enabled 返回真正参与查询的来源名。
func (s *Service) Enabled() []string {
	out := make([]string, 0, len(s.providers))
	for _, p := range s.providers {
		out = append(out, p.Name())
	}
	return out
}

// Stats 返回各来源的健康状态副本（界面「纯净度设置」页展示）。
func (s *Service) Stats() []SourceStat {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SourceStat, 0, len(s.stats))
	for _, st := range s.stats {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Cached 返回缓存里的结论；过期或没有就返回 nil。
func (s *Service) Cached(ip string) *model.PurityResult {
	return s.cached(ip, false)
}

func (s *Service) cached(ip string, force bool) *model.PurityResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.cache[ip]
	if !ok || r == nil || force {
		return nil
	}
	ttl := time.Duration(s.cfg.TTLHours) * time.Hour
	if ttl <= 0 {
		ttl = 168 * time.Hour
	}
	// 完全没证据的结论（所有来源都失败）只信 6 小时：
	// 免费源临时挂了不该让「无结论」赖在缓存里一周。
	if r.Confidence <= 0 {
		ttl = min(ttl, 6*time.Hour)
	}
	if time.Since(r.CheckedAt) > ttl {
		return nil
	}
	c := *r
	return &c
}

// Check 查一个 IP。命中缓存就直接返回。
//
// 返回的 error 只用于「连一个来源都没跑通且缓存也没有」这种情况；
// 部分来源失败是常态，不算错误，失败详情在 result.Providers 里。
func (s *Service) Check(ctx context.Context, q Query) (*model.PurityResult, error) {
	ip, err := normalizeIP(q.IP)
	if err != nil {
		return nil, err
	}
	q.IP = ip
	if !q.Force {
		if r := s.cached(q.IP, false); r != nil {
			return r, nil
		}
	}
	if len(s.providers) == 0 {
		return nil, errors.New("没有启用任何纯净度来源（检查 purity.providers 与 keys）")
	}

	type out struct {
		sig *Signals
		err error
	}
	ch := make(chan out, len(s.providers))
	var wg sync.WaitGroup
	for _, p := range s.providers {
		wg.Add(1)
		go func(p Provider) {
			defer wg.Done()
			// 内置源不联网，也不占限流额度。
			if p.Name() != "builtin" {
				if err := s.wait(ctx, p.Name()); err != nil {
					ch <- out{err: err}
					return
				}
			}
			cctx, cancel := context.WithTimeout(ctx, providerTimeout+2*time.Second)
			defer cancel()
			t0 := time.Now()
			sig, err := p.Lookup(cctx, q, s.h)
			ms := time.Since(t0).Milliseconds()
			if sig != nil {
				sig.MS = ms
			}
			s.noteResult(p.Name(), sig, err, ms)
			if err != nil {
				if sig == nil {
					sig = &Signals{Name: p.Name(), OK: false, Err: err.Error(), MS: ms, Weight: Weight(p.Name())}
				}
				ch <- out{sig: sig, err: err}
				return
			}
			ch <- out{sig: sig}
		}(p)
	}
	wg.Wait()
	close(ch)

	var sigs []*Signals
	var valid int
	for o := range ch {
		if o.sig != nil {
			sigs = append(sigs, o.sig)
			if o.sig.OK {
				valid++
			}
		}
	}
	res := Merge(q, sigs, MergeOptions{
		MinProviders: s.cfg.MinProviders,
		RawKeepBytes: s.cfg.RawKeepBytes,
	})
	res.TTLHours = s.cfg.TTLHours
	if res.TTLHours <= 0 {
		res.TTLHours = 168
	}
	if valid == 0 {
		// 一条都没通：仍然把「无结论」放进缓存（6 小时），免得每轮都白打一遍 API。
		res.Confidence = 0
	}
	s.put(res)
	if valid == 0 {
		var msgs []string
		for _, sg := range sigs {
			if sg.Err != "" {
				msgs = append(msgs, sg.Name+": "+sg.Err)
			}
		}
		return res, fmt.Errorf("所有来源都失败: %s", strings.Join(msgs, "; "))
	}
	return res, nil
}

// CheckIPs 并发查一批 IP。onResult 在查询线程里被调用（不是单线程），
// 调用方要自己保证写回是原子的（本项目的 store 已经加锁）。
func (s *Service) CheckIPs(ctx context.Context, qs []Query, concurrency int,
	onResult func(q Query, r *model.PurityResult, err error),
	onProgress func(done, total, ok, fail int, last string)) (int, int) {
	if concurrency <= 0 {
		concurrency = s.cfg.Concurrency
	}
	if concurrency <= 0 {
		concurrency = 6
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var okCount, failCount int

	for _, q := range qs {
		select {
		case <-ctx.Done():
			wg.Wait()
			return okCount, failCount
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(q Query) {
			defer wg.Done()
			defer func() { <-sem }()
			res, err := s.Check(ctx, q)
			mu.Lock()
			if err != nil {
				failCount++
			} else {
				okCount++
			}
			done, ok, fail := okCount+failCount, okCount, failCount
			mu.Unlock()
			if onResult != nil {
				onResult(q, res, err)
			}
			if onProgress != nil {
				onProgress(done, len(qs), ok, fail, q.IP)
			}
		}(q)
	}
	wg.Wait()
	return okCount, failCount
}

// ---------- 限流 ----------

// buckets 是每个来源的令牌桶。免费源限流很紧（ipquery 免费档实测几十次/分），
// 全用同一个全局桶会把带 key 的宽裕来源一起卡住，所以按来源分桶。
type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	rate   float64 // 每秒允许的请求数
	cap    float64
}

// rateFor 返回某个来源允许的请求速率（次/秒）。
//
// 免费源用配置里的 requests_per_minute；带 key 的来源按 3 倍算，
// 因为它们的免费档普遍更宽（ipinfo 免费 500 次/月除外，那种是配额而非速率限制，
// 超了会 429，由 noteResult 记进界面）。
func (s *Service) rateFor(name string) float64 {
	s.mu.Lock()
	rpm := s.cfg.RequestsPerMinute
	s.mu.Unlock()
	if rpm <= 0 {
		rpm = 40
	}
	if st := s.stats[name]; st != nil && st.HasKey {
		rpm *= 3
	}
	return float64(rpm) / 60.0
}

// UpdateRPM 动态更新限流频率（次/分钟），重置令牌桶立即生效。
func (s *Service) UpdateRPM(rpm int) {
	if rpm <= 0 {
		rpm = 40
	}
	s.mu.Lock()
	s.cfg.RequestsPerMinute = rpm
	s.mu.Unlock()

	s.bucketsMu.Lock()
	s.buckets = map[string]*bucket{}
	s.bucketsMu.Unlock()
}

func (s *Service) bucketFor(name string) *bucket {
	s.bucketsMu.Lock()
	defer s.bucketsMu.Unlock()
	b, ok := s.buckets[name]
	if !ok {
		rate := s.rateFor(name)
		cap := rate * 5
		if cap < 1 {
			cap = 1
		}
		b = &bucket{tokens: cap, last: time.Now(), rate: rate, cap: cap}
		s.buckets[name] = b
	}
	return b
}

// wait 阻塞到该来源可以再发一次请求，或者 ctx 结束。
func (s *Service) wait(ctx context.Context, name string) error {
	b := s.bucketFor(name)
	for {
		b.mu.Lock()
		now := time.Now()
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.cap {
			b.tokens = b.cap
		}
		b.last = now
		if b.tokens >= 1 {
			b.tokens -= 1
			b.mu.Unlock()
			return nil
		}
		need := (1 - b.tokens) / b.rate
		b.mu.Unlock()
		sleep := time.Duration(need * float64(time.Second))
		if sleep < 20*time.Millisecond {
			sleep = 20 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
	}
}

// ---------- 统计与缓存落盘 ----------

func (s *Service) noteResult(name string, sig *Signals, err error, ms int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.stats[name]
	if !ok {
		st = &SourceStat{Name: name, Enabled: true}
		s.stats[name] = st
	}
	st.LastTry = time.Now().UTC()
	st.LastMS = ms
	if err != nil || (sig != nil && !sig.OK) {
		st.Failed++
		msg := ""
		if err != nil {
			msg = err.Error()
		} else if sig != nil {
			msg = sig.Err
		}
		// 错误信息可能带 IP 和长响应，截一下再存，不然界面和缓存文件都脏。
		if len(msg) > 200 {
			msg = msg[:200]
		}
		st.LastErr = msg
		return
	}
	st.OK++
	st.LastErr = ""
}

func (s *Service) put(r *model.PurityResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[r.IP] = r
	s.dirty = true
}

// Put 允许外部（比如 CLI 手动导入）塞一条结论。
func (s *Service) Put(r *model.PurityResult) { s.put(r) }

func (s *Service) load() error {
	blob, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var cf cacheFile
	if err := json.Unmarshal(blob, &cf); err != nil {
		return fmt.Errorf("解析 %s 失败: %w", s.path, err)
	}
	for _, r := range cf.Entries {
		if r == nil || r.IP == "" {
			continue
		}
		s.cache[r.IP] = r
	}
	for _, st := range cf.PerSource {
		if st == nil || st.Name == "" {
			continue
		}
		if cur, ok := s.stats[st.Name]; ok {
			cur.OK, cur.Failed, cur.LastErr, cur.LastTry = st.OK, st.Failed, st.LastErr, st.LastTry
		}
	}
	// 缓存是旧规则算的就重算一遍。New 里没有并发，直接改。
	s.mergeVer = cf.MergeVer
	if s.mergeVer < mergeVersion {
		s.upgradedAtLoad = s.upgradeLocked()
	}
	return nil
}

// UpgradeCache 是 load 的对外入口：app 启动后用它能拿到「缓存被重算了多少条」，
// 好把新结论同步回节点（节点上存的是结论副本，不是引用）。
func (s *Service) UpgradeCache() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.upgradedAtLoad > 0 {
		return s.upgradedAtLoad
	}
	if s.mergeVer >= mergeVersion {
		return 0
	}
	n := s.upgradeLocked()
	s.upgradedAtLoad = n
	return n
}

// upgradeLocked 用当前规则把每条缓存结论离线重算。返回改动条数。
//
// 只吃缓存里已经存的各来源结论（ProviderVerdict 里有 asn/org/type/因子），
// 所以不产生任何外部请求；CheckedAt 与 TTL 保持原样，不然等于给缓存续期一周。
func (s *Service) upgradeLocked() int {
	var changed int
	for ip, r := range s.cache {
		if r == nil {
			continue
		}
		sigs := signalsFromVerdicts(r.Providers)
		if len(sigs) == 0 {
			continue
		}
		next := Merge(Query{IP: ip}, sigs, MergeOptions{
			MinProviders: s.cfg.MinProviders,
			RawKeepBytes: s.cfg.RawKeepBytes,
		})
		if next == nil {
			continue
		}
		next.CheckedAt = r.CheckedAt
		next.TTLHours = r.TTLHours
		s.cache[ip] = next
		if next.IPType != r.IPType || next.TypeSource != r.TypeSource || next.Score != r.Score {
			changed++
		}
	}
	s.mergeVer = mergeVersion
	if changed > 0 {
		s.dirty = true
	}
	return changed
}

// signalsFromVerdicts 把存下来的结论还原成 Merge 的输入。
//
// 一个还原细节：builtin 的「弃权票」靠 no-internal-rule 标记从置信度里剔除，
// 而 verdict 没存 Tags。这里按同样的条件重建标记（builtin、没类型、没任何因子），
// 否则重算出来的置信度会比实查时高一截。
func signalsFromVerdicts(vs []model.ProviderVerdict) []*Signals {
	var out []*Signals
	for _, v := range vs {
		s := &Signals{
			Name:    v.Name,
			OK:      v.OK,
			Err:     v.Err,
			MS:      v.MS,
			Score:   v.Score,
			Type:    v.Type,
			Factors: v.Factors,
			ASN:     v.ASN,
			Org:     v.Org,
			ISP:     v.ISP,
			Domain:  v.Domain,
			Usage:   v.Usage,
			Country: v.Country,
			Tags:    v.Privates,
			Raw:     v.Raw,
			Weight:  Weight(v.Name),
		}
		if v.Name == "builtin" && v.Type == "" && v.Factors.AllEmpty() {
			s.Tags = append(s.Tags, "no-internal-rule")
		}
		out = append(out, s)
	}
	return out
}

// Save 原子写缓存。定时器和手动操作负责控制频率。
func (s *Service) Save() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	cf := cacheFile{Version: 1, MergeVer: mergeVersion, SavedAt: time.Now().UTC(), Entries: map[string]*model.PurityResult{}}
	for k, v := range s.cache {
		cf.Entries[k] = v
	}
	for _, st := range s.stats {
		c := *st
		cf.PerSource = append(cf.PerSource, &c)
	}
	s.dirty = false
	s.mu.Unlock()

	sort.Slice(cf.PerSource, func(i, j int) bool { return cf.PerSource[i].Name < cf.PerSource[j].Name })
	blob, err := json.MarshalIndent(cf, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Prune 清掉过老/超量的缓存条目，返回删除数。
// 保留 2 倍 TTL：留一点历史，改 TTL 配置时不至于把数据全删了。
func (s *Service) Prune() int {
	ttl := time.Duration(s.cfg.TTLHours) * time.Hour
	if ttl <= 0 {
		ttl = 168 * time.Hour
	}
	cutoff := time.Now().Add(-2 * ttl)
	s.mu.Lock()
	defer s.mu.Unlock()
	var removed int
	for ip, r := range s.cache {
		if r == nil || r.CheckedAt.Before(cutoff) {
			delete(s.cache, ip)
			removed++
		}
	}
	if len(s.cache) > cacheCap {
		// 超量就按检测时间从旧到新删到上限。
		type ent struct {
			ip string
			at time.Time
		}
		list := make([]ent, 0, len(s.cache))
		for ip, r := range s.cache {
			list = append(list, ent{ip, r.CheckedAt})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].at.Before(list[j].at) })
		for _, e := range list[:len(list)-cacheCap] {
			delete(s.cache, e.ip)
			removed++
		}
	}
	if removed > 0 {
		s.dirty = true
	}
	return removed
}

// CacheSize 返回缓存条目数。
func (s *Service) CacheSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.cache)
}

// normalizeIP 校验并规范化 IP，顺手挡掉明显不该查的地址。
// 私有/回环地址查了也是白花配额（免费源通常直接返回错误）。
func normalizeIP(raw string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return "", fmt.Errorf("不是合法 IP: %q", raw)
	}
	switch {
	case ip.IsUnspecified():
		return "", fmt.Errorf("IP 是未指定地址")
	case ip.IsLoopback():
		return "", fmt.Errorf("IP 是回环地址")
	case ip.IsMulticast():
		return "", fmt.Errorf("IP 是组播地址")
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), nil
	}
	return ip.String(), nil
}
