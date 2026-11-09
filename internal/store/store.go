// Package store 管节点池的内存索引与落盘。
//
// 不引入数据库是有意的：池子最大也就几千个节点，全内存 + 一份原子写的
// JSON 快照足够，换来的是零依赖单文件部署。.ovpn 正文按 sha256 内容寻址
// 单独存盘（data/configs/<sha>.ovpn）——实测全站配置高度重复，去重后
// 几千个节点只占几 MB。
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/config"
	"github.com/gebaolei/vpngate-agg/internal/model"
	"github.com/gebaolei/vpngate-agg/internal/source"
)

// SchemaVersion 是磁盘快照的格式版本。加字段是兼容的（JSON 忽略缺失字段），
// 改语义就要升版本并在加载时处理老数据。
const SchemaVersion = 1

type snapshot struct {
	SchemaVersion int                    `json:"schema_version"`
	Meta          model.Meta             `json:"meta"`
	PrevCounts    map[string]int         `json:"prev_counts"`
	Commit        string                 `json:"cdn_commit"`
	PoolCommit    string                 `json:"cdn_pool_commit"`
	Nodes         map[string]*model.Node `json:"nodes"`
}

// Store 是节点池。所有导出方法都可并发调用。
type Store struct {
	dir string

	mu         sync.RWMutex
	nodes      map[string]*model.Node
	byIP       map[string][]string // IP → 节点 ID，纯净度按 IP 回写要用
	meta       model.Meta
	prevCounts map[string]int
	cdnCommit  string
	poolCommit string
	lastSave   time.Time
	// dirty 为 true 表示自上次落盘后有变化。定时落盘只在脏的时候写。
	dirty bool
}

// New 读盘。文件不存在时得到一个空池（不是错误）——首次部署必须能起来。
func New(dir string) (*Store, error) {
	s := &Store{
		dir:        dir,
		nodes:      map[string]*model.Node{},
		byIP:       map[string][]string{},
		prevCounts: map[string]int{},
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}
	if err := os.MkdirAll(s.configDir(), 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "pool.json")
	blob, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		s.meta.SchemaVersion = SchemaVersion
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	var snap snapshot
	if err := json.Unmarshal(blob, &snap); err != nil {
		// 快照坏了不能直接把服务起不来：备份一份，从空池开始，
		// 让下一轮刷新把数据补回来。
		backup := path + ".bad-" + time.Now().UTC().Format("20060102T150405")
		_ = os.Rename(path, backup)
		fmt.Printf("[store] 解析 %s 失败（已备份到 %s，从空池开始）: %v\n", path, backup, err)
		s.meta.SchemaVersion = SchemaVersion
		return s, nil
	}
	if snap.SchemaVersion != SchemaVersion {
		fmt.Printf("[store] 快照 schema_version=%d（当前 %d），按不兼容处理并忽略旧数据\n", snap.SchemaVersion, SchemaVersion)
		s.meta.SchemaVersion = SchemaVersion
		return s, nil
	}
	s.nodes = snap.Nodes
	if s.nodes == nil {
		s.nodes = map[string]*model.Node{}
	}
	s.meta = snap.Meta
	s.prevCounts = snap.PrevCounts
	if s.prevCounts == nil {
		s.prevCounts = map[string]int{}
	}
	s.cdnCommit, s.poolCommit = snap.Commit, snap.PoolCommit
	var cfgFixed int
	for id, n := range s.nodes {
		if n == nil {
			delete(s.nodes, id)
			continue
		}
		n.Health = ComputeHealth(n.Probes, 0)
		// config_local 按磁盘实况回填：快照里这个标记只反映「那一轮抓取有没有拿到正文」，
		// 而正文是按 sha 内容寻址单独存盘的 —— 不回填，重启后一批「其实盘上有」的节点
		// 会被当成缺正文，界面上点开就走一次不必要的回源（ApplyRefresh 里是同样的修正）。
		if !n.ConfigLocal && s.hasConfigOnDisk(n.ConfigSHA256) {
			n.ConfigLocal = true
			cfgFixed++
		}
		s.indexIP(n.IP, id)
	}
	if cfgFixed > 0 {
		s.dirty = true // 下一次落盘把修正后的标记写回快照，下次启动就不用再补
		fmt.Printf("[store] 按磁盘实况回填 config_local：%d 个节点\n", cfgFixed)
	}
	return s, nil
}

func (s *Store) configDir() string { return filepath.Join(s.dir, "configs") }

func (s *Store) indexIP(ip, id string) {
	if ip == "" {
		return
	}
	for _, existing := range s.byIP[ip] {
		if existing == id {
			return
		}
	}
	s.byIP[ip] = append(s.byIP[ip], id)
}

// Dir 返回数据目录。
func (s *Store) Dir() string { return s.dir }

// Eviction 是节点池的淘汰门槛，由配置换算而来。两个门槛相互独立：
//   - KeepDays：不管探测结果，从名单里消失这么久就删（对齐 mirror 的 7 天）。
//   - AbsentFor + FailRounds：TCP 节点缺席满 AbsentFor、且已经连续 FailRounds 轮
//     有效探测明确失败，就提前删（mirror 对「明显已经不行的 TCP 节点」的清理）。
//
// FailRounds 只数「有效轮」：拿到了确定结论才算。超时和 UDP 无回包不算失败，
// 否则半池 UDP 节点会被误杀。
type Eviction struct {
	KeepDays   int
	AbsentFor  time.Duration
	FailRounds int
	// KeepOwnNet 保留 VPN Gate 自营机房节点（public-vpn-* / 自营网段）。
	// 默认 false：那是官方自己的机房出口，跟「志愿者家宽」是两回事。
	KeepOwnNet bool
}

// EvictionFrom 把配置换算成淘汰门槛，省得调用处各写一遍单位换算。
func EvictionFrom(s config.SourcesConfig) Eviction {
	return Eviction{KeepDays: s.KeepDays, AbsentFor: s.PurgeAbsent(), FailRounds: s.PurgeFailRounds,
		KeepOwnNet: s.KeepVpngateOwn}
}

// RefreshDiff 是一轮刷新对池子的改动。界面上要把「到期清除」和「提前淘汰」分开显示：
// 前者是上游轮换，后者是我们自己把明显不行的节点请出去。
type RefreshDiff struct {
	Added   int `json:"added"`
	Expired int `json:"expired"`
	Purged  int `json:"purged"`
	// DroppedOwn 是因「自营机房节点」被剔掉的数量：新抓的直接不进池，
	// 池里已有的在下一轮清掉。它和 Purged 分开算，因为原因不是节点坏了。
	DroppedOwn int `json:"dropped_own"`
	Total      int `json:"total"`
}

// Removed 是本轮从池子里消失的节点总数。
func (d RefreshDiff) Removed() int { return d.Expired + d.Purged + d.DroppedOwn }

// ApplyRefresh 把一轮抓取的产出并进池子。
//
// 已有节点保留探测历史、纯净度结论和 first_seen —— 这些是我们自己攒的，
// 不能被上游一次轮换抹掉。keepDays 和缺席门槛都为 0 时不删任何节点。
func (s *Store) ApplyRefresh(agg *source.Aggregated, ev Eviction) RefreshDiff {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()

	var diff RefreshDiff
	for id, fresh := range agg.Nodes {
		// 自营机房节点默认不进池（见 Eviction.KeepOwnNet）。放在最前面是为了让
		// Added 只数「真的进池的节点」，不然界面上会看到加了又被删。
		// 计数只在「池里还没有这个节点」时加，否则下面循环删它时会再数一次，
		// 同一个节点被算两遍。
		if !ev.KeepOwnNet && model.VpngateOwn(fresh.IP, fresh.HostName) {
			if _, seen := s.nodes[id]; !seen {
				diff.DroppedOwn++
			}
			continue
		}
		old, ok := s.nodes[id]
		if !ok {
			clone := *fresh
			clone.Health = ComputeHealth(nil, 0)
			s.nodes[id] = &clone
			s.indexIP(clone.IP, id)
			diff.Added++
			continue
		}
		// 保住我们自己的观测，只更新上游给的字段。
		fresh.Probes = old.Probes
		fresh.Probe = old.Probe
		fresh.Health = ComputeHealth(old.Probes, 0)
		fresh.Purity = old.Purity
		fresh.Residential = old.Residential
		if fresh.FirstSeen.IsZero() || old.FirstSeen.Before(fresh.FirstSeen) {
			fresh.FirstSeen = old.FirstSeen
		}
		// 配置正文已经在磁盘上（按 sha 存过）就把 ConfigLocal 修正回来：
		// 抓取阶段只知道本轮有没有正文，而磁盘可能早就有了。
		if !fresh.ConfigLocal && s.hasConfigOnDisk(fresh.ConfigSHA256) {
			fresh.ConfigLocal = true
		}
		s.nodes[id] = fresh
		s.indexIP(fresh.IP, id)
	}

	// 本轮没出现的节点不算死亡，只是「本轮没在名单里」：缺席计时从这里开始。
	//
	// InLatestSource 用本地自己的判定刷新（而不是沿用镜像池给的值）：
	// 我们自己拉了这一轮官方名单，比 mirror 的观测更新鲜。
	cutoff := now.Add(-time.Duration(ev.KeepDays) * 24 * time.Hour)
	for id, n := range s.nodes {
		// 池里已经有自营节点的情况：用户刚把开关关掉，这一轮把它们请出去。
		if !ev.KeepOwnNet && model.VpngateOwn(n.IP, n.HostName) {
			delete(s.nodes, id)
			s.unindexIP(n.IP, id)
			diff.DroppedOwn++
			continue
		}
		in := presentInCurrentList(agg.Nodes[id])
		v := in
		n.InLatestSource = &v
		if in {
			n.AbsentSince = nil // 又在名单里了，缺席计时清零
			continue
		}
		if n.AbsentSince == nil {
			t := now
			n.AbsentSince = &t
		}
		if ev.KeepDays > 0 && n.LastSeen.Before(cutoff) {
			delete(s.nodes, id)
			s.unindexIP(n.IP, id)
			diff.Expired++
			continue
		}
		// 提前淘汰（对齐 mirror）：只有 TCP 参与。UDP 节点对硬重置探测基本不回包，
		// 攒不出「有效失败」，删了就是把还能用的节点赶出池子。
		if ev.AbsentFor > 0 && ev.FailRounds > 0 && n.Proto == "tcp" &&
			n.DownRounds >= ev.FailRounds && now.Sub(*n.AbsentSince) >= ev.AbsentFor {
			delete(s.nodes, id)
			s.unindexIP(n.IP, id)
			diff.Purged++
		}
	}

	s.meta.SourceStats = agg.Stats
	s.meta.UpdatedAt = now
	s.meta.Mirrors = agg.Mirrors
	s.meta.MirrorsFetched = agg.MirrorFetched
	if agg.MirrorErr != "" {
		s.meta.Notes = []string{"镜像列表页: " + agg.MirrorErr}
	}
	s.cdnCommit, s.poolCommit = agg.Commit, agg.PoolCommit
	for u, c := range agg.CountsByURL {
		s.prevCounts[u] = c
	}
	s.dirty = true
	diff.Total = len(s.nodes)
	return diff
}

// presentInCurrentList 判断某个节点本轮是不是真的在名单里。
//
// 累积池（cdn-pool）的节点是第三方项目的历史观测，它自己的 last_seen 可能已经
// 好几天没被官方见过；把「池里还有」当成「本轮在名单里」会让过期和淘汰都不发生。
// 所以 -pool 结尾的来源不算本轮在场。
func presentInCurrentList(n *model.Node) bool {
	if n == nil {
		return false
	}
	return !strings.HasSuffix(n.LastSource, "-pool")
}

// UpdateFailRounds 在一轮探测结束时更新「连续明确失败轮数」，对齐 mirror 的
// 「连续三轮有效探测失败」。判定只看每个节点本轮最新那条样本：
//
//   - 连上了 → 清零
//   - 明确否定（refused / unreachable / blocked）→ 加一
//   - 超时、UDP 无回包这种说不清 → 不动（既不算失败，也不把已有的连击抹掉）
//   - 本轮没测到 → 不动
//
// counting=false 用于补测轮：同一轮里再数一次会把删除提前一倍。
func (s *Store) UpdateFailRounds(roundStart time.Time, counting bool) {
	if !counting {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.nodes {
		if len(n.Probes) == 0 {
			continue
		}
		last := n.Probes[len(n.Probes)-1]
		if last.At.Before(roundStart) {
			continue // 本轮没测过这个节点
		}
		switch {
		case last.OK:
			n.DownRounds = 0
		case last.Service == model.ServiceRefused || last.Service == model.ServiceUnreachable ||
			last.Service == model.ServiceBlocked:
			n.DownRounds++
		}
	}
	s.dirty = true
}

func (s *Store) unindexIP(ip, id string) {
	list := s.byIP[ip]
	for i, x := range list {
		if x == id {
			s.byIP[ip] = append(list[:i], list[i+1:]...)
			break
		}
	}
	if len(s.byIP[ip]) == 0 {
		delete(s.byIP, ip)
	}
}

// ApplyProbeResults 批量写入探测结果。
//
// 批量而不是逐个写锁：一轮探测几千个节点，每个都抢写锁会把界面的列表查询
// 卡成一列。探测线程写各自的结果，调度器每隔几秒调一次这个方法统一并入。
func (s *Store) ApplyProbeResults(updates map[string]*model.ProbeResult, historyKeep int) int {
	if len(updates) == 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, res := range updates {
		node, ok := s.nodes[id]
		if !ok || res == nil {
			continue
		}
		node.Probe = res
		node.Probes = append(node.Probes, sampleOf(res))
		if historyKeep > 0 && len(node.Probes) > historyKeep {
			node.Probes = node.Probes[len(node.Probes)-historyKeep:]
		}
		node.Health = ComputeHealth(node.Probes, 0)
		n++
	}
	if n > 0 {
		s.dirty = true
	}
	return n
}

// ApplyPurity 按 IP 把纯净度结论写给所有共享该 IP 的节点。
// 同一个 IP 上跑多个 VPN Gate 节点是常事（志愿者换端口），逐个查会白花 API 配额。
func (s *Store) ApplyPurity(res *model.PurityResult) int {
	if res == nil || res.IP == "" {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := *res
	var n int
	for _, id := range s.byIP[res.IP] {
		if node, ok := s.nodes[id]; ok {
			c := clone
			node.Purity = &c
			n++
		}
	}
	if n > 0 {
		s.dirty = true
	}
	return n
}

// SetResidential 写入「志愿者家宽 / 自营机房」判定。
func (s *Store) SetResidential(id string, residential bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	node, ok := s.nodes[id]
	if !ok {
		return false
	}
	v := residential
	node.Residential = &v
	s.dirty = true
	return true
}

// sampleOf 把完整结果压成历史样本。
func sampleOf(r *model.ProbeResult) model.ProbeSample {
	return model.ProbeSample{At: r.At, OK: r.OK, RTTMS: r.RTTMS, Service: r.Service, Reason: r.Reason}
}

// Save 原子写快照。调用方（定时器和手动操作）负责控制频率。
func (s *Store) Save() error {
	s.mu.RLock()
	snap := snapshot{
		SchemaVersion: SchemaVersion,
		Meta:          s.meta,
		PrevCounts:    s.prevCounts,
		Commit:        s.cdnCommit,
		PoolCommit:    s.poolCommit,
		Nodes:         s.nodes,
	}
	s.mu.RUnlock()

	blob, err := json.MarshalIndent(snap, "", " ")
	if err != nil {
		return fmt.Errorf("序列化节点池失败: %w", err)
	}
	path := filepath.Join(s.dir, "pool.json")
	tmp := path + ".tmp"
	// 0600：池子里有节点备注和运营商名，不含密钥，但没人愿意别人的服务读到
	// 自己攒的数据。
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("写 %s 失败: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("替换 %s 失败: %w", path, err)
	}
	s.mu.Lock()
	s.lastSave = time.Now().UTC()
	s.dirty = false
	s.mu.Unlock()
	return nil
}

// Dirty 返回自上次落盘后是否有变化。
func (s *Store) Dirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dirty
}

// LastSave 返回上次落盘时间。
func (s *Store) LastSave() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSave
}

// SaveConfig 按 sha256 存一份 .ovpn 正文。已存在就直接返回，不重复写。
func (s *Store) SaveConfig(sha string, cfg []byte) error {
	if sha == "" || len(cfg) == 0 {
		return errors.New("空的配置正文")
	}
	path := filepath.Join(s.configDir(), sha+".ovpn")
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, cfg, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) configPath(sha string) string {
	if !isHex(sha) {
		return ""
	}
	return filepath.Join(s.configDir(), sha+".ovpn")
}

func (s *Store) hasConfigOnDisk(sha string) bool {
	p := s.configPath(sha)
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// Config 读一份 .ovpn 正文。第二个返回值 false 表示本地没有。
func (s *Store) Config(sha string) ([]byte, bool) {
	p := s.configPath(sha)
	if p == "" {
		return nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil || len(b) == 0 {
		return nil, false
	}
	return b, true
}

// PutConfigs 批量存正文（一轮刷新后调用），返回新写入的数量。
func (s *Store) PutConfigs(m map[string][]byte) (int, error) {
	var written int
	for sha, cfg := range m {
		if s.hasConfigOnDisk(sha) {
			continue
		}
		if err := s.SaveConfig(sha, cfg); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// MarkConfigLocal 把节点的「正文已在本地」标记补上（按需拉取成功后调用）。
func (s *Store) MarkConfigLocal(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[id]
	if !ok {
		return false
	}
	if !n.ConfigLocal {
		n.ConfigLocal = true
		s.dirty = true
	}
	return true
}

// PrevCounts 返回上一轮各源给的节点数，用于数量骤减判断。
func (s *Store) PrevCounts() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int, len(s.prevCounts))
	for k, v := range s.prevCounts {
		out[k] = v
	}
	return out
}

// Commits 返回镜像的单快照 commit 与累积池 commit（按需拉池配置要用）。
func (s *Store) Commits() (commit, poolCommit string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cdnCommit, s.poolCommit
}

// SetJob 记录某类任务的进展。kind 是 refresh/probe/purity。
func (s *Store) SetJob(kind string, job *model.JobState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job == nil {
		return
	}
	clone := *job
	switch kind {
	case "refresh":
		s.meta.LastRefresh = &clone
	case "probe":
		s.meta.LastProbeRound = &clone
	case "purity":
		s.meta.LastPurityScan = &clone
	}
	s.meta.UpdatedAt = time.Now().UTC()
	s.dirty = true
}

// Jobs 返回三类任务的最近状态。
func (s *Store) Jobs() map[string]*model.JobState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]*model.JobState{}
	if s.meta.LastRefresh != nil {
		out["refresh"] = s.meta.LastRefresh
	}
	if s.meta.LastProbeRound != nil {
		out["probe"] = s.meta.LastProbeRound
	}
	if s.meta.LastPurityScan != nil {
		out["purity"] = s.meta.LastPurityScan
	}
	return out
}

// Meta 返回元数据副本（含源状态、镜像列表）。
func (s *Store) Meta() model.Meta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.meta
	m.SourceStats = append([]model.SourceStat(nil), s.meta.SourceStats...)
	m.Mirrors = append([]model.MirrorEntry(nil), s.meta.Mirrors...)
	return m
}

// All 返回节点指针的快照切片。调用方只读，且不要再改这些指针指向的对象
// （改要走 Apply* 方法）。
func (s *Store) All() []*model.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*model.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n)
	}
	return out
}

// Get 按 ID 取节点（返回深拷贝，调用方随便用）。
func (s *Store) Get(id string) (*model.Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n, ok := s.nodes[id]
	if !ok {
		return nil, false
	}
	return cloneNode(n), true
}

// NodesWithIP 返回某个 IP 上的所有节点 ID。
func (s *Store) NodesWithIP(ip string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.byIP[ip]...)
}

// Count 返回池内节点数。
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nodes)
}

// Stats 汇总仪表盘要的数字。
func (s *Store) Stats() model.Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st := model.Stats{PoolNodes: len(s.nodes), UpdatedAt: s.meta.UpdatedAt}
	var pings, purities []int64
	var residential, purityChecked, fresh int
	var residentialVerified, residentialDerived, typeUnknown int
	seenCountry := map[string]bool{}
	for _, n := range s.nodes {
		st.Nodes++
		switch n.Proto {
		case "tcp":
			st.TCP++
		case "udp":
			st.UDP++
		}
		switch model.HealthLevel(n.Health) {
		case "stable", "reachable":
			st.Alive++
		case "down":
			st.Down++
		case "untested":
			st.Untested++
		default:
			st.Unknown++
		}
		if n.InLatestSource != nil && *n.InLatestSource {
			fresh++
		}
		if cc := n.CountryCode; cc != "" {
			seenCountry[cc] = true
		}
		if n.Residential != nil && *n.Residential {
			residential++
			if n.Purity != nil && strings.HasPrefix(n.Purity.TypeSource, "derived:") {
				residentialDerived++
			} else {
				residentialVerified++
			}
		}
		if n.Purity != nil {
			purityChecked++
			if n.Purity.IPType == "" || n.Purity.IPType == model.TypeUnknown {
				typeUnknown++
			}
			purities = append(purities, int64(n.Purity.Score))
			// 取最近一次而不是最早一次：界面写的是「上次检测 x 前」。
			if n.Purity.CheckedAt.After(st.PurityAt) {
				st.PurityAt = n.Purity.CheckedAt
			}
		}
		if p := pingOf(n); p > 0 {
			pings = append(pings, p)
		}
		st.AvgUpstreamMbps += float64(n.UpstreamSpeedBps) / 1e6
		// 最近一次探测时间同样要取最大值：写错方向会让界面永远显示「从未探测」。
		if n.Health.LastTry.After(st.ProbedAt) {
			st.ProbedAt = n.Health.LastTry
		}
	}
	st.FreshNodes = fresh
	st.Countries = len(seenCountry)
	st.PurityChecked = purityChecked
	if st.Nodes > 0 {
		st.AvgUpstreamMbps /= float64(st.Nodes)
		st.ResidentialShare = 100 * float64(residential) / float64(st.Nodes)
		st.Residential = residential
		st.ResidentialVerified = residentialVerified
		st.ResidentialDerived = residentialDerived
		st.PurityTypeUnknown = typeUnknown
	}
	st.MedianPingMS = median(pings)
	if len(purities) > 0 {
		st.MedianPurity = int(median(purities))
	}
	st.Sources = append([]model.SourceStat(nil), s.meta.SourceStats...)
	return st
}

// Countries 返回国家维度的聚合，按节点数降序。
func (s *Store) Countries() []model.CountryBucket {
	s.mu.RLock()
	defer s.mu.RUnlock()

	type acc struct {
		b      model.CountryBucket
		pings  []int64
		purity []int64
		names  map[string]bool
	}
	by := map[string]*acc{}
	for _, n := range s.nodes {
		code := n.CountryCode
		if code == "" {
			code = "?"
		}
		a := by[code]
		if a == nil {
			a = &acc{b: model.CountryBucket{Code: code}, names: map[string]bool{}}
			by[code] = a
		}
		a.b.Nodes++
		if n.Country != "" {
			a.names[n.Country] = true
		}
		switch model.HealthLevel(n.Health) {
		case "stable", "reachable":
			a.b.Alive++
		}
		if p := pingOf(n); p > 0 {
			a.pings = append(a.pings, p)
		}
		if n.Purity != nil {
			a.purity = append(a.purity, int64(n.Purity.Score))
		}
		if n.Residential != nil && *n.Residential {
			a.b.Residential++
		}
	}
	out := make([]model.CountryBucket, 0, len(by))
	for _, a := range by {
		a.b.MedPing = median(a.pings)
		if len(a.purity) > 0 {
			a.b.MedPurity = int(median(a.purity))
		}
		names := make([]string, 0, len(a.names))
		for k := range a.names {
			names = append(names, k)
		}
		sort.Strings(names)
		a.b.Name = strings.Join(names, " / ")
		out = append(out, a.b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Nodes != out[j].Nodes {
			return out[i].Nodes > out[j].Nodes
		}
		return out[i].Code < out[j].Code
	})
	return out
}

// pingOf 取「最能代表这个节点现在多快」的延迟：
// 优先我们自己测的 EWMA，其次最近一次成功的 RTT，最后才是官方给的 Ping。
// 官方 Ping 是别人那张网看到的，只在没测过时兜底，界面会标来源。
//
// 注意：这一条只给统计卡片和地图的国家中位延迟用。节点列表的延迟列、
// sort=ping / max_ping 用的是 query.localPing（只看本机实测，不兜底官方），
// 两边不同是有意的：实测只覆盖少数节点（实测中 74/269），拿它算全盘中位数
// 会让地图按延迟上色时大片变成「没数据」；而列表上“这个节点能不能用”
// 只能看本机自己的观测。
func pingOf(n *model.Node) int64 {
	if n.Health.EWMAPingMS > 0 {
		return n.Health.EWMAPingMS
	}
	if n.Probe != nil && n.Probe.OK && n.Probe.RTTMS > 0 {
		return n.Probe.RTTMS
	}
	if n.UpstreamPingMS > 0 {
		return n.UpstreamPingMS
	}
	return 0
}

func median(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]int64(nil), v...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	m := len(c) / 2
	if len(c)%2 == 1 {
		return c[m]
	}
	return (c[m-1] + c[m]) / 2
}

// isHex 判断是不是纯十六进制串，用来防目录穿越：
// 配置文件名直接由 sha 拼出来，不做校验的话 "../x" 也能进来。
func isHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ParseID 校验 ID 形状（v1: + 64 位 hex）。
func ParseID(s string) bool {
	if !strings.HasPrefix(s, "v1:") || len(s) != 67 {
		return false
	}
	return isHex(s[3:])
}

// FormatMS 是日志用的可读延迟。
func FormatMS(ms int64) string {
	switch {
	case ms <= 0:
		return "-"
	case ms < 1000:
		return strconv.FormatInt(ms, 10) + "ms"
	default:
		return fmt.Sprintf("%.2fs", float64(ms)/1000)
	}
}
