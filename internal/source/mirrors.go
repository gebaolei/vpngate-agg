package source

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/config"
	"github.com/gebaolei/vpngate-agg/internal/model"
)

// 官方镜像列表页本身只有十几 KB，给 1 MB 已经极其宽松，超过就是页面不对。
const maxMirrorEntries = 16

// mirrorFailBackoff 是列表页连续失败后的重试间隔。
// 第一次失败不能「一失败就静默等 12 小时」，那等于首日整天只有单源。
var mirrorFailBackoff = []time.Duration{
	15 * time.Minute, time.Hour, 6 * time.Hour, 12 * time.Hour,
}

// 页面把镜像列表放在 <span id="Label1"> 里，里面紧跟一个 <ul>，形如：
//
//	<li><strong><span ...><a href='http://150.40.105.16:33958/en/'>…</a></span>
//	    </strong>&nbsp;(Mirror location: Croatia (LOCAL Name: Hrvatska))</li>
//
// 收口必须用 </ul>：每个 <li> 内部都有 </span>，按 </span> 收会直接切在
// 第一个镜像中间，什么都解析不出来。
var (
	reLabel1   = regexp.MustCompile(`(?is)<span[^>]+id=['"]Label1['"][^>]*>(.*?)</ul>`)
	reListItem = regexp.MustCompile(`(?is)<li[^>]*>(.*?)</li>`)
	reHref     = regexp.MustCompile(`(?is)href=['"]([^'"]+)['"]`)
	reLocation = regexp.MustCompile(`(?i)Mirror location:\s*([^<]*)`)
)

// ParseMirrorPage 从列表页取镜像条目。
//
// 先只认 Label1 那块；那块解不出东西就退回全页扫描 —— 上游改模板时至少还能
// 拿到源，代价是没有 location，选源时只能靠网段去重。
func ParseMirrorPage(body string) ([]model.MirrorEntry, error) {
	var out []model.MirrorEntry
	if m := reLabel1.FindStringSubmatch(body); len(m) == 2 {
		out = scanMirrorItems(m[1])
	}
	if len(out) == 0 {
		out = scanMirrorLinks(body)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("镜像列表页里没有解析出任何可用镜像")
	}
	if len(out) > maxMirrorEntries {
		out = out[:maxMirrorEntries]
	}
	return out, nil
}

// scanMirrorItems 扫一块 HTML 里的 <li>，把过得了校验的镜像收进来。
// 过不了的（站内链接、外站域名、私有地址）直接跳过不报错：页面上本来就混着
// 几十条导航链接，逐条报错除了刷日志没有别的用处。
func scanMirrorItems(section string) []model.MirrorEntry {
	var out []model.MirrorEntry
	seen := map[string]bool{}
	for _, li := range reListItem.FindAllStringSubmatch(section, -1) {
		href := ""
		if h := reHref.FindStringSubmatch(li[1]); len(h) == 2 {
			href = h[1]
		}
		if href == "" {
			continue
		}
		base, _, _, err := validateMirrorBase(href, nil)
		if err != nil || seen[base] {
			continue
		}
		seen[base] = true
		loc := ""
		if m := reLocation.FindStringSubmatch(li[1]); len(m) == 2 {
			loc = cleanMirrorLocation(m[1])
		}
		out = append(out, model.MirrorEntry{Base: base, Location: loc})
	}
	return out
}

// scanMirrorLinks 是全页兜底：不要求链接在 <li> 里，只收 href。
func scanMirrorLinks(body string) []model.MirrorEntry {
	var out []model.MirrorEntry
	seen := map[string]bool{}
	for _, m := range reHref.FindAllStringSubmatch(body, -1) {
		base, _, _, err := validateMirrorBase(m[1], nil)
		if err != nil || seen[base] {
			continue
		}
		seen[base] = true
		out = append(out, model.MirrorEntry{Base: base})
	}
	return out
}

// cleanMirrorLocation 把 "Croatia (LOCAL Name: Hrvatska)" 收成 "Croatia"。
func cleanMirrorLocation(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.IndexAny(s, "(（"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	s = strings.TrimRight(s, ")）,;")
	return strings.TrimSpace(s)
}

func locationKey(location string) string {
	return strings.ToLower(cleanMirrorLocation(location))
}

// validateMirrorBase 校验列表页给出的一个地址，返回归一化后的站点根
// （scheme://host:port，不带 /en/ 这种后缀）。
//
// localPorts 用来拒绝「镜像端口正好是这台机器正在监听的端口」，传 nil 表示
// 不做这项检查（解析阶段用 nil，真正拉取前必须传）。
//
// 只收 IPv4 字面量：域名要先解析再校验，而且解析结果能随 DNS 变，校验和连接
// 之间还能重新绑定（DNS rebinding）。页面上给的全是 IP，所以先把域名拒掉。
func validateMirrorBase(raw string, localPorts func(int) bool) (string, net.IP, int, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", nil, 0, fmt.Errorf("镜像地址无法解析: %v", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", nil, 0, fmt.Errorf("镜像协议不被允许: %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", nil, 0, fmt.Errorf("镜像地址缺少主机")
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return "", nil, 0, fmt.Errorf("镜像必须是 IPv4 字面量，不接受域名: %q", host)
	}
	if reason := blockedAddrReason(ip); reason != "" {
		return "", nil, 0, fmt.Errorf("镜像地址 %s 不被允许: %s", ip, reason)
	}
	port := 0
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", nil, 0, fmt.Errorf("镜像端口不合法: %q", p)
		}
		port = n
	} else if scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	if localPorts != nil && localPorts(port) {
		return "", nil, 0, fmt.Errorf("镜像端口 %d 与本机正在监听的端口冲突", port)
	}
	return scheme + "://" + net.JoinHostPort(ip.String(), strconv.Itoa(port)), ip, port, nil
}

// blockedAddrReason 返回拒绝这个地址的原因，空串表示放行。
// 列表页返回的是任意 IP:PORT —— 不校验等于把一个是 SSRF 入口直接交给第三方页面。
func blockedAddrReason(ip net.IP) string {
	switch {
	case ip.IsUnspecified():
		return "未指定地址"
	case ip.IsLoopback():
		return "回环地址"
	case ip.IsPrivate():
		return "私有网段"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "链路本地地址"
	case ip.IsMulticast():
		return "组播地址"
	}
	for _, block := range blockedPrefixes {
		if block.Contains(ip) {
			return "保留段 " + block.String()
		}
	}
	return ""
}

// mirrorSubnet 返回镜像所在的 /24。
//
// 按 /24 去重比按 location 更准：实测列表页上 4 个克罗地亚镜像全在
// 150.40.105.0/24，其中两两的节点 CSV 高度重复 —— 同一网段基本就是同一处
// 机房的多个端口，重复拉只是白花带宽。
func mirrorSubnet(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || ip.To4() == nil {
		return ""
	}
	return ip.To4().Mask(net.CIDRMask(24, 32)).String()
}

// pickMirrorSources 从缓存的镜像列表里挑彼此不同源的镜像。
// n<=0 表示本轮全抓（默认的 sources.mirrors.max_mirrors=0）。
//
// 去重尺度跟着 n 变：限量时 /24 + location 都去重，为了把带宽花在
// 不同机房；全抓时只按 /24 去重 —— 同一机房多个端口拉的 CSV 几乎一模一样，
// 但同一国家不同机房的镜像是独立的缓存，节点集真的不一样，全抓的意义上就该拉。
//
// rotation 是轮转偏移：限量时每轮换一批，跨轮次的并集会持续变大。
func pickMirrorSources(entries []model.MirrorEntry, n int, rotation int) []model.MirrorEntry {
	if len(entries) == 0 {
		return nil
	}
	limit, dedupeLocation := len(entries), false // 全抓：只按 /24 去重
	if n > 0 {
		// 限量时更严格：/24 和 location 都去重，把带宽花在不同机房/地区。
		limit, dedupeLocation = n, true
	}
	out := make([]model.MirrorEntry, 0, limit)
	usedSubnet, usedLocation := map[string]bool{}, map[string]bool{}
	start := rotation % len(entries)
	if start < 0 {
		start += len(entries)
	}
	for i := 0; i < len(entries) && len(out) < limit; i++ {
		e := entries[(start+i)%len(entries)]
		if strings.TrimSpace(e.Base) == "" {
			continue
		}
		if s := mirrorSubnet(e.Base); s != "" {
			if usedSubnet[s] {
				continue
			}
			usedSubnet[s] = true
		}
		if loc := locationKey(e.Location); dedupeLocation && loc != "" {
			if usedLocation[loc] {
				continue
			}
			usedLocation[loc] = true
		}
		out = append(out, e)
	}
	return out
}

// feedURL 拼出某个源的节点列表接口。实测 6 个镜像的路径完全一致。
func feedURL(base string) string {
	return strings.TrimRight(base, "/") + "/api/iphone/"
}

type mirrorCache struct {
	Fetched time.Time           `json:"fetched"`
	Mirrors []model.MirrorEntry `json:"mirrors"`
}

// MirrorStore 管官方镜像列表的读盘缓存、过期重拉、失败退避、轮转偏移。
// 它只在刷新节点列表时被碰，而刷新可能来自定时器、也可能来自界面的手动按钮，
// 所以自带一把锁。
type MirrorStore struct {
	mu       sync.Mutex
	dir      string
	entries  []model.MirrorEntry
	fetched  time.Time
	rotation int
	fails    int
	nextTry  time.Time
	lastErr  string // 最后一次拉列表页失败的原因，只在锁内读写
	// portBusy 判断端口是否已被占用。做成字段是为了测试里能绕开真 bind。
	portBusy func(int) bool
	client   *Client
}

// NewMirrorStore 先读盘：重启时不必等网络就有一份可用的镜像列表。
func NewMirrorStore(dir string, client *Client) *MirrorStore {
	s := &MirrorStore{dir: dir, portBusy: listeningPort, client: client}
	entries, fetched, err := s.load()
	if err != nil {
		fmt.Printf("[source] 读取镜像列表缓存失败（会重拉）: %v\n", err)
	}
	s.entries, s.fetched = entries, fetched
	return s
}

func (s *MirrorStore) path() string { return filepath.Join(s.dir, "vpngate-mirrors.json") }

func (s *MirrorStore) load() ([]model.MirrorEntry, time.Time, error) {
	blob, err := os.ReadFile(s.path())
	if os.IsNotExist(err) {
		return nil, time.Time{}, nil
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	var c mirrorCache
	if err := json.Unmarshal(blob, &c); err != nil {
		return nil, time.Time{}, fmt.Errorf("解析镜像列表缓存失败: %w", err)
	}
	return c.Mirrors, c.Fetched, nil
}

func (s *MirrorStore) save(entries []model.MirrorEntry) error {
	blob, err := json.MarshalIndent(mirrorCache{Fetched: time.Now().UTC(), Mirrors: entries}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	tmp := s.path() + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("写镜像列表缓存失败: %w", err)
	}
	return os.Rename(tmp, s.path())
}

// Sources 返回本轮要用的官方镜像 feed 地址。
// 列表过期或还没有时先重拉；拉不动就沿用旧列表并按退避跳过。
func (s *MirrorStore) Sources(ctx context.Context, cfg config.MirrorSource, now time.Time) []string {
	if s == nil || !cfg.Enabled {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	maxAge := time.Duration(cfg.ListMaxHours) * time.Hour
	if maxAge <= 0 {
		maxAge = 12 * time.Hour
	}
	stale := s.fetched.IsZero() || now.Sub(s.fetched) > maxAge
	if len(s.entries) == 0 || stale {
		// 顺序不能倒：先判退避，否则退避期到了之前每轮都会白打一次列表页。
		switch {
		case now.Before(s.nextTry):
			// 还在退避期内，本轮延用旧列表
		case s.client == nil || cfg.SitesPage == "":
			s.nextTry = now.Add(15 * time.Minute)
		default:
			entries, err := s.fetchList(ctx, cfg)
			if err != nil {
				s.fails++
				wait := mirrorFailBackoff[min(s.fails-1, len(mirrorFailBackoff)-1)]
				s.nextTry = now.Add(wait)
				s.lastErr = err.Error()
			} else {
				s.entries, s.fetched = entries, now
				s.fails, s.nextTry, s.lastErr = 0, time.Time{}, ""
				if werr := s.save(entries); werr != nil {
					fmt.Printf("[source] 保存镜像列表缓存失败: %v\n", werr)
				}
			}
		}
	}

	busy := s.portBusy
	if busy == nil {
		busy = listeningPort
	}
	var urls []string
	for _, e := range pickMirrorSources(s.entries, cfg.MaxMirrors, s.rotation) {
		// 解析阶段不查端口（页面上几十条链接逐条 bind 一次不现实），
		// 真正要拉之前这一道必须过。
		base, _, _, err := validateMirrorBase(e.Base, busy)
		if err != nil {
			continue
		}
		urls = append(urls, feedURL(base))
	}
	s.rotation++
	return urls
}

// Summary 给界面用：当前缓存的镜像、列表页上次更新时间、最后一次拉取失败的原因。
func (s *MirrorStore) Summary() ([]model.MirrorEntry, time.Time, string) {
	if s == nil {
		return nil, time.Time{}, ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.entries, s.fetched, s.lastErr
}

// NoteFailure 记一次「整轮节点源都失败」，让下一轮更早重拉列表页。
// 列表页本身没坏，但源全挂通常意味着网络出问题了，值得早点重试。
func (s *MirrorStore) NoteFailure(now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextTry.IsZero() || s.nextTry.Before(now) {
		s.nextTry = now.Add(15 * time.Minute)
	}
}

// fetchList 拉镜像列表页并解析出可用镜像。失败时调用方决定怎么办
// （沿用旧缓存 / 退避）。
func (s *MirrorStore) fetchList(ctx context.Context, cfg config.MirrorSource) ([]model.MirrorEntry, error) {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	raw, err := s.client.Get(ctx, cfg.SitesPage, SitesPageMaxByte, timeout)
	if err != nil {
		return nil, fmt.Errorf("拉取镜像列表页失败: %w", err)
	}
	if len(raw) < 512 {
		return nil, fmt.Errorf("镜像列表页内容过短(%d 字节)，按异常处理", len(raw))
	}
	return ParseMirrorPage(string(raw))
}

// listeningPort 用「能不能 bind」判断端口是否已被占用。
// 镜像列表页给的是公网 IP:PORT，回环与私有段已经被地址校验拦了，
// 但「本机公网 IP : 本服务正在监听的端口」这种形式进得来 ——
// 真去连一个自己开的端口，拿到的是自己的服务，解析不了还算轻的。
func listeningPort(port int) bool {
	ln, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", fmt.Sprint(port)))
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}
