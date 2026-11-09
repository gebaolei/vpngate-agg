// Package model 定义整个工具共享的数据结构。
//
// 这里不放业务逻辑，只放「会被序列化到磁盘 / 交给前端」的形状，
// 所以它不 import 本仓库的任何其他包（避免环）。上游字段名与
// VPN Gate CSV / vpngate-list-mirror 协议一一对应，本地测出来的东西
// 一律带自己的名字（probe_*、purity_*），不跟上游观测混在一个字段里：
// 官方 Ping/Score 是「官方看到的」，我们的探测是「你这张网看到的」，
// 两者必须能分别解释，否则界面上说不清是谁给的结论。
package model

import (
	"net"
	"strings"
	"time"
)

// Node 是一个 OpenVPN/SoftEther 节点在节点池里的完整状态。
//
// 身份用的是 vpngate-list-mirror 的 v1 规则：
//
//	"v1:" + sha256("vpngate-node-v1\x00" + normalized_hostname + "\x00" + canonical_ip)
//
// hostname 或 IP 一变就是新节点。这是「目录身份」，不是设备身份。
type Node struct {
	ID       string `json:"id"`
	HostName string `json:"hostname"`
	IP       string `json:"ip"`

	Country     string `json:"country"`      // CountryLong，如 "Japan (Tokyo)"
	CountryCode string `json:"country_code"` // 大写两位码，未知为 ""
	Operator    string `json:"operator,omitempty"`
	Message     string `json:"message,omitempty"`
	LogType     string `json:"logtype,omitempty"`

	// 上游观测（VPN Gate 官方测的，不是我们测的）
	UpstreamScore    int64 `json:"upstream_score"`
	UpstreamPingMS   int64 `json:"upstream_ping_ms"`
	UpstreamSpeedBps int64 `json:"upstream_speed_bps"`
	Sessions         int64 `json:"sessions"`
	UptimeSeconds    int64 `json:"uptime_seconds,omitempty"`
	TotalUsers       int64 `json:"total_users,omitempty"`
	TotalTraffic     int64 `json:"total_traffic,omitempty"`

	// .ovpn 配置：正文按 sha256 内容寻址单独存盘（data/configs/<sha>.ovpn），
	// 池文件里只留摘要。VPN Gate 全站配置高度重复，去重后磁盘占用可以忽略。
	ConfigSHA256 string `json:"config_sha256"`
	ConfigBytes  int    `json:"config_bytes"`
	// ConfigLocal 假代表本地 data/configs/<sha>.ovpn 已有正文。
	// 从 mirror 累积池导入的节点只有 hash 与端点，正文按需拉（几千个配置
	// 文件逐个拉一遍会把一轮刷新变成十几分钟）。
	ConfigLocal   bool   `json:"config_local"`
	Server        string `json:"server,omitempty"` // .ovpn 里 remote 的第一段
	Port          int    `json:"port,omitempty"`
	Proto         string `json:"proto,omitempty"` // "tcp" | "udp"
	Cipher        string `json:"cipher,omitempty"`
	AuthAlgorithm string `json:"auth_algorithm,omitempty"`
	// Vendor 是从配置注释里认出来的服务厂商：softether / openvpn / ""。
	// VPN Gate 上实测全是 SoftEther，这直接决定了 TCP 探测会收到什么回包。
	Vendor   string `json:"vendor,omitempty"`
	HasCerts bool   `json:"has_certs"`
	// Residential 是内置启发式（hostname 前缀 + 自营网段 + 纯净度）判的
	// 「志愿者家宽」，nil 表示还没判过。
	Residential *bool `json:"residential,omitempty"`

	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// InLatestSource 是 mirror 累积池给的 present_in_latest_source：最一次
	// 官方 API 响应里有没有这个 ID。它不是在线标记，只是「还在名单里」。
	InLatestSource *bool `json:"in_latest_source,omitempty"`
	// 最后一次被哪个源给出：vpngate / mirror:<host> / cdn / cdn-pool。
	// 排障时要知道节点是只在累积池里见到的、还是本轮官方 API 真给了。
	LastSource string `json:"last_source,omitempty"`
	// AbsentSince 是这个节点从官方名单里消失的起点：本轮没见到就记上时间，
	// 重新出现就清空。提前淘汰用的就是这个钟（对齐 vpngate-list-mirror 滚动池的
	// 「缺席满 24 小时」），和 LastSeen 的七天过期是两个独立门槛。
	AbsentSince *time.Time `json:"absent_since,omitempty"`
	// DownRounds 是连续多少轮有效探测给出明确否定结论。一轮只加一次；连上就清零；
	// 超时、UDP 无回包这种「说不清」既不加分也不清零（mirror 的规则：unknown 不算失败）。
	// 补测轮不计入，否则一轮会被算成两轮、节点提前一倍被删掉。
	DownRounds int `json:"down_rounds,omitempty"`
	// CFProbe 是 vpngate-list-mirror 里 Cloudflare Worker 的 TCP 观测。
	// 它不是本工具测的，也不能归入 Probe/Health：那是别人那张网看到的可达性。
	CFProbe *CFProbe `json:"cf_tcp,omitempty"`

	Probe  *ProbeResult  `json:"probe,omitempty"`
	Probes []ProbeSample `json:"probes,omitempty"` // 环形历史，长度由配置裁剪
	Health ProbeHealth   `json:"health"`
	Purity *PurityResult `json:"purity,omitempty"`
	Notes  []string      `json:"notes,omitempty"` // 解析/校验留下的告警
}

// VpngateOwnNets 是 VPN Gate 自营服务器所在网段（筑波大学学术网出口）。
var VpngateOwnNets = []string{"219.100.37.0/24"}

// vpngateOwnNets 是解析好的网段，只建一次。
var vpngateOwnNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range VpngateOwnNets {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// VpngateOwn 回答「这是不是 VPN Gate 自营机房节点」：hostname 前缀 public-vpn-*，
// 或落在自营网段里。这是官方名单里**唯一**自带的类型标识 —— 而且它标的是机房
// 不是家宽（自营服务器是 SoftEther 放在学术网里的官方机器）。
func VpngateOwn(ip, hostname string) bool {
	h := strings.ToLower(strings.TrimSpace(hostname))
	if strings.HasPrefix(h, "public-vpn-") || strings.HasPrefix(h, "public_vpn-") {
		return true
	}
	if parsed := net.ParseIP(strings.TrimSpace(ip)); parsed != nil {
		for _, n := range vpngateOwnNets {
			if n.Contains(parsed) {
				return true
			}
		}
	}
	return false
}

// Addr 返回真正要连的地址：以 .ovpn 里的 remote 为准，
// 回落到 CSV 的 IP。VPN Gate 的 remote 偶尔是域名，而 CSV 的 IP 才是解析结果，
// 两者不一致时优先 remote（连接语义要跟客户端一致），但会在 Notes 里留痕。
func (n *Node) Addr() (host string, port int, proto string) {
	host, port, proto = n.Server, n.Port, n.Proto
	if host == "" {
		host = n.IP
	}
	if port <= 0 {
		port = 1194
	}
	if proto == "" {
		proto = "udp"
	}
	return
}

// CFProbe 是第三方（Cloudflare Worker）的 TCP 观测，原样搬过来。
type CFProbe struct {
	Status      string    `json:"status"` // reachable / unreachable / unknown / not_applicable
	CheckedAt   time.Time `json:"checked_at,omitempty"`
	LastSuccess time.Time `json:"last_success_at,omitempty"`
	ConnectMS   *int64    `json:"connect_ms,omitempty"`
	Endpoint    string    `json:"connected_endpoint,omitempty"`
	Fails       int       `json:"consecutive_failures,omitempty"`
	Source      string    `json:"probe_source,omitempty"`
	Round       int64     `json:"round,omitempty"`
}

// ProbeSample 是一次探测的紧凑记录（存历史用）。
type ProbeSample struct {
	At      time.Time `json:"at"`
	OK      bool      `json:"ok"`
	RTTMS   int64     `json:"rtt_ms"`
	Service string    `json:"service,omitempty"`
	Reason  string    `json:"reason,omitempty"` // 失败原因或 unknown 的原因
}

// ProbeResult 是一次探测的完整结果。
type ProbeResult struct {
	At         time.Time `json:"at"`
	OK         bool      `json:"ok"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Proto      string    `json:"proto"`
	RTTMS      int64     `json:"rtt_ms"`     // TCP 握手耗时；UDP 是收到回包的往返
	ConnectMS  int64     `json:"connect_ms"` // 纯 TCP 三次握手（UDP 节点为 dial 到对端耗时）
	Handshake  bool      `json:"handshake"`  // 是否做了 OpenVPN 硬重置探测
	Service    string    `json:"service"`    // 见下方 Service* 常量
	Detail     string    `json:"detail,omitempty"`
	Reason     string    `json:"reason,omitempty"` // 失败/unknown 的原因
	Attempts   int       `json:"attempts,omitempty"`
	DurationMS int64     `json:"duration_ms"`
}

// 服务指纹。判定分层是关键：TCP 能握手就代表「这个端口在你的网络里可达」，
// 后面的指纹只回答「它是不是真的 OpenVPN/SoftEther 服务」。
const (
	ServiceOpenVPN     = "openvpn"     // 回了 opcode 8 (P_CONTROL_HARD_RESET_SERVER_V2)
	ServiceSoftEther   = "softether"   // 回了 "HTTP/..." —— SoftEther 的 OpenVPN-TCP 通道对裸包的回法
	ServiceResponded   = "responded"   // 有回包但认不出来
	ServiceNoReply     = "no-reply"    // 连上了但不应答（TCP）/ 无回包（UDP）
	ServiceRefused     = "refused"     // 连接被拒绝：端口没在听
	ServiceTimeout     = "timeout"     // TCP 握手超时
	ServiceUnreachable = "unreachable" // DNS/路由/网络不可达
	ServiceTCPOpen     = "tcp-open"    // 只做了 TCP 三次握手（配置里关掉了握手探测）
	ServiceUnknown     = "unknown"     // 还没测过
	ServiceBlocked     = "blocked"     // 地址被本地策略拒绝（私有段/本机端口等）
)

// ProbeHealth 是由历史算出来的可信用指标，界面上排序主要靠它。
type ProbeHealth struct {
	Tests      int       `json:"tests"`
	Successes  int       `json:"successes"`
	SuccessPct float64   `json:"success_pct"`
	FailStreak int       `json:"fail_streak"`
	LastOK     time.Time `json:"last_ok,omitempty"`
	LastTry    time.Time `json:"last_try,omitempty"`
	EWMAPingMS int64     `json:"ewma_ping_ms"`
	// Alive 是明确结论：true 可达，false 明确不可达，指针为 nil 表示未知
	// （UDP 无响应、超时这些都落在未知，不能当死亡处理）。
	Alive *bool `json:"alive,omitempty"`
	// Level 是拿来直接展示的可达档位（stable/reachable/unknown/flaky/down/untested），
	// 由 ComputeHealth 算好填上。之所以要序列化出来：界面徽章和 ?level= 筛选必须是
	// 同一套说法，否则会出现「表格里标着已挂、按已挂筛却筛不出」这种自相矛盾。
	Level string `json:"level"`
	// Confidence 0-1：这次结论有多少证据（成功次数 + 失败次数 + 新鲜度）。
	Confidence float64 `json:"confidence"`
}

// HealthLevel 由历史算出可直接展示的可达性档位。ComputeHealth 会顺手把结果
// 填进 ProbeHealth.Level；单独导出是为了读到缺这个字段的老快照时也能重算。
//
// 「挂了」只给明确的否定结论（RST / 网络不可达 / 被本地策略拦下），
// 而且要连续两次。超时和 UDP 无回包落在 unknown：跨境链路丢一个 SYN 太常见，
// 而实测 SoftEther 的 UDP 监听基本不回硬重置包 —— 按失败算的话，
// 半池子 UDP 节点会被长期误标成死亡。
func HealthLevel(h ProbeHealth) string {
	switch {
	case h.Tests == 0:
		return "untested"
	case h.Alive != nil && *h.Alive:
		if h.SuccessPct >= 80 {
			return "stable"
		}
		return "reachable"
	case h.Alive != nil:
		if h.FailStreak >= 2 {
			return "down"
		}
		return "flaky"
	case h.Successes > 0:
		// 以前连上过、最近这次只是没拿到明确结论：抖动，不是死亡。
		return "flaky"
	default:
		return "unknown"
	}
}

// HealthLevelLabels 是可达档位的中文名，给 CLI 和日志用。
// （CLI 一度误用了纯净度的 LevelLabels，状态列一直是空的。）
var HealthLevelLabels = map[string]string{
	"stable":    "稳定",
	"reachable": "可达",
	"unknown":   "状态未知",
	"flaky":     "抖动",
	"down":      "已挂",
	"untested":  "未测",
}

// PurityFactors 是各来源给出的风险因子，指针区分「没说」和「说了否」。
type PurityFactors struct {
	Proxy      *bool `json:"proxy,omitempty"`
	VPN        *bool `json:"vpn,omitempty"`
	Tor        *bool `json:"tor,omitempty"`
	Datacenter *bool `json:"datacenter,omitempty"`
	Mobile     *bool `json:"mobile,omitempty"`
	Abuser     *bool `json:"abuser,omitempty"`
	Bot        *bool `json:"bot,omitempty"`
	Streaming  *bool `json:"streaming,omitempty"` // 被流媒体当数据中心拒了
	AbuseScore *int  `json:"abuse_score,omitempty"`
}

// AllEmpty 表示这一组因子什么都没表过态。缓存离线重算时要用它还原 builtin
// 的「弃权票」标记（verdict 里没存 Tags），不还原会把置信度算高。
func (f PurityFactors) AllEmpty() bool {
	return f.Proxy == nil && f.VPN == nil && f.Tor == nil && f.Datacenter == nil &&
		f.Mobile == nil && f.Abuser == nil && f.Bot == nil && f.Streaming == nil &&
		f.AbuseScore == nil
}

// ProviderVerdict 是单个来源的原始结论。界面上逐条列出来，
// 让用户能看到「谁说了什么」而不是只给一个总分。
type ProviderVerdict struct {
	Name      string        `json:"name"`
	OK        bool          `json:"ok"`
	Err       string        `json:"err,omitempty"`
	MS        int64         `json:"ms"`
	Score     *int          `json:"score,omitempty"`      // 该来源原生的风险分，已归一到 0-100
	ScoreName string        `json:"score_name,omitempty"` // 原始分数的名字，如 FraudScore
	Factors   PurityFactors `json:"factors"`
	Type      string        `json:"ip_type,omitempty"`
	ASN       string        `json:"asn,omitempty"`
	Org       string        `json:"org,omitempty"`
	ISP       string        `json:"isp,omitempty"`
	Domain    string        `json:"domain,omitempty"`
	Usage     string        `json:"usage,omitempty"`
	Country   string        `json:"country,omitempty"`
	Privates  []string      `json:"privates,omitempty"` // 隐私/风险标签名，如 vps/hosting/tor_exit
	Raw       []byte        `json:"raw,omitempty"`      // 截断后的原始响应，供点开核对
}

// PurityResult 是汇总后的 IP 纯净度结论。
type PurityResult struct {
	IP        string            `json:"ip"`
	CheckedAt time.Time         `json:"checked_at"`
	Score     int               `json:"score"` // 0-100，越高越纯净
	Level     string            `json:"level"` // excellent/good/fair/poor/bad
	IPType    string            `json:"ip_type"`
	TypeLabel string            `json:"type_label"`
	Factors   PurityFactors     `json:"factors"`
	ASN       string            `json:"asn,omitempty"`
	Org       string            `json:"org,omitempty"`
	ISP       string            `json:"isp,omitempty"`
	Domain    string            `json:"domain,omitempty"`
	Usage     string            `json:"usage,omitempty"`
	Country   string            `json:"country,omitempty"`
	Providers []ProviderVerdict `json:"providers"`
	Reasons   []string          `json:"reasons"`
	// TypeSource 记录「这个 ip_type 是谁给的」：外部来源就是来源名（ipinfo 等），
	// 我们推导出来的就是 derived:asn:AS4766 / derived:isp:telecom 这种标记。
	// 家宽必须是正向证据，所以界面上要把「来源认定」和「推导」分开显示 ——
	// 不配 key 时只有 builtin + ipquery，它们都不给类型字段，混在一起就等于把
	// 「没被情报标记过」当成「干净家宽」。
	TypeSource string `json:"type_source,omitempty"`
	Confidence int    `json:"confidence"` // 0-100，参与汇总的来源权重和
	TTLHours   int    `json:"ttl_hours"`
}

// Level 常量，前端按这个上色。
const (
	PurityExcellent = "excellent" // >=85 纯家宽/住宅
	PurityGood      = "good"      // 70-84
	PurityFair      = "fair"      // 50-69
	PurityPoor      = "poor"      // 30-49
	PurityBad       = "bad"       // <30 机房/匿名/黑名单
)

// IP 类型。跟 IPQuality 的「IP Type」模块对齐，另加 VPN Gate 特有的
// vpngate-hosting（自营机房 219.100.37.0/24、public-vpn-*）。
const (
	TypeResidential  = "residential"
	TypeMobile       = "mobile"
	TypeBusiness     = "business"
	TypeEducation    = "education"
	TypeGovernment   = "government"
	TypeHosting      = "hosting"
	TypeVPNProxy     = "vpn-proxy"
	TypeTor          = "tor"
	TypeCDN          = "cdn"
	TypeSearchEngine = "search-engine"
	TypeVpngateOwn   = "vpngate-hosting"
	TypeUnknown      = "unknown"
)

// TypeLabels 是类型码到中文的映射（前端与 CLI 共用同一份，避免两边漂移）。
var TypeLabels = map[string]string{
	TypeResidential:  "住宅宽带",
	TypeMobile:       "移动网络",
	TypeBusiness:     "企业线路",
	TypeEducation:    "科研教育",
	TypeGovernment:   "政府机构",
	TypeHosting:      "数据中心/机房",
	TypeVPNProxy:     "代理/VPN 出口",
	TypeTor:          "Tor 出口",
	TypeCDN:          "CDN",
	TypeSearchEngine: "搜索引擎爬虫",
	TypeVpngateOwn:   "VPN Gate 自营机房",
	TypeUnknown:      "未知类型",
}

// LevelLabels 是纯净度分档到中文的映射。
var LevelLabels = map[string]string{
	PurityExcellent: "极纯净",
	PurityGood:      "纯净",
	PurityFair:      "一般",
	PurityPoor:      "较差",
	PurityBad:       "脏",
}

// LevelOfScore 按分数给档，别让各处自己写阈值。
func LevelOfScore(s int) string {
	switch {
	case s >= 85:
		return PurityExcellent
	case s >= 70:
		return PurityGood
	case s >= 50:
		return PurityFair
	case s >= 30:
		return PurityPoor
	default:
		return PurityBad
	}
}

// SourceStat 是一个数据源的抓取结果，界面与日志都要显示。
type SourceStat struct {
	Name    string    `json:"name"`
	URL     string    `json:"url"`
	Nodes   int       `json:"nodes"`
	MS      int64     `json:"ms"`
	Err     string    `json:"err,omitempty"`
	Via     string    `json:"via,omitempty"` // direct / mirror-site / cdn / raw
	Commit  string    `json:"commit,omitempty"`
	Skipped int       `json:"skipped,omitempty"` // 因数量骤减等被丢弃
	At      time.Time `json:"at"`
}

// Meta 是节点池的整体元数据。
type Meta struct {
	SchemaVersion  int           `json:"schema_version"`
	UpdatedAt      time.Time     `json:"updated_at"`
	SourceStats    []SourceStat  `json:"source_stats,omitempty"`
	Mirrors        []MirrorEntry `json:"mirrors,omitempty"`
	MirrorsFetched time.Time     `json:"mirrors_fetched,omitempty"`
	LastProbeRound *JobState     `json:"last_probe_round,omitempty"`
	LastPurityScan *JobState     `json:"last_purity_scan,omitempty"`
	LastRefresh    *JobState     `json:"last_refresh,omitempty"`
	Notes          []string      `json:"notes,omitempty"`
}

// MirrorEntry 是 VPN Gate 官方镜像列表页上的一个镜像站。
type MirrorEntry struct {
	Base     string `json:"base"` // scheme://ip:port，不带 /en/
	Location string `json:"location,omitempty"`
}

// JobState 记录一轮任务的进展，前端 SSE 与 /api/jobs 都用它。
type JobState struct {
	Kind       string    `json:"kind"`   // refresh / probe / purity
	Status     string    `json:"status"` // idle / running / done / failed / cancelled
	StartedAt  time.Time `json:"started_at"`
	EndedAt    time.Time `json:"ended_at,omitempty"`
	Total      int       `json:"total"`
	Done       int       `json:"done"`
	OK         int       `json:"ok"`
	Failed     int       `json:"failed"`
	Skipped    int       `json:"skipped"`
	Message    string    `json:"message,omitempty"`
	LastNode   string    `json:"last_node,omitempty"`
	ETASeconds int64     `json:"eta_seconds,omitempty"`
}

// Stats 是给仪表盘头部用的汇总。
type Stats struct {
	Nodes            int     `json:"nodes"`
	PoolNodes        int     `json:"pool_nodes"`  // 含已经不在本轮快照里的
	FreshNodes       int     `json:"fresh_nodes"` // 本轮名单里有的（官方主站 + 官方镜像；第三方源开启后它的快照也算）
	Alive            int     `json:"alive"`
	Unknown          int     `json:"unknown"`
	Down             int     `json:"down"`
	Untested         int     `json:"untested"`
	TCP              int     `json:"tcp"`
	UDP              int     `json:"udp"`
	Countries        int     `json:"countries"`
	MedianPingMS     int64   `json:"median_ping_ms"`
	MedianPurity     int     `json:"median_purity"`
	ResidentialShare float64 `json:"residential_share"`
	// Residential 是被判为志愿者家宽的节点数（share 的分子，给 CLI 和界面直接用）。
	Residential int `json:"residential"`
	// 家宽按证据强度拆两个数：Verified 是有来源给了类型（ipinfo 的 type 之类），
	// Derived 是从 ASN / 运营商名推导出来的。只有推导数时，「家宽 62%」的意思其实是
	// 「大概率是」，界面上必须分开显示，不能混成一个数。
	ResidentialVerified int `json:"residential_verified"`
	ResidentialDerived  int `json:"residential_derived"`
	// PurityTypeUnknown 是「查过纯净度，但没有任何来源给类型、也没推导成功」的数量。
	// 缺这个数，家宽占比会被读成「98% 不是家宽」，而事实是「没数据」。
	PurityTypeUnknown int          `json:"purity_type_unknown"`
	PurityChecked     int          `json:"purity_checked"`
	AvgUpstreamMbps   float64      `json:"avg_upstream_mbps"`
	ProbedAt          time.Time    `json:"probed_at,omitempty"`
	PurityAt          time.Time    `json:"purity_at,omitempty"`
	UpdatedAt         time.Time    `json:"updated_at"`
	Sources           []SourceStat `json:"sources,omitempty"`
}

// CountryBucket 是国家维度的聚合（筛选下拉与国家分布图用）。
type CountryBucket struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	Nodes     int    `json:"nodes"`
	Alive     int    `json:"alive"`
	MedPing   int64  `json:"med_ping_ms"`
	MedPurity int    `json:"med_purity"`
	// Residential 是这一国家里判定为志愿者家宽的节点数。国家分布图按
	// 「家宽数」着色时读它；缺这个字段前端就只能按节点数上色。
	Residential int `json:"residential"`
}
