// Package config 负责配置的默认值、文件加载与环境变量覆盖。
//
// 优先级：命令行 flag > 环境变量 > config.json > 内置默认值。
// 之所以把「关掉某个源」和「该源地址为空」分开处理（Enabled 字段独立），
// 是因为空 URL 是有语义的，悄悄填默认值会把用户明确关掉的东西又打开。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultAPI       = "https://www.vpngate.net/api/iphone/"
	DefaultSitesPage = "https://www.vpngate.net/en/sites.aspx"
)

// Config 是全部可调参数。
type Config struct {
	Listen    string `json:"listen"`
	DataDir   string `json:"data_dir"`
	Title     string `json:"title"`
	LogLevel  string `json:"log_level"` // debug|info|warn|error
	PublicURL string `json:"public_url,omitempty"`

	Auth    AuthConfig    `json:"auth"`
	Sources SourcesConfig `json:"sources"`
	Probe   ProbeConfig   `json:"probe"`
	Purity  PurityConfig  `json:"purity"`
	API     APIConfig     `json:"api"`

	// path 记下实际加载的文件，保存时写回同一个文件。
	path string `json:"-"`
}

// AuthConfig 是登录相关设置。
type AuthConfig struct {
	Username string `json:"username"`
	// Password 写明文即可（首次启动会转成下面的 PBKDF2 并清空）。
	// 生产环境建议直接给 PBKDF2，或者设完一次密码后用界面上的「改密码」。
	Password     string `json:"password,omitempty"`
	PBKDF2       string `json:"pbkdf2,omitempty"` // 格式 pbkdf2$sha256$迭代数$盐$哈希
	SessionHours int    `json:"session_hours"`
	// CookieSecure 在 https 部署时打开；反代结束 TLS 时也可以开。
	CookieSecure bool `json:"cookie_secure"`
	// DisableAuth 只适合纯内网自用的场景，界面与接口全部放开。
	DisableAuth bool `json:"disable_auth"`
}

// APIConfig 是对外只读接口（GET /vpngate/api/iphone/）的参数。
//
// 默认关掉是有意的：这条接口把整个节点库（连 .ovpn 正文）交给调用方，而界面
// 那套「签名 cookie + CSRF」是给浏览器设计的，机器对机器不该借用登录态。
// enabled=true 却没给 token 就直接拒绝启动 —— 「配了一半结果接口裸奔」是
// 最难发现的一类事故，宁可起不来也不要悄悄对外敞开。
type APIConfig struct {
	Enabled bool   `json:"enabled"`
	Token   string `json:"token,omitempty"` // 调用方用 Authorization: Bearer 或 ?key= 带上
	// IncludeConfig 决定响应里有没有 OpenVPN_ConfigData_Base64 这一列。
	// 默认 true：官方 /api/iphone/ 的 15 列里就有它，不给就不算「同形」。
	// 调用方也可以单次用 ?config=0 只要名单（响应体能小一个数量级）。
	IncludeConfig bool `json:"include_config"`
	// MaxNodes 是单次响应的节点上限，剩下的用 offset 翻页。上限锁在 500：
	// 一页带正文就有几 MB，再大对双方都没好处。
	MaxNodes int `json:"max_nodes"`
	// RatePerMinute 按来源 IP 限流，0 = 不限。
	RatePerMinute int `json:"rate_per_minute"`
}

// SourcesConfig 管两个来源：官方主站 API、官方镜像站。
type SourcesConfig struct {
	RefreshIntervalMinutes int `json:"refresh_interval_minutes"`
	KeepDays               int `json:"keep_days"` // 节点在池里保留多少天
	// 提前淘汰：本轮名单里没见到的 TCP 节点，
	// 缺席满 PurgeAbsentHours 且连续 PurgeFailRounds 轮有效探测明确失败就删掉。
	// 「有效」指拿到了确定结论 —— 超时、UDP 无回包、本轮没测到都不算失败。
	// PurgeAbsentHours 设 0 表示不提前淘汰，只按 KeepDays 过期。
	PurgeAbsentHours int `json:"purge_absent_hours"`
	PurgeFailRounds  int `json:"purge_fail_rounds"`
	// MaxNodes 是节点池的容量上限：每轮刷新并入后、以及启动时，超出来的部分会被
	// 容量裁剪请出去（硬伤的先生，再按推荐分从低到高）。0 = 不限。
	// 要有上限的理由：探测一轮、写盘、拉纯净度都随池子线性变贵，
	// 而官方 + 镜像一轮就能给到几千个。
	MaxNodes int `json:"max_nodes"`
	// KeepVpngateOwn 保留 VPN Gate 自营机房节点（hostname public-vpn-*、网段
	// 219.100.37.0/24）。默认 false：那是 SoftEther 官方放在筑波大学学术网里的
	// 机器，本质是机房出口，官方分数再高也不是家宽；要「全局出口稳、别掉线」的
	// 人可以打开。关掉以后新抓到的不进池，池里已有的下一轮刷新一并清掉。
	KeepVpngateOwn bool          `json:"keep_vpngate_own"`
	Vpngate        VpngateSource `json:"vpngate"`
	Mirrors        MirrorSource  `json:"mirrors"`
	UserAgent      string        `json:"user_agent,omitempty"`
}

// VpngateSource 是官方主站。
type VpngateSource struct {
	Enabled         bool `json:"enabled"`
	TimeoutSeconds  int  `json:"timeout_seconds"`
	MinNodes        int  `json:"min_nodes"`         // 数量合理性下限，低于就当异常
	MaxDropPct      int  `json:"max_drop_pct"`      // 比上一轮少这么多百分比就当异常（0=关）
	AllowPrivateIPs bool `json:"allow_private_ips"` // 节点 IP 落在私有/保留段时是否放过
}

// MirrorSource 是 VPN Gate 官方列出的镜像站（sites.aspx 上那批 IP:PORT）。
type MirrorSource struct {
	Enabled        bool   `json:"enabled"`
	SitesPage      string `json:"sites_page"`
	MaxMirrors     int    `json:"max_mirrors"`    // 0=本轮把去重后的镜像全抓（默认）；>0=每轮最多取几个，按 /24 + location 去重后轮转
	ListMaxHours   int    `json:"list_max_hours"` // 镜像列表页缓存时长
	TimeoutSeconds int    `json:"timeout_seconds"`
	MinNodes       int    `json:"min_nodes"`
}

// ProbeConfig 是节点测试参数。
type ProbeConfig struct {
	Enabled           bool `json:"enabled"`
	IntervalMinutes   int  `json:"interval_minutes"`
	Concurrency       int  `json:"concurrency"`
	TCPTimeoutSeconds int  `json:"tcp_timeout_seconds"`
	UDPTimeoutSeconds int  `json:"udp_timeout_seconds"`
	HandshakeSeconds  int  `json:"handshake_seconds"`
	Handshake         bool `json:"handshake"` // 关掉就只测 TCP 连通性
	Retries           int  `json:"retries"`   // TCP 握手失败后的重试次数
	HistoryKeep       int  `json:"history_keep"`
	MaxNodesPerRound  int  `json:"max_nodes_per_round"`
	// Selection: all（池里全部）/ fresh（本轮快照）/ suspect（历史可疑）
	Selection string `json:"selection"`
	// UnknownRetryMinutes：正式一轮跑完后隔多久对「说不清」的 TCP 节点补测一轮。
	// 对齐 mirror 项目「unknown 结果可以用富余容量在一小时后重试」的做法；0 = 不补测。
	// 补测轮不计入淘汰的「连续失败轮数」，否则一轮会被算成两轮、提前一倍删掉。
	UnknownRetryMinutes int      `json:"unknown_retry_minutes"`
	Countries           []string `json:"countries,omitempty"`
	Protocols           []string `json:"protocols,omitempty"` // 只测某些 proto，空=全部
	SkipDownForHours    int      `json:"skip_down_for_hours"` // 连续失败这么久就本轮跳过，给上游减负（0=关）
}

// PurityConfig 是 IP 纯净度参数。
type PurityConfig struct {
	Enabled           bool              `json:"enabled"`
	IntervalMinutes   int               `json:"interval_minutes"`
	TTLHours          int               `json:"ttl_hours"`
	Concurrency       int               `json:"concurrency"`
	RequestsPerMinute int               `json:"requests_per_minute"` // 全局令牌桶，免费源都会限流
	MinProviders      int               `json:"min_providers"`       // 少于这么多个来源就当结论不可信
	MaxNodesPerRound  int               `json:"max_nodes_per_round"`
	Selection         string            `json:"selection"` // all / fresh / unchecked
	Countries         []string          `json:"countries,omitempty"`
	RawKeepBytes      int               `json:"raw_keep_bytes"`      // 每个来源保留多少原始响应字节给界面核对
	Providers         map[string]bool   `json:"providers,omitempty"` // 显式开关，nil 用默认
	Keys              map[string]string `json:"keys,omitempty"`
	// PreferResidential 在排序里给住宅 IP 加权（列表打分用），不影响结论本身。
	PreferResidential bool `json:"prefer_residential"`
}

// Default 返回一份「什么都不配」时的合理参数。
func Default() Config {
	return Config{
		Listen:   ":8080",
		DataDir:  "data",
		Title:    "VPN Gate 节点聚合中心",
		LogLevel: "info",
		Auth: AuthConfig{
			Username:     "admin",
			Password:     "",
			SessionHours: 168,
		},
		Sources: SourcesConfig{
			RefreshIntervalMinutes: 60,
			KeepDays:               7,
			PurgeAbsentHours:       24,
			PurgeFailRounds:        3,
			MaxNodes:               1500,
			Vpngate: VpngateSource{
				Enabled:        true,
				TimeoutSeconds: 35,
				MinNodes:       20,
				MaxDropPct:     50,
			}, Mirrors: MirrorSource{
				Enabled:        true,
				SitesPage:      DefaultSitesPage,
				MaxMirrors:     0, // 0 = 每轮全抓：节点量全靠这几个镜像抹开
				ListMaxHours:   12,
				TimeoutSeconds: 30,
				MinNodes:       20,
			},
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
		},
		Probe: ProbeConfig{
			Enabled:           true,
			IntervalMinutes:   360, // 6 小时一轮，对齐 mirror 的六小时探测轮；界面里手动触发不受限
			Concurrency:       64,
			TCPTimeoutSeconds: 5,
			UDPTimeoutSeconds: 4,
			HandshakeSeconds:  4,
			Handshake:         true,
			Retries:           1,
			HistoryKeep:       8,
			MaxNodesPerRound:  2000,
			// all：源只剩官方接口和镜像站后一轮就 270 个左右，池子里累积的老节点
			// 也得保持复测，否则它们的可达状态会逐周期变旧。
			Selection:           "all",
			UnknownRetryMinutes: 60,
			SkipDownForHours:    12,
		},
		Purity: PurityConfig{
			Enabled:           true,
			IntervalMinutes:   720,
			TTLHours:          168,
			Concurrency:       6,
			RequestsPerMinute: 40,
			MinProviders:      1,
			MaxNodesPerRound:  800,
			Selection:         "unchecked",
			RawKeepBytes:      900,
			PreferResidential: true,
		},
		API: APIConfig{
			Enabled:       false,
			IncludeConfig: true,
			MaxNodes:      500,
			RatePerMinute: 30,
		},
	}
}

// Load 读配置文件（不存在时用默认值），再叠加环境变量与 flag 覆盖，最后校验。
//
// 没给 -config 时的查找顺序：VPNGATE_AGG_CONFIG → <数据目录>/config.json → ./config.json。
// 中间那条是必须的：界面上改开关时 PatchConfig 会把配置写到 <data_dir>/config.json，
// 启动时不读回来就成了「界面上改了、重启就丢」，那比不给改更糟。
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = firstExistingConfig()
	}
	if b, err := os.ReadFile(path); err == nil {
		// 先解到默认值上，缺字段就保留默认，不会因为加字段而把老配置里的默认掏空。
		if err := json.Unmarshal(b, &cfg); err != nil {
			return cfg, fmt.Errorf("解析配置文件 %s 失败: %w", path, err)
		}
		cfg.path = path
	} else if !os.IsNotExist(err) {
		return cfg, fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
	}
	applyEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// firstExistingConfig 按优先级挑一个存在的配置文件；都没有就返回 ""（用默认值）。
func firstExistingConfig() string {
	if p := strings.TrimSpace(os.Getenv("VPNGATE_AGG_CONFIG")); p != "" {
		return p
	}
	dataDir := strings.TrimSpace(os.Getenv("VPNGATE_AGG_DATA_DIR"))
	if dataDir == "" {
		dataDir = Default().DataDir
	}
	for _, cand := range []string{filepath.Join(dataDir, "config.json"), "config.json"} {
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
	}
	return ""
}

// applyEnv 用环境变量覆盖。只覆盖「部署时真的会变的」那些，
// 剩下的走配置文件，否则环境变量清单会变成第二套未文档化的配置。
func applyEnv(c *Config) {
	setStr := func(env string, dst *string) {
		if v, ok := os.LookupEnv(env); ok {
			*dst = v
		}
	}
	setInt := func(env string, dst *int) {
		v, ok := os.LookupEnv(env)
		if !ok {
			return
		}
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			*dst = n
		}
	}
	setBool := func(env string, dst *bool) {
		v, ok := os.LookupEnv(env)
		if !ok {
			return
		}
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "on":
			*dst = true
		case "0", "false", "no", "off":
			*dst = false
		}
	}

	setStr("VPNGATE_AGG_LISTEN", &c.Listen)
	setStr("VPNGATE_AGG_DATA_DIR", &c.DataDir)
	setStr("VPNGATE_AGG_TITLE", &c.Title)
	setStr("VPNGATE_AGG_LOG_LEVEL", &c.LogLevel)
	setStr("VPNGATE_AGG_USER", &c.Auth.Username)
	setStr("VPNGATE_AGG_PASSWORD", &c.Auth.Password)
	setStr("VPNGATE_AGG_PBKDF2", &c.Auth.PBKDF2)
	setBool("VPNGATE_AGG_COOKIE_SECURE", &c.Auth.CookieSecure)
	setBool("VPNGATE_AGG_DISABLE_AUTH", &c.Auth.DisableAuth)
	setBool("VPNGATE_AGG_API_ENABLED", &c.API.Enabled)
	setStr("VPNGATE_AGG_API_TOKEN", &c.API.Token)
	setBool("VPNGATE_AGG_API_INCLUDE_CONFIG", &c.API.IncludeConfig)
	setInt("VPNGATE_AGG_API_MAX_NODES", &c.API.MaxNodes)
	setInt("VPNGATE_AGG_API_RATE_PER_MIN", &c.API.RatePerMinute)
	setInt("VPNGATE_AGG_REFRESH_MINUTES", &c.Sources.RefreshIntervalMinutes)
	// 池子容量上限：0 = 不限。用同一个变量名是为了跟界面里的 max_nodes 对得上。
	setInt("VPNGATE_AGG_MAX_NODES", &c.Sources.MaxNodes)
	setInt("VPNGATE_AGG_PROBE_INTERVAL", &c.Probe.IntervalMinutes)
	setInt("VPNGATE_AGG_PROBE_CONCURRENCY", &c.Probe.Concurrency)
	setBool("VPNGATE_AGG_PROBE_ENABLED", &c.Probe.Enabled)
	setBool("VPNGATE_AGG_KEEP_VPNGATE_OWN", &c.Sources.KeepVpngateOwn)
	setInt("VPNGATE_AGG_PURITY_RPM", &c.Purity.RequestsPerMinute)
	setBool("VPNGATE_AGG_PURITY_ENABLED", &c.Purity.Enabled)

	// API key 用通用的短名字，方便和 IPQuality 那类脚本的用法对齐。
	for name, env := range map[string]string{
		"ipquery":        "IPQUERY_KEY",
		"ipinfo":         "IPINFO_TOKEN",
		"scamalytics":    "SCAMALYTICS_KEY",
		"ipqualityscore": "IPQUALITYSCORE_KEY",
		"ipregistry":     "IPREGISTRY_KEY",
		"abuseipdb":      "ABUSEIPDB_KEY",
		"dbip":           "DBIP_KEY",
		"ip2location":    "IP2LOCATION_KEY",
	} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			if c.Purity.Keys == nil {
				c.Purity.Keys = map[string]string{}
			}
			c.Purity.Keys[name] = v
		}
	}
}

// Validate 兜底数值、拒绝明显不成立的组合。
func (c *Config) Validate() error {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	if c.Title == "" {
		c.Title = Default().Title
	}
	if c.Auth.SessionHours <= 0 {
		c.Auth.SessionHours = 168
	}
	if c.Auth.SessionHours > 24*365 {
		return fmt.Errorf("auth.session_hours 太大（%d），最多 8760", c.Auth.SessionHours)
	}
	if !c.Auth.DisableAuth && strings.TrimSpace(c.Auth.Username) == "" {
		return fmt.Errorf("auth.username 不能为空（要彻底关掉登录就设 auth.disable_auth=true）")
	}
	c.API.Token = strings.TrimSpace(c.API.Token)
	if c.API.Enabled && c.API.Token == "" {
		return fmt.Errorf("api.enabled=true 但 api.token 为空：对外接口必须有 token，不想开就别设 api.enabled（生成一个：openssl rand -hex 24）")
	}
	if len(c.API.Token) > 0 && len(c.API.Token) < 16 {
		return fmt.Errorf("api.token 太短（%d 字符），至少 16：这是对外接口唯一的门闩", len(c.API.Token))
	}
	if c.API.MaxNodes <= 0 {
		c.API.MaxNodes = Default().API.MaxNodes
	}
	if c.API.MaxNodes > 500 {
		c.API.MaxNodes = 500 // 再大就是让调用方一次吞几十 MB 正文，翻页吧
	}
	if c.API.RatePerMinute < 0 {
		c.API.RatePerMinute = 0
	}
	if c.Sources.RefreshIntervalMinutes <= 0 {
		c.Sources.RefreshIntervalMinutes = 60
	}
	if c.Sources.KeepDays <= 0 {
		c.Sources.KeepDays = 7
	}
	// 提前淘汰参数：负数是写错了，回到默认 24 小时；显式写 0 表示“只按 keep_days 过期”。
	if c.Sources.PurgeAbsentHours < 0 {
		c.Sources.PurgeAbsentHours = 24
	}
	if c.Sources.PurgeFailRounds <= 0 {
		c.Sources.PurgeFailRounds = 3
	} else if c.Sources.PurgeFailRounds > 12 {
		c.Sources.PurgeFailRounds = 12 // 再高就永远碰不到，等于只按 keep_days 过期
	}
	if c.Sources.UserAgent == "" {
		c.Sources.UserAgent = Default().Sources.UserAgent
	}
	if c.Sources.Vpngate.Enabled && c.Sources.Vpngate.TimeoutSeconds <= 0 {
		c.Sources.Vpngate.TimeoutSeconds = 35
	}
	if c.Sources.Mirrors.Enabled && c.Sources.Mirrors.SitesPage == "" {
		c.Sources.Mirrors.SitesPage = DefaultSitesPage
	}
	// 0 = 本轮全抓（默认），所以只拒负数。
	if c.Sources.Mirrors.MaxMirrors < 0 {
		c.Sources.Mirrors.MaxMirrors = 0
	}
	// max_nodes：0 = 不限（默认）。负数是配置写错；十万这个上限是为了拦住
	// 「多打几个 0」——真按十万节点跑一轮探测就是几个小时，不如拒掉。
	if c.Sources.MaxNodes < 0 {
		return fmt.Errorf("sources.max_nodes 不能是负数（0 = 不限），给的是 %d", c.Sources.MaxNodes)
	}
	if c.Sources.MaxNodes > 100000 {
		c.Sources.MaxNodes = 100000
	}
	if c.Probe.Enabled {
		if c.Probe.IntervalMinutes <= 0 {
			c.Probe.IntervalMinutes = 360
		}
		if c.Probe.Concurrency <= 0 {
			c.Probe.Concurrency = 64
		}
		if c.Probe.Concurrency > 512 {
			c.Probe.Concurrency = 512 // 再高就是在自己机器上制造 SYN 风暴了
		}
		if c.Probe.TCPTimeoutSeconds <= 0 {
			c.Probe.TCPTimeoutSeconds = 5
		}
		if c.Probe.UDPTimeoutSeconds <= 0 {
			c.Probe.UDPTimeoutSeconds = 4
		}
		if c.Probe.HandshakeSeconds <= 0 {
			c.Probe.HandshakeSeconds = 4
		}
		if c.Probe.Retries < 0 {
			c.Probe.Retries = 0
		}
		if c.Probe.HistoryKeep <= 0 {
			c.Probe.HistoryKeep = 8
		}
		if c.Probe.HistoryKeep > 64 {
			c.Probe.HistoryKeep = 64
		}
		if c.Probe.UnknownRetryMinutes < 0 {
			c.Probe.UnknownRetryMinutes = 0
		}
		// 补测轮不能顶到下一轮头上：两轮挨着跑会把「连续失败轮数」算两次，
		// 节点会提前一倍被删掉。
		if c.Probe.UnknownRetryMinutes >= c.Probe.IntervalMinutes {
			c.Probe.UnknownRetryMinutes = c.Probe.IntervalMinutes / 2
		}
		switch c.Probe.Selection {
		case "":
			c.Probe.Selection = "all"
		case "all", "fresh", "suspect":
		default:
			return fmt.Errorf("probe.selection 只能是 all/fresh/suspect，给的是 %q", c.Probe.Selection)
		}
	}
	if c.Purity.Enabled {
		if c.Purity.TTLHours <= 0 {
			c.Purity.TTLHours = 168
		}
		if c.Purity.Concurrency <= 0 {
			c.Purity.Concurrency = 6
		}
		if c.Purity.RequestsPerMinute <= 0 {
			c.Purity.RequestsPerMinute = 40
		}
		if c.Purity.IntervalMinutes <= 0 {
			c.Purity.IntervalMinutes = 720
		}
		if c.Purity.RawKeepBytes < 0 {
			c.Purity.RawKeepBytes = 0
		}
		switch c.Purity.Selection {
		case "":
			c.Purity.Selection = "unchecked"
		case "all", "fresh", "unchecked":
		default:
			return fmt.Errorf("purity.selection 只能是 all/fresh/unchecked，给的是 %q", c.Purity.Selection)
		}
	}
	return nil
}

// Path 返回实际加载的配置文件路径（空串表示用的是默认值）。
func (c Config) Path() string { return c.path }

// Interval 等几个便捷方法：把秒配置换成 time.Duration，避免每个调用点各写一遍。
func (s SourcesConfig) RefreshInterval() time.Duration {
	return time.Duration(s.RefreshIntervalMinutes) * time.Minute
}

// PurgeAbsent 是「缺席多久 + 连续几轮明确失败」里那个时间门槛；0 表示不提前淘汰。
func (s SourcesConfig) PurgeAbsent() time.Duration {
	return time.Duration(s.PurgeAbsentHours) * time.Hour
}
func (p ProbeConfig) Interval() time.Duration {
	return time.Duration(p.IntervalMinutes) * time.Minute
}
func (p PurityConfig) Interval() time.Duration {
	return time.Duration(p.IntervalMinutes) * time.Minute
}
func (p PurityConfig) TTL() time.Duration { return time.Duration(p.TTLHours) * time.Hour }

// UnknownRetry 是正式一轮跑完后隔多久补测「说不清」的节点；0 表示不补测。
func (p ProbeConfig) UnknownRetry() time.Duration {
	return time.Duration(p.UnknownRetryMinutes) * time.Minute
}

// ProviderEnabled 判断某个纯净度来源是否启用。
// 规则：显式设过就用显式的，否则「免费源默认开、要 key 的有 key 才开」。
func (p PurityConfig) ProviderEnabled(name string, needsKey bool) bool {
	if p.Providers != nil {
		if v, ok := p.Providers[name]; ok {
			return v
		}
	}
	if !needsKey {
		return true
	}
	return strings.TrimSpace(p.Keys[name]) != ""
}

// Save 把配置写回原路径（没有原路径时写到 data 目录下）。
// 只在「运行时会改」的几处用到（改密码），所以不做备份轮换，
// 直接临时文件 + rename，避免写一半掉电留下半截 JSON。
func (c *Config) Save() error {
	path := c.path
	if path == "" {
		path = filepath.Join(c.DataDir, "config.json")
		c.path = path
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// MaskedKey 给界面回显 key 时用：只露首尾各 3 位。
func MaskedKey(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if len(v) <= 8 {
		return strings.Repeat("*", len(v))
	}
	return v[:3] + strings.Repeat("*", len(v)-6) + v[len(v)-3:]
}
