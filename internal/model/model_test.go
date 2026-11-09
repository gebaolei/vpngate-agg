package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLevelOfScoreBoundaries(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{100, PurityExcellent}, {86, PurityExcellent}, {85, PurityExcellent},
		{84, PurityGood}, {71, PurityGood}, {70, PurityGood},
		{69, PurityFair}, {51, PurityFair}, {50, PurityFair},
		{49, PurityPoor}, {31, PurityPoor}, {30, PurityPoor},
		{29, PurityBad}, {1, PurityBad}, {0, PurityBad}, {-5, PurityBad},
	}
	for _, c := range cases {
		if got := LevelOfScore(c.score); got != c.want {
			t.Errorf("LevelOfScore(%d) = %s，期望 %s", c.score, got, c.want)
		}
	}

	// 分数越高档位不能变差：界面上「92 分但显示成脏」是解释不通的。
	prev := ""
	for s := -10; s <= 110; s++ {
		lv := LevelOfScore(s)
		if LevelLabels[lv] == "" {
			t.Fatalf("分数 %d 给出了没有中文标签的档位 %q", s, lv)
		}
		if prev != "" && orderOf(lv) < orderOf(prev) {
			t.Errorf("分数从 %d 升到 %d，档位反而从 %s 退回 %s", s-1, s, prev, lv)
		}
		prev = lv
	}
}

func orderOf(level string) int {
	for i, l := range []string{PurityBad, PurityPoor, PurityFair, PurityGood, PurityExcellent} {
		if l == level {
			return i
		}
	}
	return -1
}

// 前端和 CLI 共用这两张表：漏一个码，界面上就会出现「undefined」。
func TestLabelMapsCoverEveryCode(t *testing.T) {
	for _, l := range []string{PurityExcellent, PurityGood, PurityFair, PurityPoor, PurityBad} {
		if strings.TrimSpace(LevelLabels[l]) == "" {
			t.Errorf("档位 %s 没有中文标签", l)
		}
	}
	types := []string{
		TypeResidential, TypeMobile, TypeBusiness, TypeEducation, TypeGovernment,
		TypeHosting, TypeVPNProxy, TypeTor, TypeCDN, TypeSearchEngine, TypeVpngateOwn, TypeUnknown,
	}
	for _, tp := range types {
		if strings.TrimSpace(TypeLabels[tp]) == "" {
			t.Errorf("类型 %s 没有中文标签", tp)
		}
	}
	// 标签不能重复到分不清：两个码同一个中文名，用户就没法区分机房和自营。
	seen := map[string]string{}
	for _, tp := range types {
		label := TypeLabels[tp]
		if other, dup := seen[label]; dup {
			t.Errorf("类型 %s 和 %s 共用了标签 %q", tp, other, label)
		}
		seen[label] = tp
	}
	// 未知类型必须有个能显示的名字，不能是空串。
	if TypeLabels["没这个类型"] != "" {
		t.Error("映射表里不该出现未知键（上面用 TypeLabels[x] 取不到时前端会显示 undefined）")
	}
}

func TestProbeHealthLevelTable(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		why  string
		h    ProbeHealth
		want string
	}{
		{"没测过", ProbeHealth{}, "untested"},
		{"全成功", ProbeHealth{Tests: 4, Successes: 4, SuccessPct: 100, Alive: &yes}, "stable"},
		{"连着但成功率低", ProbeHealth{Tests: 4, Successes: 3, SuccessPct: 75, Alive: &yes}, "reachable"},
		{"明确不可达且连续两次", ProbeHealth{Tests: 3, Successes: 1, FailStreak: 2, Alive: &no}, "down"},
		{"明确不可达但只一次", ProbeHealth{Tests: 2, Successes: 1, FailStreak: 1, Alive: &no}, "flaky"},
		{"超时未知", ProbeHealth{Tests: 3, FailStreak: 3, Alive: nil}, "unknown"},
		{"以前连上过现在超时", ProbeHealth{Tests: 4, Successes: 3, FailStreak: 1, Alive: nil}, "flaky"},
	}
	for _, c := range cases {
		if got := HealthLevel(c.h); got != c.want {
			t.Errorf("%s: Level() = %s，期望 %s", c.why, got, c.want)
		}
	}
}

func TestNodeAddrFallsBack(t *testing.T) {
	// .ovpn 里的 remote 优先：客户端连的就是它，探测要跟客户端一致。
	n := &Node{IP: "8.8.8.1", Server: "vpn.example.jp", Port: 1194, Proto: "tcp"}
	if host, port, proto := n.Addr(); host != "vpn.example.jp" || port != 1194 || proto != "tcp" {
		t.Errorf("Addr = %s:%d/%s", host, port, proto)
	}
	// 没有 remote 才回落到 CSV 的 IP。
	n2 := &Node{IP: "8.8.8.1"}
	if host, port, proto := n2.Addr(); host != "8.8.8.1" || port != 1194 || proto != "udp" {
		t.Errorf("缺字段时的默认地址 = %s:%d/%s，期望回落 IP/1194/udp", host, port, proto)
	}
	// 端口为 0 或负数（累积池里见过）都不能把探测指到 0 端口。
	n3 := &Node{IP: "8.8.8.1", Server: "vpn.example.jp", Port: -1, Proto: "udp"}
	if _, port, _ := n3.Addr(); port != 1194 {
		t.Errorf("端口 = %d", port)
	}
	// 空节点也不能崩。
	var zero Node
	if host, port, proto := zero.Addr(); host != "" || port != 1194 || proto != "udp" {
		t.Errorf("零值节点 Addr = %q:%d/%s", host, port, proto)
	}
}

// 前端是按 JSON 字段名读数据的：这些名字改了必须同时改 app.js，
// 否则线上表现是「表格空白」而不是编译失败。这里把契约钉住。
func TestJSONFieldNamesMatchFrontendContract(t *testing.T) {
	now := time.Now().UTC()
	yes := true
	ms := int64(30)
	score := 5

	nodeJSON := mustMarshal(t, &Node{
		ID: "v1:" + strings.Repeat("a", 64), HostName: "vpnA", IP: "8.8.8.1",
		Country: "Japan (Tokyo)", CountryCode: "JP", Operator: "NTT", Message: "hi", LogType: "no logging",
		UpstreamScore: 1, UpstreamPingMS: 2, UpstreamSpeedBps: 3, Sessions: 4,
		ConfigSHA256: strings.Repeat("b", 64), ConfigBytes: 100, ConfigLocal: true,
		Server: "vpn.example.jp", Port: 1194, Proto: "tcp", Cipher: "AES-256-GCM",
		AuthAlgorithm: "SHA1", Vendor: "softether", HasCerts: true, Residential: &yes,
		FirstSeen: now, LastSeen: now, InLatestSource: &yes, LastSource: "vpngate",
		CFProbe: &CFProbe{Status: "reachable", CheckedAt: now, ConnectMS: &ms, Endpoint: "tls:xxx", Source: "cf", Round: 1},
		Probe:   &ProbeResult{At: now, OK: true, Host: "8.8.8.1", Port: 1194, Proto: "tcp", RTTMS: 30, ConnectMS: 28, Handshake: true, Service: ServiceSoftEther, Detail: "d", Reason: "r", Attempts: 1, DurationMS: 31},
		Probes:  []ProbeSample{{At: now, OK: true, RTTMS: 30, Service: ServiceSoftEther, Reason: "r"}},
		Health:  ProbeHealth{Tests: 1, Successes: 1, SuccessPct: 100, FailStreak: 0, LastOK: now, LastTry: now, EWMAPingMS: 30, Alive: &yes, Confidence: 1},
		Purity:  &PurityResult{IP: "8.8.8.1", CheckedAt: now, Score: 90, Level: PurityExcellent, IPType: TypeResidential, TypeLabel: "住宅宽带", Confidence: 100, TTLHours: 72, ASN: "AS9405", Org: "BB-Tech", ISP: "BBTech", Domain: "bbtec.net", Country: "JP", Usage: "家宽", Reasons: []string{"r"}, Providers: []ProviderVerdict{{Name: "ipquery", OK: true, Score: &score, ScoreName: "risk", Type: TypeResidential, ASN: "AS9405", Org: "BB-Tech", Raw: []byte("{}"), MS: 12}}},
		Notes:   []string{"n"},
	})
	for _, key := range []string{
		"id", "hostname", "ip", "country", "country_code", "operator", "message", "logtype",
		"upstream_score", "upstream_ping_ms", "upstream_speed_bps", "sessions",
		"config_sha256", "config_bytes", "config_local", "server", "port", "proto",
		"cipher", "auth_algorithm", "vendor", "has_certs", "residential",
		"first_seen", "last_seen", "in_latest_source", "last_source",
		"cf_tcp", "probe", "probes", "health", "purity", "notes",
	} {
		if _, ok := nodeJSON[key]; !ok {
			t.Errorf("节点 JSON 缺字段 %q（前端按这个名字读）", key)
		}
	}

	healthJSON := mustMarshal(t, ProbeHealth{Tests: 1, Confidence: 0.5})
	for _, key := range []string{"tests", "successes", "success_pct", "fail_streak", "level", "ewma_ping_ms", "confidence"} {
		if _, ok := healthJSON[key]; !ok {
			t.Errorf("health JSON 缺字段 %q", key)
		}
	}

	known := true
	no := false
	abuse := 60
	purityJSON := mustMarshal(t, &PurityResult{
		IP: "1.1.1.1", Score: 50, Level: PurityFair, IPType: TypeHosting,
		ASN: "AS24940", Org: "Hetzner", ISP: "Hetzner", Domain: "hetzner.com", Country: "DE", Usage: "机房",
		Factors:   PurityFactors{Proxy: &known, VPN: &known, Tor: &no, Datacenter: &no, Mobile: &no, Abuser: &no, Bot: &no, AbuseScore: &abuse},
		Providers: []ProviderVerdict{{Name: "x"}},
	})
	for _, key := range []string{"ip", "checked_at", "score", "level", "ip_type", "type_label", "confidence", "ttl_hours", "asn", "org", "isp", "domain", "country", "usage", "factors", "reasons", "providers"} {
		if _, ok := purityJSON[key]; !ok {
			t.Errorf("purity JSON 缺字段 %q", key)
		}
	}
	for _, key := range []string{"proxy", "vpn", "tor", "datacenter", "mobile", "abuser", "bot", "abuse_score"} {
		if _, ok := purityJSON["factors"].(map[string]any)[key]; !ok {
			t.Errorf("factors 缺字段 %q（因子表按这些键渲染）", key)
		}
	}
	// 没表态的因子要整个不出现在 JSON 里，前端才能区分「不知道」和「不是」。
	if got := mustMarshal(t, PurityFactors{}); len(got) != 0 {
		t.Errorf("零值因子集被序列化成 %v，期望整个省略", got)
	}
	// 来源明细里 raw 是 base64，界面拿到后要 atob 再展开。
	verdict := mustMarshal(t, ProviderVerdict{Name: "ipquery", OK: true, Raw: []byte("{}中")})
	if _, ok := verdict["raw"].(string); !ok {
		t.Errorf("raw 应是 base64 字符串，实得 %T", verdict["raw"])
	}

	statsJSON := mustMarshal(t, Stats{Nodes: 1, PoolNodes: 1, FreshNodes: 1, Alive: 1, Down: 1, Untested: 1, Unknown: 1, TCP: 1, UDP: 1, Countries: 1, MedianPingMS: 1, MedianPurity: 1, ResidentialShare: 1, PurityChecked: 1, AvgUpstreamMbps: 1, ProbedAt: now, PurityAt: now, UpdatedAt: now, Sources: []SourceStat{{Name: "official"}}})
	for _, key := range []string{"nodes", "pool_nodes", "fresh_nodes", "alive", "down", "untested", "unknown", "tcp", "udp", "countries", "median_ping_ms", "median_purity", "residential_share", "purity_checked", "avg_upstream_mbps", "probed_at", "purity_at", "updated_at", "sources"} {
		if _, ok := statsJSON[key]; !ok {
			t.Errorf("stats JSON 缺字段 %q（仪表盘卡片按这些名字取）", key)
		}
	}

	jobJSON := mustMarshal(t, &JobState{Kind: "probe", Status: "running", StartedAt: now, Total: 10, Done: 1, OK: 1, Failed: 0, Skipped: 0, Message: "m", LastNode: "vpnA", ETASeconds: 5})
	for _, key := range []string{"kind", "status", "started_at", "total", "done", "ok", "failed", "skipped", "message", "last_node", "eta_seconds"} {
		if _, ok := jobJSON[key]; !ok {
			t.Errorf("job JSON 缺字段 %q（进度条按这些名字读）", key)
		}
	}

	countryJSON := mustMarshal(t, CountryBucket{Code: "JP", Name: "Japan", Nodes: 1, Alive: 1, MedPing: 1, MedPurity: 1, Residential: 1})
	for _, key := range []string{"code", "name", "nodes", "alive", "med_ping_ms", "med_purity", "residential"} {
		if _, ok := countryJSON[key]; !ok {
			t.Errorf("国家桶 JSON 缺字段 %q", key)
		}
	}
}

// omitempty 用错会让前端拿到 undefined 而不是走默认分支，
// 所以「没值时应该没有这个键」也要钉住。
func TestJSONOmitEmptyOnOptionalFields(t *testing.T) {
	b, err := json.Marshal(&Node{ID: "x", HostName: "h", IP: "1.1.1.1"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"operator", "message", "cf_tcp", "probe", "probes", "purity", "notes", "residential", "in_latest_source", "last_source", "vendor", "cipher"} {
		if _, present := m[key]; present {
			t.Errorf("没值的 %q 不该出现在 JSON 里（前端要按「缺字段」判断有没有测过）", key)
		}
	}
	// health 不是指针，永远会出现：前端可以直接读 health.level。
	if _, ok := m["health"]; !ok {
		t.Error("health 必须始终存在")
	}
}

func mustMarshal(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	return m
}

// 自营机房识别是「保留自营节点」这个开关的唯一依据，判错会整批误删/误留，
// 所以前缀和网段两条路都要钉住。
func TestVpngateOwn(t *testing.T) {
	cases := []struct {
		ip, host string
		want     bool
		why      string
	}{
		{"219.100.37.11", "vpn123", true, "自营网段"},
		{"219.100.37.254", "", true, "自营网段末尾"},
		{"8.8.8.8", "public-vpn-232", true, "public-vpn 前缀"},
		{"8.8.8.8", "PUBLIC_VPN-9", true, "大小写和下划线变体"},
		{"8.8.8.8", "vpn123", false, "普通节点"},
		{"219.100.36.11", "vpn123", false, "相邻网段不算"},
		{"240b:4000::1", "vpn123", false, "IPv6 不套自营网段"},
		{"", "vpn123", false, "空 IP"},
		{"不是 IP", "vpn123", false, "烂 IP 文本不 panic"},
	}
	for _, c := range cases {
		if got := VpngateOwn(c.ip, c.host); got != c.want {
			t.Errorf("VpngateOwn(%q, %q) = %v，期望 %v（%s）", c.ip, c.host, got, c.want, c.why)
		}
	}
}

// 缓存离线重算要用 AllEmpty 还原 builtin 的弃权票：false 是表过态，不算空。
func TestPurityFactorsAllEmpty(t *testing.T) {
	if !(PurityFactors{}).AllEmpty() {
		t.Error("空因子集应判为 AllEmpty")
	}
	no := false
	if (PurityFactors{Datacenter: &no}).AllEmpty() {
		t.Error("明确 false 也是表过态，不该算空")
	}
	if (PurityFactors{Streaming: &no}).AllEmpty() {
		t.Error("Streaming 漏算了")
	}
	zero := 0
	if (PurityFactors{AbuseScore: &zero}).AllEmpty() {
		t.Error("AbuseScore=0 也是表过态")
	}
}
