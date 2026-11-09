package purity

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/config"
	"github.com/gebaolei/vpngate-agg/internal/model"
)

func boolp(v bool) *bool { return &v }
func intp(v int) *int    { return &v }

// 家宽 + 无风险因子 + 两个来源 → 高分、residential。
func TestMergeResidential(t *testing.T) {
	res := Merge(Query{IP: "1.2.3.4", HostName: "vpn100"}, []*Signals{
		{Name: "ipquery", OK: true, Type: model.TypeResidential, Score: intp(4), ScoreName: "risk",
			Factors: model.PurityFactors{Datacenter: boolp(false), Proxy: boolp(false), VPN: boolp(false), Tor: boolp(false)}},
		{Name: "scamalytics", OK: true, Type: model.TypeResidential, Score: intp(0), ScoreName: "FraudScore"},
	}, MergeOptions{})

	if res.IPType != model.TypeResidential {
		t.Errorf("类型 = %s，期望 residential", res.IPType)
	}
	if res.TypeLabel != model.TypeLabels[model.TypeResidential] {
		t.Errorf("类型中文 = %q", res.TypeLabel)
	}
	if res.Score < 90 {
		t.Errorf("纯净度 = %d，两家都说干净，应该很高", res.Score)
	}
	if res.Level != model.PurityExcellent {
		t.Errorf("档位 = %s，期望 excellent", res.Level)
	}
	if res.Confidence < 95 {
		t.Errorf("两个来源的可信度 = %d，期望接近 100", res.Confidence)
	}
}

// 一个专业源明确说是机房，就算另一个不同意也算 ——
// 把机房误判成家宽的代价（连上后被目标站风控）比反过来重。
func TestMergeHostingOneProfessionalIsEnough(t *testing.T) {
	res := Merge(Query{IP: "5.9.9.9"}, []*Signals{
		{Name: "ipinfo", OK: true, Type: model.TypeBusiness, Score: intp(20),
			Factors: model.PurityFactors{Datacenter: boolp(false)}},
		{Name: "scamalytics", OK: true, Type: model.TypeHosting, Score: intp(88), ScoreName: "FraudScore",
			Factors: model.PurityFactors{Datacenter: boolp(true)}},
	}, MergeOptions{})

	if res.Factors.Datacenter == nil || !*res.Factors.Datacenter {
		t.Error("专业源说是机房，汇总后因子必须是 true")
	}
	if res.IPType != model.TypeHosting {
		t.Errorf("类型 = %s，期望 hosting", res.IPType)
	}
	if res.Score > 50 {
		t.Errorf("机房给到 %d 分太高了", res.Score)
	}
	if res.Reasons == nil || len(res.Reasons) == 0 {
		t.Error("必须给出能解释判定的理由")
	}
}

// 低权重来源单独说是机房，不该盖过两个来源的「不是」。
// ipinfo 会把 VPS 标成 vpn、ipquery 会把整个云段标成 datacenter，
// 这些不是同一件事，所以机房类结论要共识。
func TestMergeWeakSourceAloneCannotCallHosting(t *testing.T) {
	res := Merge(Query{IP: "9.9.9.9"}, []*Signals{
		{Name: "some-unknown-source", OK: true, Factors: model.PurityFactors{Datacenter: boolp(true)}},
		{Name: "ipinfo", OK: true, Type: model.TypeResidential, Factors: model.PurityFactors{Datacenter: boolp(false)}},
		{Name: "ipquery", OK: true, Type: model.TypeResidential, Factors: model.PurityFactors{Datacenter: boolp(false)}},
	}, MergeOptions{})
	if orTrue(res.Factors.Datacenter) {
		t.Errorf("一个权重 0.8 的未知来源不该定机房，因子=%v，理由=%v", res.Factors.Datacenter, res.Reasons)
	}
}

// Tor 出口即使各家分数都好看，也不可能是「纯净」——风险分有下限。
func TestMergeTorFloor(t *testing.T) {
	res := Merge(Query{IP: "171.25.193.9"}, []*Signals{
		{Name: "scamalytics", OK: true, Type: model.TypeTor, Score: intp(3), ScoreName: "FraudScore",
			Factors: model.PurityFactors{Tor: boolp(true)}},
		{Name: "ipquery", OK: true, Type: model.TypeTor, Score: intp(10),
			Factors: model.PurityFactors{Tor: boolp(true)}},
	}, MergeOptions{})

	if res.IPType != model.TypeTor {
		t.Errorf("类型 = %s，期望 tor", res.IPType)
	}
	if res.Score > 30 {
		t.Errorf("Tor 出口给 %d 分太宽松了", res.Score)
	}
	if res.Level != model.PurityBad {
		t.Errorf("档位 = %s，期望 bad", res.Level)
	}
	if !hasReasonContaining(res.Reasons, "下限") {
		t.Errorf("应说明风险分被下限抬起，实得 %v", res.Reasons)
	}
}

// VPN Gate 自营机房是这里最特殊的一类：官方自己的服务器出口，
// 官方分数再高也是机房，必须认出来（免费源不知道 public-vpn-* 是什么）。
func TestMergeVpngateOwnNet(t *testing.T) {
	sig, err := newBuiltin().Lookup(context.Background(), Query{IP: "219.100.37.10", HostName: "public-vpn-153"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Type != model.TypeVpngateOwn {
		t.Fatalf("内置规则应认出自营机房，实得 %q", sig.Type)
	}
	res := Merge(Query{IP: "219.100.37.10", HostName: "public-vpn-153"}, []*Signals{sig,
		// 免费源只看到一个普通日本 IP：内置规则必须把它纠回来。
		{Name: "ipquery", OK: true, Type: model.TypeBusiness, Score: intp(20), ASN: "AS9371", Org: "SBC RS"},
	}, MergeOptions{})

	if res.IPType != model.TypeVpngateOwn {
		t.Errorf("类型 = %s，期望 vpngate-hosting", res.IPType)
	}
	if res.Score > 60 {
		t.Errorf("自营机房给 %d 分太高", res.Score)
	}
	if !hasReasonContaining(res.Reasons, "自营") {
		t.Errorf("应说明是自营机房，实得 %v", res.Reasons)
	}
	if IsCleanResidential(res) {
		t.Error("自营机房不该算志愿者家宽")
	}
}

// 只有一个免费源时，分数必须往中性值收，而不是给一个好看的 100。
func TestMergeShrinksTowardNeutralWhenEvidenceThin(t *testing.T) {
	res := Merge(Query{IP: "8.15.10.2"}, []*Signals{
		{Name: "ipquery", OK: true, Type: model.TypeResidential, Score: intp(0),
			Factors: model.PurityFactors{Datacenter: boolp(false)}},
	}, MergeOptions{})
	if res.Confidence >= 100 {
		t.Errorf("一个免费源就说到 100%% 可信度")
	}
	if res.Score >= 100 || res.Score <= 62 {
		t.Errorf("分数应被拉向中性值 62 但不至于变脏，实得 %d", res.Score)
	}
	if !hasReasonContaining(res.Reasons, "中性值") {
		t.Errorf("应说明证据不足导致收敛，实得 %v", res.Reasons)
	}
}

// 很多来源在「有没有机房」上弃权时，汇总不能自己编一个结论。
func TestMergeKeepsUnknownFactorsUnknown(t *testing.T) {
	res := Merge(Query{IP: "4.4.4.4"}, []*Signals{
		{Name: "ipinfo", OK: true},
		{Name: "abuseipdb", OK: true},
	}, MergeOptions{})
	for name, v := range map[string]*bool{
		"datacenter": res.Factors.Datacenter, "proxy": res.Factors.Proxy,
		"vpn": res.Factors.VPN, "tor": res.Factors.Tor, "mobile": res.Factors.Mobile,
	} {
		if v != nil {
			t.Errorf("%s 没人表态，汇总不该替它填 %v", name, *v)
		}
	}
	if res.IPType != model.TypeUnknown {
		t.Errorf("类型 = %s，期望 unknown", res.IPType)
	}
}

// 组织名里漏出的机房名是常见证据来源（很多来源不给类型字段）。
func TestMergeOrgKeywordEvidence(t *testing.T) {
	res := Merge(Query{IP: "138.201.1.1"}, []*Signals{
		{Name: "ipinfo", OK: true, Score: intp(15), ASN: "AS24940", Org: "Hetzner Online GmbH", ISP: "Hetzner"},
	}, MergeOptions{})
	if !orTrue(res.Factors.Datacenter) {
		t.Errorf("org 里含 hetzner 应抬机房，实得因子 %v", res.Factors.Datacenter)
	}
	if res.IPType != model.TypeHosting {
		t.Errorf("类型 = %s，期望 hosting", res.IPType)
	}
	if !hasReasonContaining(res.Reasons, "hetzner") {
		t.Errorf("理由里要写清楚是哪个关键词命中的，实得 %v", res.Reasons)
	}
}

// AbuseIPDB 的滥用置信分不是布尔因子，但要能兜住风险分。
func TestMergeAbuseScoreFloor(t *testing.T) {
	res := Merge(Query{IP: "203.0.113.66"}, []*Signals{
		{Name: "ipinfo", OK: true, Type: model.TypeBusiness, Score: intp(5)},
		{Name: "abuseipdb", OK: true, Factors: model.PurityFactors{AbuseScore: intp(75)}},
	}, MergeOptions{})
	if res.Factors.AbuseScore == nil || *res.Factors.AbuseScore != 75 {
		t.Errorf("滥用置信分应带出来，实得 %v", res.Factors.AbuseScore)
	}
	if res.Score > 55 {
		t.Errorf("置信分 75 的 IP 不该还有 %d 分", res.Score)
	}
}

func TestMergeNoSignalsAndAllFailed(t *testing.T) {
	empty := Merge(Query{IP: "1.1.1.1"}, nil, MergeOptions{})
	if empty.Score != 55 || empty.IPType != model.TypeUnknown {
		t.Errorf("没有任何来源时应给中性结论，实得 %+v", empty)
	}

	failed := Merge(Query{IP: "1.1.1.1"}, []*Signals{
		{Name: "ipquery", OK: false, Err: "429 Too Many Requests"},
		{Name: "ipinfo", OK: false, Err: "invalid access token"},
	}, MergeOptions{})
	if failed.Score != 55 {
		t.Errorf("全失败时不该给任何倾向性分数，实得 %d", failed.Score)
	}
	if len(failed.Providers) != 2 {
		t.Errorf("失败的来源也要列出来给界面看，实得 %d 条", len(failed.Providers))
	}
	if !hasReasonContaining(failed.Reasons, "失败") {
		t.Errorf("应说明是来源全挂了，实得 %v", failed.Reasons)
	}
	// 成功的排在前面，界面不用再排一次。
	for _, p := range failed.Providers {
		if p.OK {
			t.Error("这条本来就是失败")
		}
	}
}

// 原始响应要截断后留着：界面上要能核对「谁说了什么」，
// 但不能让一个来源的整页 JSON 把节点池撑爆。
func TestMergeTruncatesRaw(t *testing.T) {
	big := make([]byte, 5000)
	for i := range big {
		big[i] = 'x'
	}
	res := Merge(Query{IP: "1.1.1.1"}, []*Signals{
		{Name: "ipquery", OK: true, Raw: big, Score: intp(5)},
	}, MergeOptions{RawKeepBytes: 300})
	if len(res.Providers) != 1 {
		t.Fatal(res.Providers)
	}
	if got := len(res.Providers[0].Raw); got != 300 {
		t.Errorf("原始响应留了 %d 字节，期望裁到 300", got)
	}
}

// 元数据取「给得最全且权重最高」的那一份，别拿失败来源的空值。
func TestMergePicksBestMetadata(t *testing.T) {
	res := Merge(Query{IP: "1.1.1.1"}, []*Signals{
		{Name: "abuseipdb", OK: true, ASN: "AS6453", Org: "Tata"},
		{Name: "scamalytics", OK: true, ASN: "AS14061", Org: " Zhejiang Juhua ", Domain: "zhomeip.net", Country: "CN"},
	}, MergeOptions{})
	if res.ASN != "AS14061" {
		t.Errorf("ASN = %q，期望取权重更高、信息更全的 scamalytics", res.ASN)
	}
	if res.Country != "CN" {
		t.Errorf("国家 = %q", res.Country)
	}
}

/* ---------------- 内置规则 ---------------- */

func TestBuiltinHosting(t *testing.T) {
	cases := []struct {
		ip, host string
		want     bool
		why      string
	}{
		{"219.100.37.10", "public-vpn-153", true, "自营网段+主机名"},
		{"219.100.37.127", "vpn-someone", true, "光靠网段也够"},
		{"1.1.1.1", "public-vpn-9", true, "光靠 public-vpn-* 前缀也够"},
		{"13.32.1.1", "vpn123", true, "AWS 样本段"},
		{"104.233.64.1", "vpn123", true, "Vultr 样本段"},
		{"138.201.5.5", "vpn123", true, "Hetzner 样本段"},
		{"1.1.1.1", "vpn123", false, "没命中内置规则"},
		{"126.100.37.10", "vpn123", false, "隔壁网段不该连带命中"},
		{"::1", "vpn123", false, "IPv6 回环"},
		{"", "vpn123", false, "缺 IP"},
	}
	for _, c := range cases {
		got, why := BuiltinHosting(c.ip, c.host)
		if got != c.want {
			t.Errorf("BuiltinHosting(%s, %s) = %v（%s），期望 %v（%s）", c.ip, c.host, got, why, c.want, c.why)
		}
		if got && why == "" {
			t.Errorf("(%s,%s) 判成机房却没给依据", c.ip, c.host)
		}
	}
}

func TestBuiltinOwnNet(t *testing.T) {
	for _, h := range []string{"public-vpn-153", "PUBLIC_VPN-1", " public-vpn-2 "} {
		if !BuiltinOwnNet(h) {
			t.Errorf("%q 应认成自营", h)
		}
	}
	for _, h := range []string{"vpn100", "public-vpn", "mypublic-vpn-1"} {
		if BuiltinOwnNet(h) {
			t.Errorf("%q 不该认成自营", h)
		}
	}
}

func TestOrgKeywordSignals(t *testing.T) {
	hosting, residential := OrgKeywordSignals("AS24940", "Hetzner Online GmbH", "hetzner.com")
	if hosting != "hetzner" {
		t.Errorf("hostingHit = %q，期望 hetzner", hosting)
	}
	if residential != "" {
		t.Errorf("机房名优先，不该同时报家宽，实得 %q", residential)
	}

	hosting, residential = OrgKeywordSignals("AS4134", "China Telecom", "")
	if hosting != "" {
		t.Errorf("China Telecom 不该命中机房关键词（只有 chinatelecom global 才算国际出口），实得 %q", hosting)
	}
	if residential == "" {
		t.Error("运营商名应作为家宽的轻微加分")
	}

	// 关键词必须带边界：不然 "Webhosting" 这种公司名会被 "hosting" 误伤。
	if h, _ := OrgKeywordSignals("Webhosting Solutions Ltd"); h != "" {
		t.Errorf("边界不该命中嵌入词，实得 %q", h)
	}
	if h, _ := OrgKeywordSignals("Web Hosting Solutions"); h == "" {
		t.Error("独立出现的 hosting 应命中")
	}
	if h, r := OrgKeywordSignals(nil...); h != "" || r != "" {
		t.Errorf("空文本不该有结论: %q / %q", h, r)
	}
}

func TestIsCleanResidential(t *testing.T) {
	base := &model.PurityResult{IPType: model.TypeResidential}
	if !IsCleanResidential(base) {
		t.Error("residential 且无风险因子应算家宽")
	}
	if IsCleanResidential(&model.PurityResult{IPType: model.TypeHosting}) {
		t.Error("机房不算家宽")
	}
	if IsCleanResidential(&model.PurityResult{IPType: model.TypeResidential, Factors: model.PurityFactors{Datacenter: boolp(true)}}) {
		t.Error("被标成机房的 residential 不该算家宽")
	}
	if IsCleanResidential(&model.PurityResult{IPType: model.TypeResidential, Factors: model.PurityFactors{VPN: boolp(true)}}) {
		t.Error("VPN 出口不该算家宽")
	}
	if IsCleanResidential(nil) {
		t.Error("nil 结论不该算家宽")
	}
	// 移动网络/科研教育也算「不是机房」，用户关心的是会不会被风控。
	for _, tp := range []string{model.TypeMobile, model.TypeEducation, model.TypeGovernment, model.TypeBusiness} {
		if !IsCleanResidential(&model.PurityResult{IPType: tp}) {
			t.Errorf("%s 应算干净出口", tp)
		}
	}
}

func TestFactorLabelsAndWeightTable(t *testing.T) {
	labels := FactorLabels()
	if len(labels) == 0 {
		t.Fatal("界面要靠这张表渲染因子")
	}
	seen := map[string]bool{}
	for _, l := range labels {
		if l.Key == "" || l.Label == "" {
			t.Errorf("因子表里有空项: %+v", l)
		}
		if seen[l.Key] {
			t.Errorf("因子键重复: %s", l.Key)
		}
		seen[l.Key] = true
	}
	for _, key := range []string{"proxy", "vpn", "tor", "datacenter", "mobile", "abuser", "bot"} {
		if !seen[key] {
			t.Errorf("因子表缺 %s", key)
		}
	}
	if w := Weight("scamalytics"); w <= Weight("abuseipdb") {
		t.Errorf("专业风险源的权重应高于只反映举报历史的来源: %v vs %v", w, Weight("abuseipdb"))
	}
	if w := Weight("made-up"); w >= Weight("ipquery") {
		t.Errorf("不认识的来源不该比 ipquery 更有分量，实得 %v", w)
	}
}

func TestBoolOf(t *testing.T) {
	f := model.PurityFactors{Tor: boolp(true), Proxy: boolp(false)}
	if v := BoolOf(&f, "tor"); v == nil || !*v {
		t.Errorf("BoolOf(tor) = %v", v)
	}
	if v := BoolOf(&f, "proxy"); v == nil || *v {
		t.Errorf("BoolOf(proxy) = %v", v)
	}
	if v := BoolOf(&f, "datacenter"); v != nil {
		t.Errorf("没表态的因子必须是 nil，实得 %v", *v)
	}
	if v := BoolOf(&f, "不存在的键"); v != nil {
		t.Errorf("未知键应返回 nil，实得 %v", *v)
	}
	if v := BoolOf(nil, "tor"); v != nil {
		t.Error("nil 因子集应返回 nil")
	}
}

/* ---------------- Service：来源装配、缓存、限流 ---------------- */

// 只用内置规则时不该联网：一个 API key 都不配的部署也该能出结论。
func TestServiceBuiltinOnlyIsOffline(t *testing.T) {
	svc := New(config.PurityConfig{
		Enabled:      true,
		TTLHours:     24,
		Selection:    "all",
		Providers:    map[string]bool{"builtin": true, "ipquery": false, "ipinfo": false, "scamalytics": false, "abuseipdb": false, "ipregistry": false, "ipqualityscore": false},
		Keys:         map[string]string{"ipinfo": "should-be-ignored"},
		MinProviders: 1,
	}, t.TempDir())

	if got := svc.Enabled(); len(got) != 1 || got[0] != "builtin" {
		t.Fatalf("只该启用内置规则，实得 %v", got)
	}
	res, err := svc.Check(context.Background(), Query{IP: "219.100.37.10", HostName: "public-vpn-153"})
	if err != nil {
		t.Fatalf("内置规则检测失败: %v", err)
	}
	if res.IPType != model.TypeVpngateOwn {
		t.Errorf("类型 = %s", res.IPType)
	}
	if res.Confidence == 0 {
		t.Error("内置来源的结论也要带可信度")
	}
	if len(res.Providers) == 0 || !res.Providers[0].OK {
		t.Errorf("来源明细要能看到内置规则参与了: %+v", res.Providers)
	}
}

// 要 key 的来源只有配了 key 才启用 —— 否则每轮都会攒一堆 401，
// 界面上看起来像坏了。
func TestServiceNeedsKeyGate(t *testing.T) {
	noKeys := New(config.PurityConfig{Enabled: true, TTLHours: 24}, t.TempDir())
	enabled := strings.Join(noKeys.Enabled(), ",")
	for _, name := range []string{"builtin", "ipquery"} {
		if !strings.Contains(enabled, name) {
			t.Errorf("免费来源 %s 默认就该开，实得 %v", name, enabled)
		}
	}
	for _, name := range []string{"ipinfo", "scamalytics", "abuseipdb", "ipregistry", "ipqualityscore"} {
		if strings.Contains(enabled, name) {
			t.Errorf("没配 key 的 %s 不该被启用: %v", name, enabled)
		}
	}
	withKeys := New(config.PurityConfig{
		Enabled: true, TTLHours: 24,
		Keys: map[string]string{"ipinfo": "tok", "scamalytics": "key"},
	}, t.TempDir())
	got := strings.Join(withKeys.Enabled(), ",")
	if !strings.Contains(got, "ipinfo") || !strings.Contains(got, "scamalytics") {
		t.Errorf("配了 key 就该开: %v", got)
	}

	// 统计面板要如实反映「有没有 key、成功几次」，用户才知道该不该去配。
	st := noKeys.Stats()
	if len(st) == 0 {
		t.Fatal("没有来源统计")
	}
	for _, s := range st {
		if s.Name == "ipinfo" && (s.HasKey || s.Enabled) {
			t.Errorf("没 key 的来源不该被标成启用: %+v", s)
		}
		if s.Name == "ipinfo" && !s.NeedsKey {
			t.Error("ipinfo 应标成需要 key")
		}
	}
}

func TestServiceCachePersistsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	svc := New(config.PurityConfig{Enabled: true, TTLHours: 24, Providers: map[string]bool{"ipquery": false}}, dir)
	res, err := svc.Check(context.Background(), Query{IP: "45.76.1.1", HostName: "vpn123"})
	if err != nil {
		t.Fatal(err)
	}
	if got := svc.Cached("45.76.1.1"); got == nil || got.IP != res.IP {
		t.Error("查过的 IP 该进缓存")
	}
	if err := svc.Save(); err != nil {
		t.Fatalf("落盘失败: %v", err)
	}

	restarted := New(config.PurityConfig{Enabled: true, TTLHours: 24, Providers: map[string]bool{"ipquery": false}}, dir)
	if restarted.CacheSize() == 0 {
		t.Fatal("重启后缓存应读回来（纯净度结论比节点身份活得久）")
	}
	if got := restarted.Cached("45.76.1.1"); got == nil {
		t.Error("重启后应直接命中缓存，不必再花一次配额")
	}
}

// 过期的结论不能用：IP 会被运营商回收再分配，昨天的机房今天可能是家宽。
func TestServiceCacheExpiry(t *testing.T) {
	svc := New(config.PurityConfig{Enabled: true, TTLHours: 1, Providers: map[string]bool{"ipquery": false}}, t.TempDir())
	stale := &model.PurityResult{
		IP: "8.8.8.8", CheckedAt: time.Now().Add(-10 * time.Hour), Score: 12,
		Level: model.PurityBad, IPType: model.TypeHosting, TTLHours: 1, Providers: []model.ProviderVerdict{},
	}
	svc.Put(stale)
	if got := svc.Cached("8.8.8.8"); got != nil {
		t.Errorf("过期结论不该再用，实得 %+v", got)
	}

	fresh := &model.PurityResult{IP: "9.9.9.9", CheckedAt: time.Now(), Score: 90, Level: model.PurityGood, IPType: model.TypeResidential, TTLHours: 24}
	svc.Put(fresh)
	if got := svc.Cached("9.9.9.9"); got == nil || got.Score != 90 {
		t.Errorf("有效期内的结论要用缓存: %+v", got)
	}
}

func TestServiceCheckIPsBatch(t *testing.T) {
	svc := New(config.PurityConfig{
		Enabled:           true,
		TTLHours:          24,
		Concurrency:       2,
		RequestsPerMinute: 600,
		Providers:         map[string]bool{"builtin": true, "ipquery": false},
	}, t.TempDir())

	qs := []Query{
		{IP: "219.100.37.10", HostName: "public-vpn-153"},
		{IP: "13.32.1.1", HostName: "vpnA"},
		{IP: "1.1.1.1", HostName: "vpnB"},
		{IP: "1.1.1.1", HostName: "vpnB-dup"}, // 同 IP 不同 hostname：这一层不去重，缓存只占一条
	}
	// onResult / onProgress 是在查询线程里被调的（接口注释写明了），
	// 测试自己得加锁 —— 跟 store 那边加锁写回是同一种写法。
	var mu sync.Mutex
	var results int
	var maxDone, maxTotal, maxOK, maxFail int
	var seenLast string
	ok, fail := svc.CheckIPs(context.Background(), qs, 2,
		func(q Query, r *model.PurityResult, err error) {
			mu.Lock()
			results++
			mu.Unlock()
			if err != nil || r == nil {
				t.Errorf("%s 查询失败: %v", q.IP, err)
			}
		},
		func(done, total, okCount, failCount int, last string) {
			mu.Lock()
			defer mu.Unlock()
			if done >= maxDone {
				maxDone, maxTotal, maxOK, maxFail, seenLast = done, total, okCount, failCount, last
			}
		})
	// 去重是调用方（app 的纯净度任务按 IP 汇总）的职责，这一层只按 Query 跑：
	// 同一 IP 不同 hostname 在内置规则里结论可能不同，不能在这层拍扁。
	if ok != 4 || fail != 0 {
		t.Errorf("ok/fail = %d/%d，期望 4/0", ok, fail)
	}
	if results != 4 {
		t.Errorf("onResult 调了 %d 次，期望 4", results)
	}
	if maxDone != 4 || maxTotal != 4 {
		t.Errorf("进度回调里最大的一条 = %d/%d，期望 4/4", maxDone, maxTotal)
	}
	if maxOK != 4 || maxFail != 0 {
		t.Errorf("进度回调里的成功/失败数 = %d/%d，期望 4/0", maxOK, maxFail)
	}
	if seenLast == "" {
		t.Error("进度回调要带上刚查完的 IP，界面才好显示「正在查 xxx」")
	}
	if svc.CacheSize() != 3 {
		t.Errorf("缓存 %d 条，期望 3（缓存按 IP，同 IP 只占一条）", svc.CacheSize())
	}
	// 已缓存的 IP 不该再花一次配额。
	if got := svc.Cached("219.100.37.10"); got == nil || got.IPType != model.TypeVpngateOwn {
		t.Errorf("查过的 IP 要能直接命中缓存: %+v", got)
	}
}

func TestServiceCancelRespectsContext(t *testing.T) {
	svc := New(config.PurityConfig{Enabled: false, TTLHours: 24, Providers: map[string]bool{"ipquery": false}}, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := svc.Check(ctx, Query{IP: "1.1.1.1", HostName: "x"})
	if err == nil && res == nil {
		t.Error("取消时要么报错要么有结论，不该两个都没有")
	}
}

func TestServiceStatsJSONShape(t *testing.T) {
	// 界面按这张表渲染来源健康，字段名一旦漂了前端就静默显示空。
	svc := New(config.PurityConfig{Enabled: true, TTLHours: 24, Providers: map[string]bool{"ipquery": false}}, t.TempDir())
	b, err := json.Marshal(svc.Stats())
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"name", "enabled", "needs_key", "has_key", "ok", "failed"} {
		if _, missing := rows[0][want]; !missing {
			t.Errorf("来源统计缺少字段 %s: %s", want, b)
		}
	}
}

func hasReasonContaining(rs []string, sub string) bool {
	for _, r := range rs {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

// 只有 builtin（弃权）+ ipquery（免费响应没有类型字段）时，家宽只能从 ASN 推。
// 这条规则是「家宽占比 0.2%」的直接修复：不推导就永远是「类型未知」。
func TestMergeDerivesResidentialFromConsumerASN(t *testing.T) {
	res := Merge(Query{IP: "221.164.89.213", HostName: "vpn615343043"}, []*Signals{
		{Name: "builtin", OK: true, Tags: []string{"no-internal-rule"}},
		{Name: "ipquery", OK: true, ASN: "AS4766", Org: "Korea Telecom", ISP: "Korea Telecom",
			Factors: model.PurityFactors{
				Datacenter: boolp(false), Proxy: boolp(false), VPN: boolp(false),
				Tor: boolp(false), Mobile: boolp(false),
			}},
	}, MergeOptions{})

	if res.IPType != model.TypeResidential {
		t.Errorf("类型 = %s，期望 residential（AS4766 是韩国电信家庭宽带）", res.IPType)
	}
	if res.TypeSource != "derived:asn:AS4766" {
		t.Errorf("TypeSource = %q，期望 derived:asn:AS4766（界面要靠它区分来源认定和推导）", res.TypeSource)
	}
	if !IsCleanResidential(res) {
		t.Error("推导出的家宽应当被 IsCleanResidential 接受，否则节点上的 residential 还是 false")
	}
	if !strings.Contains(strings.Join(res.Reasons, "\n"), "消费级宽带运营商") {
		t.Errorf("理由里没写推导依据: %v", res.Reasons)
	}
}

// 只有运营商名、没 ASN：也算家宽，但依据标成 derived:isp: 并且置信度扣一档。
func TestMergeDerivesResidentialFromISPKeyword(t *testing.T) {
	res := Merge(Query{IP: "1.1.1.1", HostName: "vpn1"}, []*Signals{
		{Name: "builtin", OK: true, Tags: []string{"no-internal-rule"}},
		{Name: "ipquery", OK: true, Org: "Chubu Telecommunications Company, Inc.",
			Factors: model.PurityFactors{Datacenter: boolp(false), Proxy: boolp(false), VPN: boolp(false)}},
	}, MergeOptions{})

	if res.IPType != model.TypeResidential {
		t.Errorf("类型 = %s，期望 residential", res.IPType)
	}
	if !strings.HasPrefix(res.TypeSource, "derived:isp:") {
		t.Errorf("TypeSource = %q，期望 derived:isp: 开头", res.TypeSource)
	}
	if !strings.Contains(strings.Join(res.Reasons, "\n"), "置信度扣 12") {
		t.Errorf("只有名字线索时该扣置信度并说明: %v", res.Reasons)
	}
}

// 三种「不该推」的情况：有机房证据、名字像政企、来源已经给了类型。
// 推导必须输给这些，否则等于把政企专线和机房 IP 叫成家宽。
func TestMergeDoesNotDeriveResidential(t *testing.T) {
	t.Run("机房因子成立就不推", func(t *testing.T) {
		res := Merge(Query{IP: "8.8.8.8"}, []*Signals{
			{Name: "ipquery", OK: true, ASN: "AS4766",
				Factors: model.PurityFactors{Datacenter: boolp(true)}},
		}, MergeOptions{})
		if res.IPType == model.TypeResidential {
			t.Errorf("明确说了机房还推成家宽: %s", res.IPType)
		}
		if res.TypeSource != "factor-vote" {
			t.Errorf("TypeSource = %q，期望 factor-vote", res.TypeSource)
		}
	})
	t.Run("政企名字不推", func(t *testing.T) {
		res := Merge(Query{IP: "9.9.9.9"}, []*Signals{
			{Name: "ipquery", OK: true, Org: "NTT DOCOMO BUSINESS,Inc.",
				Factors: model.PurityFactors{Datacenter: boolp(false)}},
		}, MergeOptions{})
		if res.IPType != model.TypeUnknown {
			t.Errorf("类型 = %s，期望 unknown（BUSINESS 是政企，别猜）", res.IPType)
		}
		if res.TypeSource != "" {
			t.Errorf("TypeSource = %q，期望空", res.TypeSource)
		}
	})
	t.Run("来源给了类型就以来源为准", func(t *testing.T) {
		res := Merge(Query{IP: "2.2.2.2"}, []*Signals{
			{Name: "ipinfo", OK: true, Type: model.TypeBusiness, ASN: "AS4766"},
		}, MergeOptions{})
		if res.IPType != model.TypeBusiness {
			t.Errorf("类型 = %s，期望 business（来源说了话，推导不得覆盖）", res.IPType)
		}
		if res.TypeSource != "ipinfo" {
			t.Errorf("TypeSource = %q，期望来源名 ipinfo", res.TypeSource)
		}
	})
}

func TestCanonicalASN(t *testing.T) {
	for in, want := range map[string]string{
		"AS4766":        "AS4766",
		"4766":          "AS4766",
		"as17676":       "AS17676",
		"AS2516 (KDDI)": "AS2516",
		"":              "",
		"unknown":       "",
	} {
		if got := canonicalASN(in); got != want {
			t.Errorf("canonicalASN(%q) = %q，期望 %q", in, got, want)
		}
	}
}
