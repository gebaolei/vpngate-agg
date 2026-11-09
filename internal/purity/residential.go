package purity

import (
	"regexp"
	"strings"

	"github.com/gebaolei/vpngate-agg/internal/model"
)

// 家宽推导。
//
// 先把实测事实摆清楚：官方名单里**没有**家宽标识。主站、`?output=1`、官方镜像站
// 返回的都是同 15 列（HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,
// NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,
// OpenVPN_ConfigData_Base64），英/中/日三版网页列表里也搜不到 Residential/住宅。
// 官方唯一带的类型标识是 public-vpn-* 前缀（自营机房，反向证据）。
//
// 免费来源也不给类型：ipquery 的免费响应只有 isp{asn,org,isp} + location + risk
// 那组布尔，没有 type 字段。所以「是不是家宽」只能从 **ASN 和运营商名** 推。
//
// 规则很克制，三条硬约束：
//  1. 有机房 / 代理 / VPN / Tor 任一证据就不推（宁缺毋滥）；
//  2. 来源只要给了类型就以来源为准，推导绝不覆盖来源；
//  3. 推导只填类型，不动纯净度分数，也不涨置信度 —— 「没被情报标记过」不等于「干净」。
//
// 依据会写进 TypeSource（derived:asn:AS4766 / derived:isp:telecom），界面据此把
// 「家宽（来源认定）」和「家宽（推导）」分开显示，不会把推导冒充成权威结论。

// consumerASNs 是我确信以消费级固网/移动宽带为主的 ASN。只收有把握的：
// 表里写错一个 ASN 会把整段政企线路标成家宽，所以宁可留给关键词那档。
// 值是给界面看的依据文案。
var consumerASNs = map[string]string{
	"AS4766":  "Korea Telecom（韩国电信固网）",
	"AS9318":  "SK Broadband",
	"AS9685":  "LG Uplus",
	"AS17676": "SoftBank（软银光回线）",
	"AS2516":  "KDDI / OCN",
	"AS3462":  "HINET（中华电信固网）",
	"AS20485": "Rostelecom",
	"AS8359":  "MTS",
	"AS12389": "Corbina",
	"AS4134":  "ChinaNet（中国电信家庭宽带）",
	"AS4837":  "China169（中国联通）",
	"AS9808":  "China Mobile（中国移动）",
	"AS3320":  "Deutsche Telekom",
	"AS3329":  "Vodafone Deutschland",
	"AS6849":  "Telekom Austria",
	"AS3269":  "Telecom Italia",
	"AS30722": "Fastweb",
	"AS1221":  "Telstra",
	"AS7545":  "Optus",
	"AS7922":  "Comcast / Xfinity",
	"AS20115": "Charter / Spectrum",
	"AS28573": "Claro（巴西）",
	"AS8151":  "Telmex / Telcel",
	"AS9299":  "PLDT / Smart",
	"AS9605":  "Globe Telecom",
}

// consumerISPKeywords 是「名字里就带着面向家庭用户的业务」的线索。
// 命中只给低置信：运营商的政企专线和家宽用的是同一个品牌名。
var consumerISPKeywords = []string{
	"telecom", "telecommunications", "telefonica", "vodafone", "orange",
	"telekom", "telenor", "telia", "elisa", "dna", "proximus", "mobilis",
	"bell canada", "rogers", "telstra", "optus", "kddi", "softbank", "docomo",
	"ntt east", "hinet", "chunghwa", "rostelecom", "corbina", "ais fibre",
	"true online", "3bb", "maxis", "unifi", "airtel", "jio", "bsnl",
	"comcast", "charter", "cox", "optimum", "centurylink", "frontier",
	"fastweb", "movistar", "claro", "telmex", "pldt", "globe",
	"j:com", "jcom", "powercomm", "biglobe", "so-net", "nifty", "plala",
	"broadband", "fibre", "fiber", "sony network", "sky broadband",
	"liberty broadband", "wow internet", "ee ltd", "three uk", "digicel",
}

// enterpriseHints 是「这名字明显不是家庭用户」的线索：政企、上流 transit、
// 机房、学校、政府。命中就不推导，留在「类型未知」，比猜错诚实。
var enterpriseHints = []string{
	"business", "enterprise", "backbone", "transit", "wholesale",
	"hosting", "hoster", "data center", "datacenter", "cloud",
	"government", "municipal", "city of", "university", "institute", "college",
	"polytechnic", "school", "research", "academy", "hospital", "ministry",
	"railway", "power company", "bank", "insurance", "airline", "airport",
	"military", "defense", "defence",
}

// reAsn 从各来源给的 ASN 文本里抠出「AS+数字」。上游格式不统一：
// ipquery 给 "AS4766"，别家可能只给 "4766"、或者 "AS4766 (Korea Telecom)"。
var reAsn = regexp.MustCompile(`(?i)\b(?:as)?\s*([0-9]{1,7})\b`)

// canonicalASN 把 ASN 文本规范成 "AS4766"；认不出来返回 ""。
func canonicalASN(text string) string {
	m := reAsn.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil {
		return ""
	}
	return "AS" + m[1]
}

// deriveResidential 决定要不要把这个 IP 推成家宽。
//
// 返回值是依据标记（"" 表示不推）：
//
//	derived:asn:AS4766   高置信：ASN 就在消费级宽带表里
//	derived:isp:telecom  低置信：只有运营商名线索
func deriveResidential(q Query, valid []*Signals, fac model.PurityFactors) string {
	// 1) 任何反证都直接放弃。注意 fac 里 false 和 nil 是分开的：只有明确 true 才算反证。
	if orTrue(fac.Datacenter) || orTrue(fac.Proxy) || orTrue(fac.VPN) || orTrue(fac.Tor) {
		return ""
	}
	// 2) 来源给了类型就不轮到我们。
	for _, s := range valid {
		if s.Type != "" && s.Type != model.TypeUnknown && s.Type != model.TypeVpngateOwn {
			return ""
		}
	}
	// 3) 文本证据：组织名 / ISP 名 / 域名 / 用途说明。
	var parts []string
	for _, s := range valid {
		parts = append(parts, s.Org, s.ISP, s.Domain, s.Usage)
	}
	if h := strings.TrimSpace(q.HostName); h != "" {
		parts = append(parts, h)
	}
	text := strings.ToLower(strings.Join(parts, " | "))

	// 4) 政企/机房/学校/政府名字一票否决：这类 IP 挂 VPN Gate 的不少，
	//    把它们叫「家宽」比叫「未知」错得更离谱。
	if hit := firstKeyword(text, enterpriseHints); hit != "" {
		return ""
	}

	// 5) ASN 表优先：这是能拿到的最强证据。
	for _, s := range valid {
		asn := canonicalASN(s.ASN)
		if asn == "" {
			continue
		}
		if _, ok := consumerASNs[asn]; ok {
			return "derived:asn:" + asn
		}
	}
	if kw := firstKeyword(text, consumerISPKeywords); kw != "" {
		return "derived:isp:" + kw
	}
	return ""
}

// residentialBasisText 把依据标记翻成界面上能看懂的一句话（进 Reasons）。
func residentialBasisText(basis string) string {
	switch {
	case strings.HasPrefix(basis, "derived:asn:"):
		asn := strings.TrimPrefix(basis, "derived:asn:")
		name := consumerASNs[asn]
		if name == "" {
			name = "消费级宽带运营商"
		}
		return "类型推导：" + asn + " 是消费级宽带运营商（" + name + "），且没有任何机房 / 代理 / VPN / Tor 证据"
	case strings.HasPrefix(basis, "derived:isp:"):
		kw := strings.TrimPrefix(basis, "derived:isp:")
		return "类型推导：运营商名含「" + kw + "」且没有任何机房 / 代理 / VPN / Tor 证据（低置信：政企专线也用同一个品牌名）"
	}
	return ""
}

// firstKeyword 返回第一个以带边界形式命中的关键词。
func firstKeyword(text string, kws []string) string {
	for _, kw := range kws {
		k := strings.TrimSpace(strings.ToLower(kw))
		if k == "" {
			continue
		}
		if keywordHit(text, k) {
			return k
		}
	}
	return ""
}
