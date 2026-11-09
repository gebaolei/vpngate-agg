// Package purity 做 IP 纯净度检测。
//
// 设计参照 xykt/IPQuality 的思路：不迷信单一来源，而是把多个来源的
// 「风险因子」（Proxy / VPN / Tor / 机房 / 滥用 / 爬虫）和「风险分」并起来看，
// 再给一个可解释的结论。界面必须能看到每个来源分别说了什么 —— 免费源之间
// 是会互相矛盾的，只给一个总分就变成玄学。
//
// 对 VPN Gate 这个场景，纯净度直接决定节点的价值：
//   - 志愿者家宽（residential）：出口干净，能过大多数风控
//   - VPN Gate 自营机房（219.100.37.0/24、public-vpn-*）：本质是数据中心出口，
//     官方分数再高也是机房
//   - 云机房 / Tor / 公开代理：容易被目标站标记
package purity

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/model"
)

// Query 是一次检测的输入。
type Query struct {
	IP       string
	HostName string // 节点名，内置规则要用（public-vpn-* 是自营机房）
	Force    bool   // 忽略缓存重查
}

// Signals 是单个来源给出的原始结论。
//
// 字段用指针的都用指针：区分「这个来源没给」和「这个来源明确说不是」。
// Score 已经归一到 0-100 的风险分（各来源原生量纲不同，换算在各自 provider 里做）。
type Signals struct {
	Name      string
	OK        bool
	Err       string
	MS        int64
	Score     *int
	ScoreName string
	Type      string
	Factors   model.PurityFactors
	ASN       string
	Org       string
	ISP       string
	Domain    string
	Usage     string
	Country   string
	Tags      []string // 来源自己的标签，如 vps / hosting / tor_exit / scanner
	Raw       []byte
	// Weight 是该来源在汇总里的权重；provider 自己填，score 只做加权。
	Weight float64
}

// Provider 是一个纯净度数据来源。
type Provider interface {
	// Name 是稳定标识，出现在配置、缓存和界面里。
	Name() string
	// NeedsKey 为 true 时没配 key 就不会被启用。
	NeedsKey() bool
	// Lookup 查一个 IP。实现方不需要自己做限流，Service 统一管。
	Lookup(ctx context.Context, q Query, h *http.Client) (*Signals, error)
}

// 权重：来源结论在汇总里的分量。
//
// 为什么不是「谁都能一票否决」：ipinfo 会把 VPS 标成 vpn，ipquery 会把整个
// 云段标成 datacenter，AbuseIPDB 只反映举报历史 —— 这些不是同一件事。
// 所以机房类结论要靠多来源共识，AbuseIPDB 只在「有明确滥用记录」时加重。
var weights = map[string]float64{
	"builtin":        1.0,
	"ipquery":        1.0,
	"ipregistry":     1.15,
	"scamalytics":    1.2,
	"ipqualityscore": 1.2,
	"ipinfo":         1.0,
	"abuseipdb":      0.85,
}

// Weight 返回来源权重；未知来源给 0.8，别让它一家独大。
func Weight(name string) float64 {
	if w, ok := weights[name]; ok {
		return w
	}
	return 0.8
}

// factorLabels 是风险因子的展示顺序与中文名（界面按这个顺序渲染因子表）。
var factorLabels = []struct{ Key, Label string }{
	{"proxy", "公开代理"},
	{"vpn", "VPN 出口"},
	{"tor", "Tor 出口"},
	{"datacenter", "数据中心"},
	{"mobile", "移动网络"},
	{"abuser", "滥用记录"},
	{"bot", "爬虫/扫描"},
}

// FactorLabels 给界面用。
func FactorLabels() []struct{ Key, Label string } { return factorLabels }

// BoolOf 从因子结构里取一个指针字段，供汇总和界面复用。
// f 为 nil 时给 nil（「没表态」），调用方常常拿着没测过的节点过来。
func BoolOf(f *model.PurityFactors, key string) *bool {
	if f == nil {
		return nil
	}
	switch strings.ToLower(key) {
	case "proxy":
		return f.Proxy
	case "vpn":
		return f.VPN
	case "tor":
		return f.Tor
	case "datacenter", "server":
		return f.Datacenter
	case "mobile":
		return f.Mobile
	case "abuser":
		return f.Abuser
	case "bot", "robot":
		return f.Bot
	}
	return nil
}

// boolOf 是包内别名，省得每处写大写。
func boolOf(f *model.PurityFactors, key string) *bool { return BoolOf(f, key) }

// clampInt 把任意来源的分数压到 0-100。
func clampInt(v int) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// ptrInt 便捷取指针（字面量没法直接取址）。
func ptrInt(v int) *int { return &v }

// mergeTrue 记录一次表态：true 直接置位；false 只在还没表过时写，
// 免得后到的弱来源把前面的明确结论抹掉（false 的权重投票在 score.go 里做）。
func mergeTrue(dst **bool, v bool) {
	if v {
		b := true
		*dst = &b
		return
	}
	if *dst == nil {
		b := false
		*dst = &b
	}
}

// truncRaw 保留原始响应的前若干字节给界面核对。免费源的响应可能很大，
// 全存会把缓存文件撑爆。
func truncRaw(b []byte, keep int) []byte {
	if keep <= 0 {
		return nil
	}
	if len(b) <= keep {
		return b
	}
	out := make([]byte, keep)
	copy(out, b)
	return out
}

// providerTimeout 是单个来源的超时。免费源偶尔会挂 20 秒，
// 一个来源挂死不能把整次检测拖满。
const providerTimeout = 8 * time.Second

// nowUTC 是当前 UTC 时间。所有落盘与展示的时间都用 UTC，
// 界面上的「N 分钟前」由前端按浏览器时区换算。
func nowUTC() time.Time { return time.Now().UTC() }

// firstNonEmpty 返回第一个非空字符串。
func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return strings.TrimSpace(x)
		}
	}
	return ""
}
