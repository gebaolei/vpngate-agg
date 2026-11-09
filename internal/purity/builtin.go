package purity

import (
	"context"
	"net"
	"net/http"
	"regexp"
	"strings"

	"github.com/gebaolei/vpngate-agg/internal/model"
)

// builtinProvider 是不联网的内置规则源。
//
// 它的价值有两种：
//  1. 一个外部 key 都不配的时候，至少还能认出 VPN Gate 自营机房和大机房段，
//     界面不会出现「什么都没测出来」；
//  2. 它给的结论永远参与投票，用来纠偏免费源对自家场景的误判
//     （免费源不知道 public-vpn-* 是什么）。
type builtinProvider struct {
	ownNets   []*net.IPNet
	cloudNets []cloudNet
}

type cloudNet struct {
	Org  string
	Net  *net.IPNet
	Kind string // hosting | cdn
}

// vpngateOwnNets 是 VPN Gate 自营服务器所在的网段（学术网络机房）。
// 实测 public-vpn-* 全在 219.100.37.0/24；这一条是最硬的家宽判据。
var vpngateOwnNets = []string{
	"219.100.37.0/24",
}

// knownCloudNets 是主要云厂商的样本网段。
//
// 说清楚：这是样本，不是完整 BGP 表。厂商的地址块上千条，内置全表会让二进制
// 胖几十 MB 还得每月更新。它的定位是「免费源都没配额了的时候仍能认出常见机房」，
// 真正的权威结论靠带 ASN 的来源（ipquery/ipregistry/scamalytics）。
var knownCloudNets = []string{
	// AWS
	"3.0.0.0/8", "13.32.0.0/13", "18.0.0.0/8", "34.192.0.0/10", "35.156.0.0/13",
	"52.94.0.0/16", "54.64.0.0/12", "99.80.0.0/15", "108.175.32.0/21",
	// Google Cloud / GCP
	"34.64.0.0/10", "35.184.0.0/13", "104.154.0.0/15", "130.211.0.0/16",
	// Microsoft Azure
	"13.64.0.0/11", "20.36.0.0/14", "20.200.0.0/13", "40.64.0.0/10", "51.140.0.0/15",
	// DigitalOcean
	"64.23.160.0/20", "68.183.0.0/16", "104.131.0.0/16", "128.199.0.0/16", "134.209.0.0/16",
	// Vultr / Choopa
	"14.102.16.0/22", "23.80.0.0/12", "45.32.0.0/16", "45.76.0.0/16", "64.29.16.0/20",
	"104.233.64.0/18", "108.61.112.0/21", "136.144.32.0/20", "155.138.128.0/17",
	// Linode / Akamai
	"50.116.0.0/16", "66.175.192.0/18", "69.164.192.0/18", "72.14.176.0/21",
	"139.162.0.0/16", "172.104.0.0/13", "172.232.0.0/13",
	// Hetzner
	"5.9.0.0/16", "91.198.15.0/24", "138.201.0.0/16", "142.134.0.0/17", "213.133.96.0/19",
	// OVH
	"5.135.0.0/16", "5.196.0.0/14", "37.59.0.0/16", "94.23.0.0/16", "144.76.0.0/16",
	"162.197.0.0/16", "176.31.192.0/18", "213.32.48.0/20",
	// Oracle / Blue Spotlight
	"129.144.0.0/16", "129.159.0.0/16", "130.35.0.0/16", "132.226.0.0/15", "134.209.0.0/16",
	// Alibaba Cloud
	"47.74.0.0/15", "47.88.0.0/14", "8.128.0.0/15", "8.140.0.0/15", "147.139.0.0/16",
	// Cloudflare（WARP 出口/数据中心）
	"104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "188.114.96.0/20", "198.41.128.0/17",
	// 其他常见机房
	"23.80.0.0/12", "104.28.20.0/22", "198.18.0.0/15",
}

// hostingOrgKeywords 是「看运营商/组织名就知道是机房」的关键词表。
// score.go 拿它去扫所有来源给的 org/isp/domain，因为很多来源不给类型字段
// 但会把 "Vultr Holdings"、"Hetzner Online GmbH" 这样的名字漏在 org 里。
var hostingOrgKeywords = []string{
	"amazon", "amazonaws", "google llc", "google cloud", "microsoft", "azure",
	"alibaba", "aliyun", "oracle", "blue spotlight", "digitalocean", "vultr",
	"choopa", "linode", "akamai", "hetzner", "ovh", "ionos", "1&1", "godaddy",
	"plusserver", "scaleway", "upcloud", "brightcove", "fastly", "cloudflare",
	"buyvm", "ramnode", "webfaction", "hostinger", "contabo", "serverhunter",
	"psychz", "bandwidth", "navegante", "myrhost", "lightwire", "volume8",
	"datacenter", "data center", "colocation", "hosting", "hoster", "web host",
	"servers llc", "cloud provider", "cloudflare warp", "proxyz", "nsfnet",
	"zhuoxi", "chinatelecom global", "china unicom global",
}

// residentialOrgKeywords 是「看着就像真家宽/运营商」的名字。
// 只在没有任何机房证据时用来轻微加分，不当硬结论 ——
// 运营商的政企专线也叫这个名字。
var residentialOrgKeywords = []string{
	"telecom", "telefonica", "vodafone", "bb tech", "telstra", "optus",
	"ntt", "kddi", "softbank", "pldt", "globe", "ais ", "true online",
	"china telecom", "china mobile", "china unicom", "j:com", "au one",
	"rogers", "bell canada", " Shaw ", "comcast", "charter", "cox", "optimum",
	"sky broadband", "bt group", "orange s.a.", "deutsche telekom", "t-mobile",
	"ee ltd", "three uk", "telia", "elisa", "proximus", "mobilis", "digicel",
	"university", "institute", "college", "polytechnic", "lab",
}

func newBuiltin() *builtinProvider {
	b := &builtinProvider{}
	for _, cidr := range vpngateOwnNets {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			b.ownNets = append(b.ownNets, n)
		}
	}
	for _, cidr := range knownCloudNets {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		b.cloudNets = append(b.cloudNets, cloudNet{Net: n, Org: "已知云机房段 " + cidr, Kind: "hosting"})
	}
	return b
}

func (b *builtinProvider) Name() string   { return "builtin" }
func (b *builtinProvider) NeedsKey() bool { return false }

// Lookup 只做本地判断，不联网。
func (b *builtinProvider) Lookup(ctx context.Context, q Query, h *http.Client) (*Signals, error) {
	s := &Signals{Name: b.Name(), OK: true, Weight: Weight(b.Name())}
	ip := net.ParseIP(q.IP)
	host := strings.ToLower(strings.TrimSpace(q.HostName))

	// 1) VPN Gate 自营机房：hostname 前缀或自营网段。
	own := false
	if strings.HasPrefix(host, "public-vpn-") || strings.HasPrefix(host, "public_vpn-") {
		own = true
		s.Tags = append(s.Tags, "hostname:public-vpn-*")
	}
	if ip != nil {
		for _, n := range b.ownNets {
			if n.Contains(ip) {
				own = true
				s.Tags = append(s.Tags, "cidr:"+n.String())
				break
			}
		}
	}
	if own {
		s.Type = model.TypeVpngateOwn
		s.Usage = "VPN Gate 自营机房（SoftEther 官方服务器，学术网络出口）"
		mergeTrue(&s.Factors.Datacenter, true)
		v := 82
		s.Score = &v
		s.ScoreName = "vpngate_own"
		s.Org = "VPN Gate / SoftEther (University of Tokyo)"
		return s, nil
	}

	// 2) 常见云机房段。
	if ip != nil {
		for _, c := range b.cloudNets {
			if c.Net.Contains(ip) {
				s.Type = model.TypeHosting
				s.Org = c.Org
				mergeTrue(&s.Factors.Datacenter, true)
				v := 72
				s.Score = &v
				s.ScoreName = "known_cloud_cidr"
				s.Tags = append(s.Tags, "cidr:"+c.Net.String())
				return s, nil
			}
		}
	}

	// 3) 什么都没有：给一个「无结论」的有效响应（OK 但不带因子），
	//    让汇总知道这一票是弃权而不是「干净」。
	s.Type = ""
	s.Tags = append(s.Tags, "no-internal-rule")
	return s, nil
}

// BuiltinHosting 不联网就能定下的硬结论：true = 确定是机房/自营。
//
// 第二个返回值是依据（给界面用）。false 不是「家宽证明」，只是内置规则
// 没命中 —— 家宽要靠外部来源的证据，内置规则只能认反面。
func BuiltinHosting(ip, hostname string) (bool, string) {
	sig, err := newBuiltin().Lookup(context.Background(), Query{IP: ip, HostName: hostname}, nil)
	if err != nil || sig == nil {
		return false, ""
	}
	if sig.Type == model.TypeVpngateOwn {
		return true, "VPN Gate 自营机房（" + strings.Join(sig.Tags, " ") + "）"
	}
	if orTrue(sig.Factors.Datacenter) {
		return true, "命中已知云机房段（" + strings.Join(sig.Tags, " ") + "）"
	}
	return false, ""
}

// BuiltinOwnNet 只回答「是不是 VPN Gate 自营」。用于导出过滤等轻场景。
func BuiltinOwnNet(hostname string) bool {
	h := strings.ToLower(strings.TrimSpace(hostname))
	return strings.HasPrefix(h, "public-vpn-") || strings.HasPrefix(h, "public_vpn-")
}

// reOrgBoundary 用来要求关键词前后是分隔符，避免 "a1amazonx" 这种误命中，
// 也避免 "Shaw " 这种带空格的名字匹配不上。
var reOrgBoundary = regexp.MustCompile(`[\s,._\-()']`)

// OrgKeywordSignals 把「运营商/组织名」文本变成结构化证据。
//
// 单独导出是为了给界面显示理由用：用户点开通净度详情，要能看到
// 「ipregistry 给的 org 里含 hetzner」这种具体依据，而不是只看到
// 「判定：机房」四个字。
func OrgKeywordSignals(texts ...string) (hostingHit, residentialHit string) {
	joined := strings.ToLower(strings.Join(texts, " | "))
	if joined == "" {
		return "", ""
	}
	for _, kw := range hostingOrgKeywords {
		k := strings.ToLower(strings.TrimSpace(kw))
		if k == "" {
			continue
		}
		if keywordHit(joined, k) {
			hostingHit = strings.TrimSpace(kw)
			break
		}
	}
	for _, kw := range residentialOrgKeywords {
		k := strings.ToLower(strings.TrimSpace(kw))
		if k == "" {
			continue
		}
		if keywordHit(joined, k) {
			residentialHit = strings.TrimSpace(kw)
			break
		}
	}
	return hostingHit, residentialHit
}

// keywordHit 要求关键词以「整词或带边界」的形式出现。
func keywordHit(hay, needle string) bool {
	from := 0
	for {
		i := strings.Index(hay[from:], needle)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(needle)
		lowerOK := i == 0 || reOrgBoundary.MatchString(hay[i-1:i])
		upperOK := end >= len(hay) || reOrgBoundary.MatchString(hay[end:end+1])
		if lowerOK && upperOK {
			return true
		}
		from = i + 1
		if from >= len(hay) {
			return false
		}
	}
}
