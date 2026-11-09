package source

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/gebaolei/vpngate-agg/internal/model"
)

// FillFromConfig 从 .ovpn 正文里抽出连接参数、证书情况和厂商指纹。
//
// 只解析、不执行指令：OpenVPN 的指令语义很宽（--config 里能挂脚本），
// 我们只关心「客户端要往哪连」，绝不尝试理解 exec 之类会落地的东西。
func FillFromConfig(n *model.Node, cfg []byte) {
	text := string(cfg)
	sum := sha256.Sum256(cfg)
	n.ConfigSHA256 = hex.EncodeToString(sum[:])
	n.ConfigBytes = len(cfg)

	if strings.Contains(text, "SOFTETHER") || strings.Contains(strings.ToUpper(text), "SOFTETHER") {
		n.Vendor = "softether"
	} else if ovpnDirective(text, "client") != "" {
		n.Vendor = "openvpn"
	}

	if ovpnDirective(text, "client") == "" {
		n.Notes = append(n.Notes, "配置里没有 client 指令（可能不是客户端配置）")
	}
	if dev := ovpnDirective(text, "dev"); dev != "tun" && dev != "tap" {
		n.Notes = append(n.Notes, "dev 指令缺失或异常: "+dev)
	}

	fields := strings.Fields(ovpnDirective(text, "remote"))
	switch len(fields) {
	case 0:
		n.Notes = append(n.Notes, "配置里没有 remote 指令")
	case 1, 2:
		// 有些配置只写 remote <host>，端口靠默认值。留痕，端口回落 1194。
		if len(fields) == 1 {
			n.Notes = append(n.Notes, "remote 缺少端口，按 1194 处理")
		}
		n.Server = fields[0]
		if len(fields) == 2 {
			if p, err := strconv.Atoi(fields[1]); err == nil && p > 0 && p <= 65535 {
				n.Port = p
			} else {
				n.Notes = append(n.Notes, "remote 端口异常: "+fields[1])
			}
		}
	default:
		n.Server = fields[0]
		if p, err := strconv.Atoi(fields[1]); err == nil && p > 0 && p <= 65535 {
			n.Port = p
		} else {
			n.Notes = append(n.Notes, "remote 端口异常: "+fields[1])
		}
	}

	switch strings.ToLower(ovpnDirective(text, "proto")) {
	case "tcp", "udp":
		n.Proto = strings.ToLower(ovpnDirective(text, "proto"))
	case "":
		n.Notes = append(n.Notes, "配置里没有 proto 指令，按 udp 处理（OpenVPN 默认）")
		n.Proto = "udp"
	default:
		n.Notes = append(n.Notes, "proto 不是 tcp/udp: "+ovpnDirective(text, "proto"))
		n.Proto = strings.ToLower(ovpnDirective(text, "proto"))
	}

	n.Cipher = ovpnDirective(text, "cipher")
	if n.Cipher == "" {
		// SoftEther 的 OpenVPN 配置基本都会写；真没写就用 SoftEther/2.x 的默认值，
		// 免得界面上出现「无加密字段」这种误导。
		n.Cipher = "AES-128-CBC"
	}
	n.AuthAlgorithm = ovpnDirective(text, "auth")
	if n.AuthAlgorithm == "" {
		n.AuthAlgorithm = "SHA1"
	}
	n.HasCerts = ovpnInlineBlock(text, "ca") != ""
	if !n.HasCerts {
		n.Notes = append(n.Notes, "配置里没有内联 <ca>，导入客户端时要自己补证书")
	}
	if ovpnDirective(text, "tls-auth") != "" || ovpnDirective(text, "tls-crypt") != "" {
		n.Notes = append(n.Notes, "配置带 tls-auth/tls-crypt（导入时需要该密钥）")
	}
	// 只有 IP 字面量才算「能直接连」；域名 remote 要走 DNS，探测时也一样。
	if n.Server != "" && net.ParseIP(n.Server) == nil && !isDomain(n.Server) {
		n.Notes = append(n.Notes, "remote 既不是 IP 也不是合法域名: "+n.Server)
	}
	if n.Server != "" && n.IP != "" && net.ParseIP(n.Server) != nil && n.Server != n.IP {
		n.Notes = append(n.Notes, "remote 的 IP("+n.Server+") 与 CSV 的 IP("+n.IP+") 不一致，连接按 remote")
	}
}

// 指令与内联块的正则缓存。指令名是调用方给的固定几个词，不存在注入风险。
var (
	directiveRe   = map[string]*regexp.Regexp{}
	inlineBlockRe = map[string]*regexp.Regexp{}
)

// ovpnDirective 取一条 .ovpn 指令的值（行首允许空白，忽略大小写）。
func ovpnDirective(config, name string) string {
	re, ok := directiveRe[name]
	if !ok {
		re = regexp.MustCompile(`(?im)^[ \t]*` + regexp.QuoteMeta(name) + `[ \t]+(.+?)[ \t]*$`)
		directiveRe[name] = re
	}
	m := re.FindStringSubmatch(config)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func ovpnInlineBlock(config, tag string) string {
	re, ok := inlineBlockRe[tag]
	if !ok {
		re = regexp.MustCompile(`(?s)<` + regexp.QuoteMeta(tag) + `>(.*?)</` + regexp.QuoteMeta(tag) + `>`)
		inlineBlockRe[tag] = re
	}
	m := re.FindStringSubmatch(config)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// isDomain 宽松判断（探测阶段还要解析，这里只是留痕用）。
func isDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
			if !ok {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}
