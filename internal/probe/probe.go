package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/model"
)

// Options 是探测参数。零值由 New 兜底。
type Options struct {
	TCPTimeout       time.Duration
	UDPTimeout       time.Duration
	HandshakeTimeout time.Duration
	Handshake        bool // 关掉就只做 TCP 握手，对上游零流量
	Retries          int
	AllowPrivateIPs  bool // 默认拒绝私有/保留段地址，避免对着内网打 SYN
	// DialFrom 可选：绑定本地出口地址/接口（多线路机器上对比出口用）。
	DialFrom string
}

// Prober 执行单个节点的探测。可并发复用。
type Prober struct {
	opt Options
	// dialTCP/dialUDP 是为了单测能替换成内存实现。
	dialTCP func(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error)
	dialUDP func(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error)
	resolve func(ctx context.Context, host string) ([]net.IP, error)
}

// New 造一个 Prober。
func New(opt Options) *Prober {
	if opt.TCPTimeout <= 0 {
		opt.TCPTimeout = 5 * time.Second
	}
	if opt.UDPTimeout <= 0 {
		opt.UDPTimeout = 4 * time.Second
	}
	if opt.HandshakeTimeout <= 0 {
		opt.HandshakeTimeout = 4 * time.Second
	}
	if opt.Retries < 0 {
		opt.Retries = 0
	}
	d := &net.Dialer{}
	p := &Prober{opt: opt}
	p.dialTCP = func(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return d.DialContext(ctx, "tcp", addr)
	}
	p.dialUDP = func(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		// UDP 用「已连接」的 socket：这样收到的包只可能来自目标端口，
		// 不会被别的流量的 echo 误判成 OpenVPN 回包。
		return d.DialContext(ctx, "udp", addr)
	}
	r := &net.Resolver{PreferGo: true}
	p.resolve = func(ctx context.Context, host string) ([]net.IP, error) {
		return r.LookupIP(ctx, "ip", host)
	}
	return p
}

// Target 是一个待探测端点。探测器只需要这个，不需要完整的节点对象 ——
// 少一层依赖意味着探测可以被 CLI、定时器和界面复用。
type Target struct {
	ID    string `json:"id"`
	Host  string `json:"host"`
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	// Reason 记录「为什么被选中」，界面和日志里能看见，省掉一堆猜。
	Reason string `json:"reason,omitempty"`
}

// Probe 测一个端点。永远返回非 nil（失败也是一条结果）。
//
// 结论的可信度不在这里判断，交给 store.ComputeHealth：本函数只负责
// 「我看到了什么」，并把「不确定」如实标成 unknown。
func (p *Prober) Probe(ctx context.Context, t Target) *model.ProbeResult {
	host, port, proto := t.Host, t.Port, t.Proto
	res := &model.ProbeResult{At: time.Now().UTC(), Host: host, Port: port, Proto: proto, Service: model.ServiceUnknown, Handshake: p.opt.Handshake}
	t0 := time.Now()
	defer func() {
		res.DurationMS = time.Since(t0).Milliseconds()
		// 轮次被取消/进程收尾：这一条不是节点的结论，不能计入连负轮数。
		// 自己那道 dial 超时是子 ctx 到期，不会让父 ctx 报错，所以这里不会误标。
		if ctx.Err() != nil {
			res.Cancelled = true
		}
	}()

	if port <= 0 || port > 65535 {
		res.Service = model.ServiceBlocked
		res.Reason = "端口缺失或超出范围，无法探测"
		return res
	}
	if proto != "tcp" && proto != "udp" {
		res.Service = model.ServiceBlocked
		res.Reason = "配置里的 proto 不是 tcp/udp: " + proto
		return res
	}

	target, why := p.resolveTarget(ctx, host)
	if why != "" {
		res.Service = model.ServiceBlocked
		res.Reason = why
		return res
	}
	addr := net.JoinHostPort(target, itoa(port))

	if proto == "udp" {
		p.probeUDP(ctx, addr, res)
		return res
	}
	p.probeTCP(ctx, addr, res)
	return res
}

// resolveTarget 把 host 变成可连的 IP 字面量，并挡掉不该连的地址。
//
// 域名节点必须自己解析：DirectInputAddress 之后再用 net.Dial 等于把「校验过的
// 主机名」和「实际连的 IP」脱钩，DNS 一变就可能打到内网（SSRF）。
func (p *Prober) resolveTarget(ctx context.Context, host string) (string, string) {
	if ip := net.ParseIP(host); ip != nil {
		if why := rejectIP(ip, p.opt.AllowPrivateIPs); why != "" {
			return "", why
		}
		return canonical(ip), ""
	}
	if !isDomainName(host) {
		return "", "remote 既不是 IP 也不是合法域名: " + host
	}
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	ips, err := p.resolve(cctx, host)
	if err != nil {
		return "", "域名解析失败: " + err.Error()
	}
	// 逐个筛：域名可能同时有 A/AAAA，也可能部分记录指向内网。
	var best net.IP
	for _, ip := range ips {
		if why := rejectIP(ip, p.opt.AllowPrivateIPs); why == "" {
			best = ip
			break
		}
	}
	if best == nil {
		return "", "域名解析结果都被地址策略拒绝（私有/保留/回环）"
	}
	return canonical(best), ""
}

// rejectIP 返回拒绝原因，空串放行。
func rejectIP(ip net.IP, allowPrivate bool) string {
	switch {
	case ip.IsUnspecified():
		return "地址是未指定地址 " + ip.String()
	case ip.IsLoopback():
		return "地址是回环地址 " + ip.String()
	case ip.IsMulticast():
		return "地址是组播地址 " + ip.String()
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "地址是链路本地地址 " + ip.String()
	case ip.IsPrivate():
		if allowPrivate {
			return ""
		}
		return "地址是私有网段 " + ip.String() + "（probe.allow_private_ips=true 才放行）"
	}
	for _, block := range blockedNets {
		if block.Contains(ip) {
			return "地址落在保留段 " + block.String()
		}
	}
	return ""
}

// blockedNets 与 source 包同一套判断：0.0.0.0/8、CGNAT、fake-IP 基准段等。
var blockedNets = func() []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "198.18.0.0/15", "192.0.0.0/24",
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
	} {
		if _, block, err := net.ParseCIDR(cidr); err == nil {
			out = append(out, block)
		}
	}
	return out
}()

func canonical(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func isDomainName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
	}
	return true
}

// probeTCP 做 TCP 握手，然后（可选）发 OpenVPN 硬重置包认服务。
func (p *Prober) probeTCP(ctx context.Context, addr string, res *model.ProbeResult) {
	attempts := 1 + p.opt.Retries
	var lastService, lastReason string
	for i := 0; i < attempts; i++ {
		res.Attempts = i + 1
		t0 := time.Now()
		conn, err := p.dialTCP(ctx, addr, p.opt.TCPTimeout)
		if err != nil {
			res.ConnectMS = time.Since(t0).Milliseconds()
			res.RTTMS = 0
			lastService, lastReason = classifyDialError(err)
			res.Service, res.Reason = lastService, lastReason
			if errors.Is(err, context.Canceled) {
				return // 上层取消了，不必重试
			}
			continue
		}
		res.ConnectMS = time.Since(t0).Milliseconds()
		res.RTTMS = res.ConnectMS
		res.OK = true

		if !p.opt.Handshake {
			res.Service = model.ServiceTCPOpen
			res.Detail = "仅 TCP 握手（handshake=false）"
			_ = conn.Close()
			return
		}
		// 关键：TCP 连上就已经是可用的可达性结论，握手只是给「是不是
		// OpenVPN/SoftEther」加分。握手失败不能把 OK 改回 false。
		service, detail := p.handshakeTCP(ctx, conn)
		res.Service, res.Detail = service, detail
		res.Reason = ""
		if service == model.ServiceTimeout || service == model.ServiceNoReply {
			res.Reason = "TCP 可达但服务端未按 OpenVPN 应答"
		}
		_ = conn.Close()
		return
	}
	if lastService == "" {
		res.Service, res.Reason = model.ServiceTimeout, "探测未产生结果"
	}
}

// handshakeTCP 发送硬重置包并读回包。返回 (service, detail)。
func (p *Prober) handshakeTCP(ctx context.Context, conn net.Conn) (string, string) {
	payload := BuildHardReset(ShapeLegacy)
	if err := conn.SetDeadline(time.Now().Add(p.opt.HandshakeTimeout)); err != nil {
		return model.ServiceNoReply, "设置超时失败"
	}
	if _, err := conn.Write(TCPFrame(payload)); err != nil {
		return model.ServiceNoReply, "发送硬重置包失败: " + err.Error()
	}
	buf := make([]byte, 1024)
	// 只读一次：TCP 流式，读两次会把「服务端还没决定回不回」的等待翻倍。
	// 服务端如果回了 HTTP 错误页或 OpenVPN 回包，一次读就够拿到判据。
	n, err := conn.Read(buf)
	if n <= 0 {
		if err != nil && !errors.Is(err, io.EOF) && !isTimeout(err) {
			return model.ServiceNoReply, "读取失败: " + err.Error()
		}
		return model.ServiceNoReply, "服务端未回包（连接由对端保持）"
	}
	resp := stripTCPFrame(buf[:n])
	op, kind, detail := DecodeOpcode(resp)
	switch {
	case kind == "http":
		// SoftEther 的 OpenVPN-over-TCP 对无法识别的包就是回 HTTP 错误。
		// 这条实测命中率很高，是 VPN Gate 上「端口后面确实是 SoftEther」的证据。
		return model.ServiceSoftEther, detail
	case kind == "openvpn" && op == opcodeHardResetServerV2:
		return model.ServiceOpenVPN, detail
	case kind == "openvpn":
		return model.ServiceOpenVPN, detail + "（非硬重置回包）"
	default:
		return model.ServiceResponded, detail
	}
}

// stripTCPFrame 剥掉 OpenVPN over TCP 的 2 字节长度前缀。
// 前缀与剩余长度对不上就原样返回：SoftEther 直接回 HTTP 明文，没有前缀。
func stripTCPFrame(b []byte) []byte {
	if len(b) < 3 {
		return b
	}
	n := int(b[0])<<8 | int(b[1])
	if n > 0 && n == len(b)-2 {
		return b[2:]
	}
	return b
}

// probeUDP 发硬重置包听回包。
//
// 没有回包只说明「我们看不到这个 UDP 端口」：SoftEther 对裸硬重置包普遍静默，
// 家宽 NAT 也常把陌生源的 UDP 直接丢掉。所以这里返回 no-reply，
// 由 ComputeHealth 归到 unknown，而不是 down。
func (p *Prober) probeUDP(ctx context.Context, addr string, res *model.ProbeResult) {
	// UDP 没有“先握手再探服务”的分层：发硬重置包本身就是它的全部探测。
	res.Handshake = true
	conn, err := p.dialUDP(ctx, addr, p.opt.TCPTimeout)
	if err != nil {
		// UDP「连接」是纯本地操作，出错基本是地址/网络层问题。
		res.Service, res.Reason = classifyDialError(err)
		return
	}
	defer conn.Close()

	deadline := time.Now().Add(p.opt.UDPTimeout)
	_ = conn.SetDeadline(deadline)
	t0 := time.Now()
	shapes := []PacketShape{ShapeLegacy, ShapeModern}
	var sent int
	for i, sh := range shapes {
		if _, err := conn.Write(BuildHardReset(sh)); err != nil {
			// 连好的 UDP socket 上「发送失败」几乎只会是 ECONNREFUSED ——
			// 对端回了 ICMP 端口不可达。它看着像硬证据，但 NAT 后面的
			// 家宽节点也常被自家 NAT 设备这么回，按未知处理，不判死亡。
			if errors.Is(err, syscall.ECONNREFUSED) {
				res.Service, res.Reason = model.ServiceNoReply,
					"发送时收到端口不可达(ICMP)，UDP 上不做死亡判定"
				return
			}
			res.Service, res.Reason = model.ServiceUnreachable, "发送失败: "+err.Error()
			return
		}
		sent++
		if i < len(shapes)-1 {
			// 两种包形状之间留 200ms：先给老实现一次应答机会，也避免同 RTT
			// 内两个包都被同一个防火墙规则处理掉。
			select {
			case <-ctx.Done():
				res.Service, res.Reason = model.ServiceTimeout, "探测被取消"
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if n <= 0 {
		res.Service = model.ServiceNoReply
		switch {
		case isTimeout(err):
			res.Reason = "UDP 无响应（SoftEther/家宽 NAT 常见，不代表节点离线）"
		case errors.Is(err, syscall.ECONNREFUSED):
			res.Reason = "收到端口不可达(ICMP)，UDP 上不做死亡判定"
		case err != nil:
			res.Reason = "UDP 读取失败: " + err.Error()
		default:
			res.Reason = "UDP 无响应"
		}
		return
	}
	res.OK = true
	res.RTTMS = time.Since(t0).Milliseconds()
	resp := stripTCPFrame(buf[:n])
	op, kind, detail := DecodeOpcode(resp)
	switch {
	case kind == "http":
		res.Service, res.Detail = model.ServiceSoftEther, detail
	case kind == "openvpn" && op == opcodeHardResetServerV2:
		res.Service, res.Detail = model.ServiceOpenVPN, detail
	case kind == "openvpn":
		res.Service, res.Detail = model.ServiceOpenVPN, detail+"（非硬重置回包）"
	default:
		res.Service, res.Detail = model.ServiceResponded, detail
	}
	return
}

// classifyDialError 把连接错误分成「明确不可达」和「不确定」。
//
// refused（收到 RST）是明确的：端口后面没在听。
// timeout 不是：跨境链路上丢 SYN 太常见，写成死亡会误杀一大片。
func classifyDialError(err error) (string, string) {
	switch {
	case err == nil:
		return model.ServiceUnknown, ""
	case errors.Is(err, context.Canceled):
		return model.ServiceTimeout, "探测被取消"
	case errors.Is(err, context.DeadlineExceeded):
		return model.ServiceTimeout, "TCP 握手超时"
	case errors.Is(err, syscall.ECONNREFUSED):
		return model.ServiceRefused, "连接被拒绝（收到 RST，端口没有服务在听）"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPERM):
		return model.ServiceUnreachable, err.Error()
	case errors.Is(err, net.ErrClosed):
		return model.ServiceBlocked, "本地 socket 已关闭"
	}
	msg := err.Error()
	switch {
	case containsFold(msg, "connection refused"):
		return model.ServiceRefused, "连接被拒绝（端口没有服务在听）"
	case containsFold(msg, "no such host"):
		return model.ServiceUnreachable, "域名解析失败: " + msg
	case containsFold(msg, "network is unreachable"), containsFold(msg, "connect: no route"):
		return model.ServiceUnreachable, msg
	case containsFold(msg, "i/o timeout"), containsFold(msg, "timeout"):
		return model.ServiceTimeout, "TCP 握手超时"
	case containsFold(msg, "connection reset"):
		return model.ServiceUnreachable, "连接被重置: " + msg
	}
	return model.ServiceUnreachable, msg
}

func isTimeout(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, context.DeadlineExceeded)
}

func containsFold(s, sub string) bool {
	return len(sub) <= len(s) && indexOfLower(s, sub) >= 0
}

func indexOfLower(s, sub string) int {
	n, m := len(s), len(sub)
	for i := 0; i+m <= n; i++ {
		ok := true
		for j := 0; j < m; j++ {
			if lowerByte(s[i+j]) != lowerByte(sub[j]) {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

func lowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
