package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/model"
)

func fastOptions() Options {
	return Options{
		TCPTimeout:       2 * time.Second,
		UDPTimeout:       800 * time.Millisecond,
		HandshakeTimeout: 800 * time.Millisecond,
		Handshake:        true,
		AllowPrivateIPs:  true,
	}
}

// startTCPServer 起一个本地 TCP 服务，handler 拿到连接后随便怎么写。
// 直接调 probeTCP / probeUDP 绕开地址策略：测试用的是回环地址，
// 而策略本来就故意拒绝回环（不该对着自己打）。
func startTCPServer(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("本地监听不可用: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	return ln.Addr().String()
}

// SoftEther 的 OpenVPN-over-TCP 对硬重置包就是回 HTTP 400。
// 这是 VPN Gate 上「端口后面确实是 SoftEther」的实测特征，
// 认不出它就会把整个 TCP 池子标成「有应答但不明」。
func TestProbeTCPSoftEther(t *testing.T) {
	addr := startTCPServer(t, func(c net.Conn) {
		defer c.Close()
		_, _ = io.ReadFull(c, make([]byte, 4))
		_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\nX-T: SoftEther VPN\n\n"))
	})
	res := &model.ProbeResult{}
	New(fastOptions()).probeTCP(context.Background(), addr, res)

	if !res.OK {
		t.Fatalf("TCP 连上就算可达，实得 OK=false（%s）", res.Reason)
	}
	if res.Service != model.ServiceSoftEther {
		t.Errorf("service = %s，期望 %s（detail=%q）", res.Service, model.ServiceSoftEther, res.Detail)
	}
	if !strings.Contains(res.Detail, "HTTP/1.1 400") {
		t.Errorf("detail 应带上原始回包首行，实得 %q", res.Detail)
	}
	if res.Reason != "" {
		t.Errorf("可达时不该留失败原因，实得 %q", res.Reason)
	}
}

// 真 OpenVPN 回 opcode 8。
func TestProbeTCPHardReset(t *testing.T) {
	addr := startTCPServer(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 256)
		if _, err := c.Read(buf); err != nil {
			return
		}
		_, _ = c.Write(TCPFrame(serverHardResetReply()))
	})
	res := &model.ProbeResult{}
	New(fastOptions()).probeTCP(context.Background(), addr, res)
	if !res.OK || res.Service != model.ServiceOpenVPN {
		t.Errorf("service = %s / ok=%v，期望 openvpn", res.Service, res.OK)
	}
}

// 连上但不回话：可达性结论仍然是「可达」，只是服务指纹未知。
// 把这种情况当死亡，是这类工具最常见的误判来源。
func TestProbeTCPConnectedButSilent(t *testing.T) {
	addr := startTCPServer(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
		time.Sleep(1500 * time.Millisecond) // 比握手超时久
	})
	opt := fastOptions()
	opt.HandshakeTimeout = 300 * time.Millisecond
	res := &model.ProbeResult{}
	New(opt).probeTCP(context.Background(), addr, res)

	if !res.OK {
		t.Errorf("TCP 连上就该 OK=true，实得 false（service=%s reason=%q）", res.Service, res.Reason)
	}
	if res.Service != model.ServiceNoReply && res.Service != model.ServiceTimeout {
		t.Errorf("service = %s，期望 no-reply/timeout", res.Service)
	}
	if res.Reason == "" {
		t.Error("应当留一句能解释「为什么不知道」的原因")
	}
}

func TestProbeTCPWithoutHandshake(t *testing.T) {
	addr := startTCPServer(t, func(c net.Conn) {
		defer c.Close()
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
	})
	opt := fastOptions()
	opt.Handshake = false
	res := &model.ProbeResult{}
	New(opt).probeTCP(context.Background(), addr, res)
	if !res.OK || res.Service != model.ServiceTCPOpen {
		t.Errorf("关掉握手后应是 tcp-open，实得 %s / ok=%v", res.Service, res.OK)
	}
}

func TestProbeTCPRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("本地监听不可用: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // 立刻关掉 → 端口上没人听 → 收到 RST

	res := &model.ProbeResult{}
	New(fastOptions()).probeTCP(context.Background(), addr, res)
	if res.OK {
		t.Error("端口拒绝时可达性必须是 false")
	}
	if res.Service != model.ServiceRefused {
		t.Errorf("service = %s，期望 %s", res.Service, model.ServiceRefused)
	}
}

// UDP 无响应只能算「我们看不到」。SoftEther 对裸硬重置包普遍静默，
// 家宽 NAT 也常直接丢 —— 写成 down 会把整个 UDP 池冤枉掉。
func TestProbeUDPNoReply(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("本地 UDP 不可用: %v", err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close() // 没人收，发了等于白发

	res := &model.ProbeResult{}
	New(fastOptions()).probeUDP(context.Background(), addr, res)
	if res.OK {
		t.Error("UDP 没收到回包不该算可达")
	}
	if res.Service != model.ServiceNoReply {
		t.Errorf("service = %s，期望 %s（不是 down）", res.Service, model.ServiceNoReply)
	}
	if res.Reason == "" {
		t.Error("应留一句能解释「为什么不确定」的原因")
	}
}

func TestProbeUDPReplies(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("本地 UDP 不可用: %v", err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil || n == 0 {
				return
			}
			_, _ = pc.WriteTo(serverHardResetReply(), from)
		}
	}()

	res := &model.ProbeResult{}
	New(fastOptions()).probeUDP(context.Background(), pc.LocalAddr().String(), res)
	if !res.OK || res.Service != model.ServiceOpenVPN {
		t.Errorf("service = %s / ok=%v，期望 openvpn 硬重置回包", res.Service, res.OK)
	}
}

func TestRejectIPPolicy(t *testing.T) {
	cases := []struct {
		ip          string
		allowPriv   bool
		wantRejeect bool
	}{
		{"8.8.8.8", false, false},
		{"2001:4860:4860::8888", false, false},
		{"127.0.0.1", true, true},  // 回环永远拒绝：哪怕放开了私有段
		{"10.1.2.3", false, true},  // 默认不打内网
		{"10.1.2.3", true, false},  // 显式允许才放行
		{"100.64.0.1", true, true}, // CGNAT：放行私有段也不放行它
		{"198.18.0.1", true, true}, // fake-IP 段：本机跑 TUN 时上游域名会解析到这里
		{"169.254.1.1", true, true},
		{"224.0.0.5", true, true},
		{"0.0.0.0", true, true},
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("测试地址写错了: %s", c.ip)
		}
		got := rejectIP(ip, c.allowPriv)
		if (got != "") != c.wantRejeect {
			t.Errorf("rejectIP(%s, allowPrivate=%v) = %q，是否应拒绝=%v", c.ip, c.allowPriv, got, c.wantRejeect)
		}
	}
}

func TestProbePolicyBlocksLoopback(t *testing.T) {
	// 界面上「测一下」点一个内网地址，要拿到一个能看懂的 blocked，
	// 而不是对着自己打 SYN 然后报个莫名其妙的超时。
	res := New(fastOptions()).Probe(context.Background(), Target{ID: "v1:x", Host: "127.0.0.1", Port: 1194, Proto: "tcp"})
	if res.OK || res.Service != model.ServiceBlocked {
		t.Errorf("service = %s / ok=%v，期望 blocked", res.Service, res.OK)
	}
	if res.Reason == "" {
		t.Error("blocked 必须给原因")
	}
}

func TestProbeRejectsBadTarget(t *testing.T) {
	p := New(fastOptions())
	if res := p.Probe(context.Background(), Target{ID: "a", Host: "8.8.8.8", Port: 0, Proto: "tcp"}); res.Service != model.ServiceBlocked {
		t.Errorf("端口缺失应 blocked，实得 %s", res.Service)
	}
	if res := p.Probe(context.Background(), Target{ID: "b", Host: "8.8.8.8", Port: 1194, Proto: "sctp"}); res.Service != model.ServiceBlocked {
		t.Errorf("proto 不是 tcp/udp 应 blocked，实得 %s", res.Service)
	}
	if res := p.Probe(context.Background(), Target{ID: "c", Host: "", Port: 1194, Proto: "tcp"}); res.Service != model.ServiceBlocked {
		t.Errorf("缺主机应 blocked，实得 %s", res.Service)
	}
}

func TestClassifyDialError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{syscall.ECONNREFUSED, model.ServiceRefused},
		{errors.New("dial tcp 1.2.3.4:1194: connect: connection refused"), model.ServiceRefused},
		{context.DeadlineExceeded, model.ServiceTimeout},
		{errors.New("dial tcp: i/o timeout"), model.ServiceTimeout},
		{context.Canceled, model.ServiceTimeout},
		{errors.New("dial tcp: lookup x.invalid: no such host"), model.ServiceUnreachable},
		{errors.New("connect: network is unreachable"), model.ServiceUnreachable},
		{syscall.ECONNRESET, model.ServiceUnreachable},
		{net.ErrClosed, model.ServiceBlocked},
	}
	for _, c := range cases {
		got, detail := classifyDialError(c.err)
		if got != c.want {
			t.Errorf("classifyDialError(%v) = %s，期望 %s", c.err, got, c.want)
		}
		if detail == "" {
			t.Errorf("classifyDialError(%v) 该留下一句人话", c.err)
		}
	}
}

func TestIsDomainName(t *testing.T) {
	for _, s := range []string{"vpn.example.com", "a.b.c.d", "vpn100.local", "example.com."} {
		if !isDomainName(s) {
			t.Errorf("%q 应是合法域名", s)
		}
	}
	for _, s := range []string{"", ".com", "-bad.com", "bad-.com", "has space.com", strings.Repeat("a", 65) + ".com"} {
		if isDomainName(s) {
			t.Errorf("%q 不该被当域名", s)
		}
	}
}

func TestRunRoundCountsAndBatches(t *testing.T) {
	// 三个「端口没人听」的目标：不联网也能跑完一整轮，用来验证调度与写回。
	targets := []Target{
		{ID: "v1:aaa", Host: "127.0.0.1", Port: 1, Proto: "tcp", Reason: "从没测过"},
		{ID: "v1:bbb", Host: "127.0.0.1", Port: 2, Proto: "tcp"},
		{ID: "v1:ccc", Host: "127.0.0.1", Port: 3, Proto: "tcp"},
	}
	var applied []map[string]*model.ProbeResult
	var progress []int
	job, err := RunRound(context.Background(), New(fastOptions()), targets,
		RoundOptions{Concurrency: 2, BatchSize: 2, BatchDelay: 50 * time.Millisecond, Stagger: time.Millisecond},
		func(m map[string]*model.ProbeResult) { applied = append(applied, m) },
		func(done, ok int, last string) { progress = append(progress, done) })
	if err != nil {
		t.Fatalf("RunRound 失败: %v", err)
	}
	if job.Total != 3 || job.Done != 3 {
		t.Errorf("job = %+v，期望 total/done 都是 3", job)
	}
	if job.Status != "done" {
		t.Errorf("status = %s，期望 done", job.Status)
	}
	// 回环地址会被地址策略先拦掉（探测不该对着自己打），所以三个目标都落在
	// blocked：那是「根本不该打出去」的明确否定（与 UpdateFailRounds 同一口径），
	// 计失败而不是计不确定。
	if job.OK != 0 || job.Failed != 3 || job.Skipped != 0 {
		t.Errorf("期望 ok=0 / failed=3 / skipped=0，实得 %d / %d / %d", job.OK, job.Failed, job.Skipped)
	}
	seen := map[string]bool{}
	for _, m := range applied {
		for id, r := range m {
			seen[id] = true
			if r.Service != model.ServiceBlocked {
				t.Errorf("%s 的 service = %s，回环目标应被地址策略拦成 %s", id, r.Service, model.ServiceBlocked)
			}
		}
	}
	for _, tg := range targets {
		if !seen[tg.ID] {
			t.Errorf("%s 的结果没写回（分批写回漏了）", tg.ID)
		}
	}
	if len(progress) == 0 || progress[len(progress)-1] != 3 {
		t.Errorf("进度事件没到终值: %v", progress)
	}
}

func TestRunRoundEmptyAndCancel(t *testing.T) {
	job, err := RunRound(context.Background(), New(fastOptions()), nil, RoundOptions{}, nil, nil)
	if err != nil || job.Total != 0 || job.Status != "done" {
		t.Errorf("空目标应直接结束: %+v %v", job, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	targets := make([]Target, 0, 20)
	for i := 0; i < 20; i++ {
		targets = append(targets, Target{ID: "v1:" + string(rune('a'+i)), Host: "127.0.0.1", Port: 1, Proto: "tcp"})
	}
	job, err = RunRound(ctx, New(fastOptions()), targets, RoundOptions{Concurrency: 1, BatchSize: 100, BatchDelay: time.Second}, nil, nil)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("取消应把 context.Canceled 透传给调用方，实得 %v", err)
	}
	if job.Status != "cancelled" {
		t.Errorf("status = %s，期望 cancelled（界面上要能区分「跑完」和「被取消」）", job.Status)
	}
	if job.Done >= job.Total {
		t.Errorf("取消后不该把 %d 个目标全测完，实得 done=%d", job.Total, job.Done)
	}
}

// TCP 握手超时是「明确否定」（连不上就是不可用），被取消的探测不是结论。
// 判定靠 service + proto + cancelled 三个字段，它们必须从探测器里就带对：
// UDP 的超时不能判死，靠的就是 proto；轮次被中断不能进淘汰计数，靠的是 cancelled。
func TestProbeTimeoutIsNegativeButCancelIsNot(t *testing.T) {
	p := New(fastOptions())
	p.dialTCP = func(_ context.Context, _ string, _ time.Duration) (net.Conn, error) {
		return nil, context.DeadlineExceeded
	}
	res := p.Probe(context.Background(), Target{ID: "v1:t", Host: "8.8.8.8", Port: 995, Proto: "tcp"})
	if res.OK || res.Service != model.ServiceTimeout {
		t.Errorf("ok=%v service=%s，期望 false/timeout", res.OK, res.Service)
	}
	if res.Proto != "tcp" {
		t.Errorf("proto = %q，必须带出去：UDP 的超时不判死就靠这个字段", res.Proto)
	}
	if !model.NegativeResult(*res) {
		t.Error("TCP 握手超时应算明确否定（不可达）")
	}
	if !res.Handshake {
		t.Error("handshake=true 时结果里该记上做了硬重置探测，界面才能说明白")
	}

	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.dialTCP = func(_ context.Context, _ string, _ time.Duration) (net.Conn, error) {
		return nil, context.Canceled
	}
	res = p.Probe(cctx, Target{ID: "v1:c", Host: "8.8.8.8", Port: 995, Proto: "tcp"})
	if !res.Cancelled {
		t.Error("被取消的探测必须标 cancelled：它不是节点的结论")
	}
	if model.NegativeResult(*res) {
		t.Error("被取消的探测不该算明确否定")
	}
}

func TestMain(m *testing.M) {
	// 探测会用系统解析器，测试里只连本地地址，把 DNS 关掉避免真联网。
	_ = os.Setenv("GODEBUG", "netdns=go")
	os.Exit(m.Run())
}
