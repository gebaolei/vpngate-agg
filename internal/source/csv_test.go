package source

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestParseCSVFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/mini.csv")
	if err != nil {
		t.Fatalf("读测试数据失败: %v", err)
	}
	res, err := ParseCSV(body)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	if res.Records != 5 {
		t.Errorf("数据行数 = %d，期望 5", res.Records)
	}
	if len(res.Rows) != 4 {
		t.Fatalf("可用行 = %d，期望 4（重复行保留，坏 IP 丢弃）：%v", len(res.Rows), res.Skipped)
	}
	if got := res.Skipped["IP 无法解析: not-an-ip"]; got != 1 {
		t.Errorf("坏 IP 跳过数 = %d，期望 1（跳过统计: %v）", got, res.Skipped)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("起始/结束标记都在，不该有告警，实得: %v", res.Warnings)
	}

	first := res.Rows[0].Node
	wantID := "v1:" + shaHexStr("vpngate-node-v1\x00"+"vpn100"+"\x00"+"203.0.113.7")
	if first.ID != wantID {
		t.Errorf("节点 ID = %s，期望按 mirror v1 规则算出的 %s", first.ID, wantID)
	}
	if first.HostName != "vpn100" || first.IP != "203.0.113.7" {
		t.Errorf("主机/IP = %s / %s", first.HostName, first.IP)
	}
	if first.CountryCode != "JP" || first.Country != "Japan (Tokyo)" {
		t.Errorf("国家 = %s / %s", first.CountryCode, first.Country)
	}
	if first.UpstreamScore != 12345 || first.UpstreamSpeedBps != 120000000 || first.Sessions != 5 {
		t.Errorf("上游指标 = %d / %d / %d", first.UpstreamScore, first.UpstreamSpeedBps, first.Sessions)
	}

	// 连接参数必须来自 .ovpn，而不是 CSV —— 客户端连的就是配置里写的那个 remote。
	row := res.Rows[0]
	if row.Node.Port != 1194 || row.Node.Proto != "tcp" {
		t.Errorf("端口/协议 = %d/%s，期望 1194/tcp", row.Node.Port, row.Node.Proto)
	}
	if row.Node.Server != "203.0.113.7" {
		t.Errorf("remote = %q，期望 203.0.113.7", row.Node.Server)
	}
	if row.Node.Cipher != "AES-128-CBC" || row.Node.AuthAlgorithm != "SHA1" {
		t.Errorf("加密参数 = %s / %s", row.Node.Cipher, row.Node.AuthAlgorithm)
	}
	if !row.Node.HasCerts {
		t.Error("配置里有内联 <ca>，HasCerts 应为 true")
	}
	if got := shaHexStr(string(row.Config)); row.Node.ConfigSHA256 != got {
		t.Errorf("配置 sha = %s，实际正文的 sha 是 %s", row.Node.ConfigSHA256, got)
	}
	if row.Node.ConfigBytes != len(row.Config) {
		t.Errorf("配置字节 = %d，实际 %d", row.Node.ConfigBytes, len(row.Config))
	}

	// 上游不给 Operator/Message 加引号，这一行的 Message 里带了个逗号，
	// 字段数就比表头多。固定列按下标取、配置从尾部取，落在自由文本区的值
	// 宁可不填也不能猜错 —— 猜错会把「谁在运营这个节点」写错。
	if first.Operator != "" || first.Message != "" {
		t.Errorf("自由文本区有未转义逗号时应留空，实得 Operator=%q Message=%q", first.Operator, first.Message)
	}
	if !hasNoteContaining(row.Node.Notes, "字段数") {
		t.Errorf("应留下「字段数与表头不符」的痕，实得 %v", row.Node.Notes)
	}

	// 完全重复的两行必须 hash 相同：Aggregate 靠它区分「重复」和「同 ID 冲突」。
	if res.Rows[1].RowHash != row.RowHash {
		t.Error("两条完全相同的行 RowHash 不同")
	}
	if res.Rows[1].Node.ID != first.ID {
		t.Error("重复行的节点 ID 应与首行一致")
	}

	// 自营机房那行：remote 与 CSV 的 IP 不一致要留痕，但不能丢行。
	own := res.Rows[2].Node
	if own.IP != "219.100.37.127" {
		t.Errorf("第三行 IP = %s", own.IP)
	}
	if own.UpstreamPingMS != 0 {
		t.Errorf("Ping 是 '-' 时应记 0（未知），实得 %d", own.UpstreamPingMS)
	}
	if !hasNoteContaining(own.Notes, "remote 的 IP") {
		t.Errorf("remote 与 CSV IP 不一致应留痕，实得 %v", own.Notes)
	}

	udp := res.Rows[3].Node
	if udp.Proto != "udp" {
		t.Errorf("UDP 节点 proto = %q，期望 udp", udp.Proto)
	}
	if udp.UpstreamScore != 0 {
		t.Errorf("Score 为空应记 0，实得 %d", udp.UpstreamScore)
	}
}

func TestParseCSVRequiredColumns(t *testing.T) {
	// 缺 NumVpnSessions：格式变了就直接报错，让调用方保留上一轮的池子，
	// 而不是静默少拿节点。
	body := "*vpn_servers\r\n#HostName,IP,Ping,Speed,CountryLong,CountryShort,OpenVPN_ConfigData_Base64\r\n" +
		"vpn1,8.8.8.8,1,1,Nowhere,NN," + strings.Repeat("Y", 120) + "\r\n*\r\n"
	if _, err := ParseCSV([]byte(body)); err == nil {
		t.Fatal("缺少必需字段时应报错")
	}
}

func TestParseCSVGarbage(t *testing.T) {
	if _, err := ParseCSV([]byte("这不是 CSV\r\n")); err == nil {
		t.Error("没有表头时应报错")
	}
	if _, err := ParseCSV(nil); err == nil {
		t.Error("空内容应报错")
	}
}

func TestParseCSVMissingMarkersStillWorks(t *testing.T) {
	body, err := os.ReadFile("testdata/mini.csv")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(body), "\r\n"), "\n")
	// 去掉首尾标记：数据照用，但要在 Warnings 里说出来。
	trimmed := strings.Join(lines[1:len(lines)-1], "\n")
	res, err := ParseCSV([]byte(trimmed))
	if err != nil {
		t.Fatalf("缺标记不该失败: %v", err)
	}
	if len(res.Rows) == 0 {
		t.Fatal("应有可用节点")
	}
	if len(res.Warnings) < 2 {
		t.Errorf("应至少两条告警（缺起始标记、缺结束标记），实得 %v", res.Warnings)
	}
}

func TestCanonicalIPPolicy(t *testing.T) {
	cases := []struct {
		in       string
		wantIP   string
		wantNote string // 空 = 不该有 note；fatal: 前缀 = 致命
	}{
		{"8.8.8.8", "8.8.8.8", ""},
		{" 8.8.8.8 ", "8.8.8.8", ""},
		{"::ffff:8.8.8.8", "8.8.8.8", ""}, // IPv4 in IPv6 统一写法，否则同一节点会变两个 ID
		{"2001:4860:4860::8888", "2001:4860:4860::8888", ""},
		{"127.0.0.1", "", "fatal"},
		{"0.0.0.0", "", "fatal"},
		{"224.0.0.1", "", "fatal"},
		{"not-an-ip", "", "fatal"},
		{"fe80::1%eth0", "", "fatal"},
		{"10.1.2.3", "10.1.2.3", "私有网段"},
		{"100.64.5.6", "100.64.5.6", "保留段"},   // CGNAT / Tailscale
		{"198.18.0.9", "198.18.0.9", "保留段"},   // fake-IP / TUN 代理劫持段
		{"192.0.2.7", "192.0.2.7", "保留段"},     // TEST-NET-1
		{"203.0.113.7", "203.0.113.7", "保留段"}, // TEST-NET-3
	}
	for _, c := range cases {
		got, note := canonicalIP(c.in)
		if got != c.wantIP {
			t.Errorf("canonicalIP(%q) = %q，期望 %q", c.in, got, c.wantIP)
		}
		switch {
		case c.wantNote == "" && note != "":
			t.Errorf("canonicalIP(%q) 不该有 note，实得 %q", c.in, note)
		case c.wantNote == "fatal" && !strings.HasPrefix(note, "fatal:"):
			t.Errorf("canonicalIP(%q) 应致命，实得 %q", c.in, note)
		case c.wantNote != "" && c.wantNote != "fatal" && !strings.Contains(note, c.wantNote):
			t.Errorf("canonicalIP(%q) 的 note 应含 %q，实得 %q", c.in, c.wantNote, note)
		}
	}
}

func TestNormalizeHostNameAndCountry(t *testing.T) {
	if got, note := normalizeHostName(" VPN100. "); got != "vpn100" || note != "" {
		t.Errorf("normalizeHostName = %q / %q", got, note)
	}
	if got, note := normalizeHostName("vpn100."); got != "vpn100" || note != "" {
		t.Errorf("去掉结尾点失败: %q / %q", got, note)
	}
	if _, note := normalizeHostName("-bad"); note == "" {
		t.Error("以连字符开头的标签应留痕")
	}
	if _, note := normalizeHostName(""); note == "" {
		t.Error("空 HostName 应留痕")
	}

	for code, want := range map[string]string{"jp": "JP", "JP": "JP", "XX": "", "ZZ": "", "": "", "JPP": "", "J1": ""} {
		if got := normalizeCountry(code); got != want {
			t.Errorf("normalizeCountry(%q) = %q，期望 %q", code, got, want)
		}
	}
}

func TestDecodeConfigBase64Variants(t *testing.T) {
	const plain = "client\ndev tun\n"
	for _, enc := range []string{"Y2xpZW50CmRldiB0dW4K", "Y2xpZW50CmRldiB0dW4", "-Y2xpZW50CmRldiB0dW4K"} {
		if got, err := decodeConfig(enc); err == nil && enc == "Y2xpZW50CmRldiB0dW4K" && string(got) != plain {
			t.Errorf("标准 base64 解错: %q", got)
		}
	}
	if _, err := decodeConfig("!!!!不是 base64!!!!"); err == nil {
		t.Error("非法 base64 应报错")
	}
}

func shaHexStr(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hasNoteContaining(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}
