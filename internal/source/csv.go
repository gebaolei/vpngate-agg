package source

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gebaolei/vpngate-agg/internal/model"
)

// 上限对齐 vpngate-list-mirror 的协议文档：解码后配置 128 KiB、
// 记录（含重复）5000 条、列 64 条。超了就是内容不对，不是「上游变大了」。
const (
	maxConfigBytes = 128 << 10
	maxRecords     = 5000
	maxColumns     = 64
	maxFieldHexRun = 0 // 保留位：以后要查超长字段时用
)

// requiredColumns 缺任何一条就是格式变了。与其默默少拿节点，
// 不如直接报错让上层保留上一轮的池子。
var requiredColumns = []string{
	"HostName", "IP", "Ping", "Speed", "CountryLong", "CountryShort",
	"NumVpnSessions", "OpenVPN_ConfigData_Base64",
}

// freeTextColumns 是可能自带逗号的自由文本列（运营商名、节点留言）。
// 上游并不给它们加引号，所以一行里可能出现比表头更多的字段 ——
// 这时固定列按下标取、配置列从尾部取，落在自由文本区的就不猜。
// 实测过：Operator 里 "Daiyuu Nobori_ Japan. Academic Use Only." 不带逗号，
// 但 Message 里 "AS1234, Tokyo" 这类写法很常见。
var freeTextColumns = []string{"Operator", "Message"}

// RawRow 是 CSV 一行里已经拿到的东西（配置已解码）。
type RawRow struct {
	Node    *model.Node
	Config  []byte
	RowHash string // 整行的规范化 hash，用来区分「完全重复」和「同 ID 但内容不同」
	Notes   []string
}

// ParseResult 是一次 CSV 解析的结果。
type ParseResult struct {
	Rows     []RawRow
	Skipped  map[string]int // 原因 → 行数，界面与日志都要能看见
	Warnings []string
	Records  int // 含重复的数据行数（对应 mirror 的 source_record_count）
}

// ParseCSV 解析 VPN Gate 的节点 CSV。
//
// 格式：首记录 "*vpn_servers"，表头记录以 '#' 开头，末记录只有一个 "*"。
//
// 不能先按行切再喂 csv.Reader：官方把配置放 base64 时可能带引号并内嵌换行，
// 按行切会把一个字段劈成两半。这里直接让 encoding/csv 从头读，靠状态机
// 认出三个标记（首标记、'#' 表头、结束 '*'）。
//
// FieldsPerRecord=-1 + LazyQuotes 是必要的：自由文本列里未加引号的逗号会让
// 字段数超过表头，裸引号会让严格模式直接报错。
func ParseCSV(body []byte) (*ParseResult, error) {
	s := string(bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")))
	r := csv.NewReader(strings.NewReader(s))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true

	res := &ParseResult{Skipped: map[string]int{}}
	var header []string
	var idx map[string]int
	var fixedPrefix, configIdx int
	tailFromEnd := false
	sawStart, sawEnd := false, false

	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("解析节点 CSV 失败: %w", err)
		}
		if len(rec) == 1 {
			f := strings.TrimSpace(rec[0])
			switch f {
			case "":
				continue // 空记录允许
			case "*vpn_servers":
				sawStart = true
				continue
			case "*":
				sawEnd = true
				continue
			}
		}
		if header == nil {
			h := make([]string, len(rec))
			for i, name := range rec {
				// '#' 只在解析时去掉，不参与列名（mirror 协议同样如此）
				h[i] = strings.TrimPrefix(strings.TrimSpace(name), "#")
			}
			if len(h) > maxColumns {
				return nil, fmt.Errorf("列数超过 %d，按异常处理", maxColumns)
			}
			idx = map[string]int{}
			for i, name := range h {
				if _, dup := idx[name]; dup {
					return nil, fmt.Errorf("表头列名重复: %s", name)
				}
				idx[name] = i
			}
			for _, k := range requiredColumns {
				if _, ok := idx[k]; !ok {
					return nil, fmt.Errorf("节点列表缺少字段 %s（上游格式可能变了）", k)
				}
			}
			// 固定列的边界：第一个自由文本列之前的列按下标取一定安全。
			fixedPrefix = len(h)
			for _, name := range freeTextColumns {
				if i, ok := idx[name]; ok && i < fixedPrefix {
					fixedPrefix = i
				}
			}
			configIdx = idx["OpenVPN_ConfigData_Base64"]
			// 只有配置列真的是最后一列时才能从尾部取，否则上游加列就得重新对齐。
			tailFromEnd = configIdx == len(h)-1
			header = h
			continue
		}
		if sawEnd {
			res.Warnings = append(res.Warnings, "结束标记之后出现了非空数据行，已忽略")
			continue
		}
		if res.Records >= maxRecords {
			res.Skipped["超过 5000 行上限"]++
			continue
		}
		res.Records++
		row := recordToRow(rec, len(header), idx, fixedPrefix, configIdx, tailFromEnd)
		if len(row.Node.Notes) == 0 && row.Config != nil {
			res.Rows = append(res.Rows, row)
			continue
		}
		// 有 note 的行分两类：致命的（缺 hostname/IP/配置）丢掉并计数，
		// 非致命的（指标解析失败）保留。
		if why, fatal := fatalNote(row.Node.Notes); fatal {
			res.Skipped[why]++
			continue
		}
		res.Rows = append(res.Rows, row)
	}

	if header == nil {
		return nil, errors.New("节点列表里没有表头")
	}
	if !sawStart {
		res.Warnings = append(res.Warnings, "缺少 *vpn_servers 起始标记（继续按可用数据解析）")
	}
	if !sawEnd {
		res.Warnings = append(res.Warnings, "缺少结束标记 *（可能被截断）")
	}
	if len(res.Rows) == 0 {
		return nil, fmt.Errorf("节点列表解析后没有可用节点（%v）", res.Skipped)
	}
	return res, nil
}

// recordToRow 把一条 CSV 记录变成 RawRow。
// 返回的 node.Notes 里第一条若是 "fatal:" 开头，调用方就把这行丢掉。
func recordToRow(rec []string, headerLen int, idx map[string]int, fixedPrefix, configIdx int, tailFromEnd bool) RawRow {
	get := func(k string) string {
		i, ok := idx[k]
		if !ok {
			return ""
		}
		switch {
		case len(rec) == headerLen:
			// 正常情况
		case tailFromEnd && i == configIdx:
			// 多出来的逗号在中间，配置永远是最后一个字段
			i = len(rec) - 1
		case i >= fixedPrefix:
			// 落在自由文本区，不猜
			return ""
		}
		if i < 0 || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}

	n := &model.Node{}
	host := get("HostName")
	ipRaw := get("IP")
	cfgB64 := get("OpenVPN_ConfigData_Base64")

	if host == "" {
		n.Notes = append(n.Notes, "fatal: 缺少 HostName")
		return RawRow{Node: n, Notes: n.Notes}
	}
	if len(cfgB64) < 100 {
		n.Notes = append(n.Notes, "fatal: 配置字段为空或过短")
		return RawRow{Node: n, Notes: n.Notes}
	}
	cfg, err := decodeConfig(cfgB64)
	if err != nil {
		n.Notes = append(n.Notes, "fatal: 配置 base64 无法解码: "+err.Error())
		return RawRow{Node: n, Notes: n.Notes}
	}
	if len(cfg) > maxConfigBytes {
		n.Notes = append(n.Notes, fmt.Sprintf("fatal: 配置 %d 字节，超过 %d 上限", len(cfg), maxConfigBytes))
		return RawRow{Node: n, Notes: n.Notes}
	}
	if !utf8.Valid(cfg) {
		n.Notes = append(n.Notes, "fatal: 配置不是合法 UTF-8")
		return RawRow{Node: n, Notes: n.Notes}
	}

	ip, ipNote := canonicalIP(ipRaw)
	if ipNote != "" {
		if strings.HasPrefix(ipNote, "fatal:") {
			n.Notes = append(n.Notes, ipNote)
			return RawRow{Node: n, Notes: n.Notes}
		}
		n.Notes = append(n.Notes, ipNote)
	}

	hn, hnNote := normalizeHostName(host)
	if hnNote != "" {
		n.Notes = append(n.Notes, hnNote)
	}
	if ip == "" {
		return RawRow{Node: n, Notes: n.Notes}
	}

	sum := sha256.Sum256([]byte("vpngate-node-v1\x00" + hn + "\x00" + ip))
	n.ID = "v1:" + hex.EncodeToString(sum[:])
	n.HostName = host // 原样存，展示用
	n.IP = ip
	n.Country = get("CountryLong")
	n.CountryCode = normalizeCountry(get("CountryShort"))
	n.Operator = get("Operator")
	n.Message = get("Message")
	n.LogType = get("LogType")

	// 上游指标：空值与 "-" 都当未知（记 0），解析不了的记 0 并留痕，
	// 因为界面要显示的是「官方给了什么」，不能瞎编。
	n.UpstreamScore = intInt64(get("Score"), n, "Score")
	if p := strings.TrimSpace(get("Ping")); p != "" && p != "-" {
		n.UpstreamPingMS = intInt64(p, n, "Ping")
	}
	n.UpstreamSpeedBps = intInt64(get("Speed"), n, "Speed")
	n.Sessions = intInt64(get("NumVpnSessions"), n, "NumVpnSessions")
	n.UptimeSeconds = intInt64(get("Uptime"), n, "Uptime")
	n.TotalUsers = intInt64(get("TotalUsers"), n, "TotalUsers")
	n.TotalTraffic = intInt64(get("TotalTraffic"), n, "TotalTraffic")

	// 连接参数从配置里取：客户端连的就是配置里写的 remote。
	FillFromConfig(n, cfg)
	if len(rec) != headerLen {
		n.Notes = append(n.Notes, fmt.Sprintf("字段数 %d 与表头 %d 不符（自由文本列里有未转义逗号）", len(rec), headerLen))
	}
	// 行 hash 用来区分「完全重复的行」和「同 ID 但内容不同」，
	// 后者说明上游给了互相矛盾的数据，得留痕而不是随便挑一条。
	rowSum := sha256.Sum256([]byte(strings.Join(rec, "\x1f")))
	return RawRow{Node: n, Config: cfg, RowHash: hex.EncodeToString(rowSum[:]), Notes: n.Notes}
}

// fatalNote 看 notes 里有没有 "fatal:" 前缀，有就返回原因（去掉前缀）。
func fatalNote(notes []string) (string, bool) {
	for _, x := range notes {
		if strings.HasPrefix(x, "fatal: ") {
			return strings.TrimPrefix(x, "fatal: "), true
		}
	}
	return "", false
}

// intInt64 宽松取整：空/非数字返回 0 并在 notes 里留痕。
func intInt64(s string, n *model.Node, field string) int64 {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		// 小数（Speed 偶尔给浮点）单独试一次，其余按异常留痕。
		if f, ferr := strconv.ParseFloat(s, 64); ferr == nil {
			return int64(f)
		}
		n.Notes = append(n.Notes, fmt.Sprintf("%s 无法解析: %q", field, s))
		return 0
	}
	if v < 0 {
		n.Notes = append(n.Notes, fmt.Sprintf("%s 是负数(%d)，按 0 处理", field, v))
		return 0
	}
	return v
}

// normalizeCountry: 两位码大写；XX/ZZ/空 归一为空（未知）。
func normalizeCountry(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if len(s) != 2 || s == "XX" || s == "ZZ" {
		return ""
	}
	allUpper := true
	for _, r := range s {
		if r < 'A' || r > 'Z' {
			allUpper = false
		}
	}
	if !allUpper {
		return ""
	}
	return s
}

// blockedNets 是 net.IP.IsPrivate 覆盖不到的保留段。两段必须点名：
//
//	100.64.0.0/10  运营商级 NAT，Tailscale/ZeroTier 之类会用到
//	198.18.0.0/15  基准测试段，也是 fake-IP / TUN 代理常用的劫持段。
//	               本机跑 TUN 时 www.vpngate.net 会被解析到这里，
//	               列表里真出现这种地址就说明拿回来的内容不可信。
var blockedNets = []string{
	"0.0.0.0/8", "100.64.0.0/10", "198.18.0.0/15", "192.0.0.0/24",
	"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
}

var blockedPrefixes = func() []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range blockedNets {
		if _, block, err := net.ParseCIDR(cidr); err == nil {
			out = append(out, block)
		}
	}
	return out
}()

// canonicalIP 按 mirror 协议规范化 IP：拒掉 scoped/未指定/组播/回环，
// 私有与保留段保留但留 note（探测阶段默认跳过，避免对着内网打 SYN）。
func canonicalIP(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "fatal: 缺少 IP"
	}
	// 带 zone 的 IPv6（fe80::1%eth0）一律拒：跨机器没有意义。
	if i := strings.IndexByte(raw, '%'); i >= 0 {
		return "", "fatal: IP 带 zone 后缀: " + raw
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", "fatal: IP 无法解析: " + raw
	}
	switch {
	case ip.IsUnspecified():
		return "", "fatal: IP 是未指定地址: " + raw
	case ip.IsLoopback():
		return "", "fatal: IP 是回环地址: " + raw
	case ip.IsMulticast():
		return "", "fatal: IP 是组播地址: " + raw
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return ip.String(), "IP 是链路本地地址: " + raw
	case ip.IsPrivate():
		return ip.String(), "IP 是私有网段: " + raw
	}
	for _, block := range blockedPrefixes {
		if block.Contains(ip) {
			return ip.String(), "IP 落在保留段 " + block.String() + ": " + raw
		}
	}
	// IPv4 映射的 IPv6（::ffff:1.2.3.4）统一成 IPv4 字符串，
	// 否则同一节点会因为写法不同变成两个 ID。
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), ""
	}
	return ip.String(), ""
}

var reLabel = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)

// normalizeHostName 按 mirror 的 v1 规则做 ID 归一化：trim + 小写 +
// 去掉一个结尾点，逐段校验。不合法不致命 —— 照样能连（连接用的是 IP/remote），
// 只是说明上游给了个奇怪的名字，留 note。
func normalizeHostName(raw string) (string, string) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "unnamed", "HostName 为空"
	}
	if len(s) > 253 {
		return s, fmt.Sprintf("HostName 超过 253 字符（%d）", len(s))
	}
	for _, label := range strings.Split(s, ".") {
		if !reLabel.MatchString(label) || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return s, "HostName 不是合法标签形式: " + raw
		}
	}
	return s, ""
}

// decodeConfig 解一份 .ovpn。上游 base64 里偶尔塞换行/空格，先清掉；
// 个别客户端给的是无 padding 或 URL-safe 的，各试一次再放弃。
func decodeConfig(b64 string) ([]byte, error) {
	clean := strings.Join(strings.Fields(b64), "")
	// VPN Gate 实测用的是标准表 + padding；但镜像里见过 URL-safe。
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if raw, err := enc.DecodeString(clean); err == nil {
			return raw, nil
		}
	}
	return nil, errors.New("不是任何已知的 base64 变体")
}
