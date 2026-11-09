package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/app"
	"github.com/gebaolei/vpngate-agg/internal/config"
	"github.com/gebaolei/vpngate-agg/internal/model"
	"github.com/gebaolei/vpngate-agg/internal/source"
	"github.com/gebaolei/vpngate-agg/internal/store"
)

// 对外接口的测试口令（Validate 要求至少 16 字符）。
const testAPIToken = "tok-0123456789abcdef0123456789"

// officialColumns 是官方 /api/iphone/ 表头里的 15 列，顺序也是它给 JSON 时的顺序。
// 这条接口的全部意义就是「跟官方同形」，所以这里逐列比对而不是抽查几个字段。
var officialColumns = []string{
	"HostName", "IP", "Score", "Ping", "Speed", "CountryLong", "CountryShort",
	"NumVpnSessions", "Uptime", "TotalUsers", "TotalTraffic", "LogType",
	"Operator", "Message", "OpenVPN_ConfigData_Base64",
}

// seedAPIPool 塞三个节点：分数高低各一（验证默认按 Score 降序）、
// 一个正文不在本地（验证它被整行跳过而不是塞一个空配置列）。
func seedAPIPool(t *testing.T, a *app.App) map[string]*model.Node {
	t.Helper()
	st := a.Store()
	mk := func(id, host, ip, country, code, proto string, port int, sha string, score int64, saveBody bool) *model.Node {
		if sha != "" && saveBody {
			body := "client\nremote " + ip + " " + strconv.Itoa(port) + " " + proto + "\ntls-client\n"
			if err := st.SaveConfig(sha, []byte(body)); err != nil {
				t.Fatal(err)
			}
		}
		return &model.Node{
			ID: id, HostName: host, IP: ip, Server: ip, Port: port, Proto: proto,
			Country: country, CountryCode: code,
			ConfigSHA256: sha, ConfigLocal: saveBody, ConfigBytes: 42,
			UpstreamScore: score, UpstreamPingMS: 38, UpstreamSpeedBps: 15_000_000,
			Sessions: 3, UptimeSeconds: 86_400, TotalUsers: 420, TotalTraffic: 1_234_567_890,
			LogType: "No Logging", Operator: "BBTech", Message: "AS1234, Tokyo",
			FirstSeen: time.Now().UTC().Add(-48 * time.Hour), LastSeen: time.Now().UTC(),
		}
	}
	n1 := mk("v1:"+strings.Repeat("1", 64), "vpn-high", "8.8.8.1", "Japan (Tokyo)", "JP", "tcp", 1194, strings.Repeat("a", 64), 900, true)
	n2 := mk("v1:"+strings.Repeat("2", 64), "vpn-mid", "8.8.8.2", "Germany", "DE", "udp", 443, strings.Repeat("b", 64), 500, true)
	// 正文从没拉过：累积池导入的节点就是这样（只有 sha 与端点）。
	n3 := mk("v1:"+strings.Repeat("3", 64), "vpn-noconfig", "8.8.8.3", "Korea (Republic of)", "KR", "tcp", 995, strings.Repeat("c", 64), 100, false)

	agg := &source.Aggregated{
		Nodes:       map[string]*model.Node{n1.ID: n1, n2.ID: n2, n3.ID: n3},
		Configs:     map[string][]byte{},
		CountsByURL: map[string]int{},
	}
	if diff := st.ApplyRefresh(agg, store.Eviction{KeepDays: 7}); diff.Added != 3 {
		t.Fatalf("进池 %d 个", diff.Added)
	}
	return map[string]*model.Node{"high": n1, "mid": n2, "noconfig": n3}
}

func newAPIHarness(t *testing.T, tweak func(*config.Config)) *harness {
	t.Helper()
	return newHarness(t, "对外接口测试", func(c *config.Config) {
		c.API.Enabled = true
		c.API.Token = testAPIToken
		if tweak != nil {
			tweak(c)
		}
	})
}

// apiGet 打对外接口。它的成功响应是 JSON 数组，而 harness 的 do 只认对象
// （界面那套都是 {"ok":...}），所以这里单独发一次、按数组解。
func apiGet(t *testing.T, h *harness, path, bearer string) (int, http.Header, []map[string]any, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", bearer)
	}
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	raw, _ := io.ReadAll(resp.Body)
	var rows []map[string]any
	if err := json.Unmarshal(raw, &rows); err != nil {
		var obj map[string]any
		if err2 := json.Unmarshal(raw, &obj); err2 != nil {
			t.Fatalf("响应既不是数组也不是对象: %v\n%s", err, raw)
		}
		rows = nil
	}
	return resp.StatusCode, resp.Header, rows, string(raw)
}

// 已判定不可达的节点不参与延迟排序（和界面同口径）。EWMA 只由成功样本喂出来、
// 不清空也不按时间衰减，所以「以前很快、现在已挂」的节点不管升降序都会
// 抢到「最快」那一端。
func TestVpngateAPISortPingSkipsDownNodes(t *testing.T) {
	h := newAPIHarness(t, nil)
	seeded := seedAPIPool(t, h.app)
	st := h.app.Store()
	push := func(id string, ok bool, rtt int64, svc string, ago time.Duration) {
		t.Helper()
		if n := st.ApplyProbeResults(map[string]*model.ProbeResult{
			id: {At: time.Now().UTC().Add(-ago), OK: ok, Host: "8.8.8.1", Port: 1194, Proto: "tcp", RTTMS: rtt, Service: svc},
		}, 8); n != 1 {
			t.Fatalf("探测结果没写进去：%d", n)
		}
	}
	// vpn-high：很久以前连上过而且很快（EWMA 40ms），随后连续两次 RST。
	push(seeded["high"].ID, true, 40, model.ServiceSoftEther, 6*time.Hour)
	push(seeded["high"].ID, false, 0, model.ServiceRefused, 3*time.Hour)
	push(seeded["high"].ID, false, 0, model.ServiceRefused, time.Hour)
	// vpn-mid：活着但慢（900ms）。vpn-noconfig 正文不在本地，会被整行跳过。
	push(seeded["mid"].ID, true, 900, model.ServiceSoftEther, time.Hour)

	if n, ok := st.Get(seeded["high"].ID); !ok || n.Health.Level != "down" {
		t.Fatalf("样例节点该是 down：%+v", n.Health)
	}

	for _, dir := range []string{"asc", "desc"} {
		code, _, rows, raw := apiGet(t, h, "/vpngate/api/iphone/?sort=ping&dir="+dir, "Bearer "+testAPIToken)
		if code != http.StatusOK {
			t.Fatalf("dir=%s = %d：%s", dir, code, raw)
		}
		if len(rows) != 2 {
			t.Fatalf("dir=%s 应有 2 行（vpn-noconfig 被跳过），实得 %d：%s", dir, len(rows), raw)
		}
		if rows[0]["HostName"] != "vpn-mid" || rows[1]["HostName"] != "vpn-high" {
			t.Errorf("dir=%s：已挂节点不该拿历史延迟抢位，实得顺序 %v / %v",
				dir, rows[0]["HostName"], rows[1]["HostName"])
		}
	}
}

// 关掉时连「这里有个接口」都不告诉外面：404 而不是 401。
func TestVpngateAPIOffByDefault(t *testing.T) {
	h := newHarness(t, "默认配置", nil) // config.Default()：api.enabled=false
	for _, p := range []string{"/vpngate/api/iphone/", "/vpngate/api/iphone"} {
		code, _, _, raw := apiGet(t, h, p, "Bearer "+testAPIToken)
		if code != http.StatusNotFound {
			t.Errorf("%s = %d，接口没开就该 404，实得响应 %s", p, code, raw)
		}
	}
}

// 口令只走 Authorization / ?key=，跟界面的会话 cookie 完全无关：
// 没登录的调用方照样能拉，登录了但没带 token 的浏览器则不行。
func TestVpngateAPIRequiresToken(t *testing.T) {
	h := newAPIHarness(t, nil)
	seedAPIPool(t, h.app)

	if code, hdr, _, _ := apiGet(t, h, "/vpngate/api/iphone/", ""); code != http.StatusUnauthorized {
		t.Errorf("不带 token = %d，期望 401", code)
	} else if hdr.Get("WWW-Authenticate") == "" {
		t.Error("401 该带 WWW-Authenticate: Bearer，好让 curl/脚本知道该怎么带凭据")
	}
	if code, _, _, _ := apiGet(t, h, "/vpngate/api/iphone/", "Bearer 错的-token"); code != http.StatusUnauthorized {
		t.Errorf("错 token = %d，期望 401", code)
	}
	// 三种带法都得认。
	for name, hdr := range map[string]string{
		"Bearer 头":        "Bearer " + testAPIToken,
		"裸 Authorization": testAPIToken,
	} {
		if code, _, rows, _ := apiGet(t, h, "/vpngate/api/iphone/", hdr); code != http.StatusOK {
			t.Errorf("%s = %d，rows=%d", name, code, len(rows))
		}
	}
	if code, _, rows, _ := apiGet(t, h, "/vpngate/api/iphone/?key="+testAPIToken, ""); code != http.StatusOK {
		t.Errorf("?key= = %d", code)
	} else if len(rows) == 0 {
		t.Error("?key= 拿到了空名单")
	}
	// 界面的会话不该顶替 token。
	h.login()
	resp, _ := h.get("/vpngate/api/iphone/")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("只带会话 cookie = %d，期望 401（这条接口只认 api token）", resp.StatusCode)
	}
}

// 字段名与列顺序必须跟官方表头一致，值也要落在对的列上。
func TestVpngateAPIFieldNamesMatchOfficial(t *testing.T) {
	h := newAPIHarness(t, nil)
	seed := seedAPIPool(t, h.app)

	code, hdr, rows, raw := apiGet(t, h, "/vpngate/api/iphone/?key="+testAPIToken, "")
	if code != http.StatusOK {
		t.Fatalf("状态码 %d: %s", code, raw)
	}
	if !strings.Contains(hdr.Get("Content-Type"), "application/json") {
		t.Errorf("Content-Type = %q", hdr.Get("Content-Type"))
	}
	// 顶层是数组，不带界面那套 {"ok":true} 的壳。
	if !strings.HasPrefix(strings.TrimSpace(raw), "[") {
		t.Errorf("响应顶层不是数组: %.120s", raw)
	}
	// 缺正文的那个被跳过了（带正文列时给空串等于塞个连不上的节点）。
	if len(rows) != 2 {
		t.Fatalf("行数 = %d，期望 2（缺正文的整行跳过）\n%s", len(rows), raw)
	}
	if hdr.Get("X-Vpngate-Agg-Skipped") != "1" {
		t.Errorf("X-Vpngate-Agg-Skipped = %q，期望 1", hdr.Get("X-Vpngate-Agg-Skipped"))
	}
	if hdr.Get("X-Vpngate-Agg-Rows") != "2" || hdr.Get("X-Vpngate-Agg-Total") != "3" {
		t.Errorf("行数/总数头 = %q / %q，期望 2 / 3", hdr.Get("X-Vpngate-Agg-Rows"), hdr.Get("X-Vpngate-Agg-Total"))
	}

	for i, row := range rows {
		if len(row) != len(officialColumns) {
			t.Errorf("第 %d 行有 %d 列，官方是 %d 列: %v", i, len(row), len(officialColumns), keysOf(row))
			continue
		}
		for _, col := range officialColumns {
			if _, ok := row[col]; !ok {
				t.Errorf("第 %d 行缺官方列 %s", i, col)
			}
		}
	}

	// 默认按 Score 从高到低 —— 官方名单就是这个顺序。
	if rows[0]["HostName"] != "vpn-high" || rows[1]["HostName"] != "vpn-mid" {
		t.Errorf("顺序 = %v / %v，期望 Score 降序", rows[0]["HostName"], rows[1]["HostName"])
	}
	if !strings.Contains(raw, `"OpenVPN_ConfigData_Base64"`) {
		t.Error("默认就该带 OpenVPN_ConfigData_Base64 这一列")
	}

	// 每一列的值都取自对应的本地字段，别错位（Score 填成 Ping 这种错最难发现）。
	n := seed["high"]
	r0 := rows[0]
	if r0["IP"] != n.IP || r0["CountryLong"] != n.Country || r0["CountryShort"] != n.CountryCode {
		t.Errorf("身份/国家列错位: %v %v %v", r0["IP"], r0["CountryLong"], r0["CountryShort"])
	}
	want := map[string]int64{
		"Score": n.UpstreamScore, "Ping": n.UpstreamPingMS, "Speed": n.UpstreamSpeedBps,
		"NumVpnSessions": n.Sessions, "Uptime": n.UptimeSeconds,
		"TotalUsers": n.TotalUsers, "TotalTraffic": n.TotalTraffic,
	}
	for k, w := range want {
		got, ok := r0[k].(float64)
		if !ok || int64(got) != w {
			t.Errorf("%s = %v，期望 %d", k, r0[k], w)
		}
	}
	for k, w := range map[string]string{"LogType": n.LogType, "Operator": n.Operator, "Message": n.Message} {
		if got, _ := r0[k].(string); got != w {
			t.Errorf("%s = %q，期望 %q", k, got, w)
		}
	}
	// 自由文本里带逗号不能把列挤位（官方 CSV 的老毛病，JSON 这层要没事）。
	if got, _ := r0["Message"].(string); got != "AS1234, Tokyo" {
		t.Errorf("Message = %q", got)
	}

	// 配置列是本地正文的标准 base64（官方用的就是 std + padding）。
	b64, _ := r0["OpenVPN_ConfigData_Base64"].(string)
	body, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("配置列不是合法 base64: %v", err)
	}
	if disk, ok := h.app.Store().Config(n.ConfigSHA256); !ok || string(disk) != string(body) {
		t.Errorf("配置列与盘上正文不一致: %q", string(body)[:min(40, len(body))])
	}
}

// ?config=0 只要名单；配置里关掉正文列时也不该出现这一列（而不是给空串）。
func TestVpngateAPIConfigColumnToggles(t *testing.T) {
	h := newAPIHarness(t, nil)
	seedAPIPool(t, h.app)

	for _, q := range []string{"config=0", "config=false", "config=off"} {
		_, _, rows, _ := apiGet(t, h, "/vpngate/api/iphone/?key="+testAPIToken+"&"+q, "")
		if len(rows) != 3 {
			t.Fatalf("?%s 行数 = %d，不要正文时不该再跳过缺正文的节点", q, len(rows))
		}
		for i, row := range rows {
			if _, ok := row["OpenVPN_ConfigData_Base64"]; ok {
				t.Errorf("?%s 第 %d 行还带着配置列", q, i)
			}
		}
		if len(rows[0]) != len(officialColumns)-1 {
			t.Errorf("?%s 第 0 行有 %d 列，期望 %d", q, len(rows[0]), len(officialColumns)-1)
		}
	}

	// include_config=false 是运维层面的上限：?config=1 不该把正文要回来。
	h2 := newAPIHarness(t, func(c *config.Config) { c.API.IncludeConfig = false })
	seedAPIPool(t, h2.app)
	for _, q := range []string{"", "config=1", "config=true"} {
		_, _, rows, _ := apiGet(t, h2, "/vpngate/api/iphone/?key="+testAPIToken+"&"+q, "")
		for i, row := range rows {
			if v, ok := row["OpenVPN_ConfigData_Base64"]; ok && fmt.Sprint(v) != "" {
				t.Errorf("include_config=false 时 ?%s 的第 %d 行还带正文（查询参数只能往下关，不能越过配置里的开关）", q, i)
			}
		}
	}
}

// 筛选/排序/翻页复用界面那套参数，参数写错要 422 而不是悄悄给全量。
func TestVpngateAPIFiltersAndPaging(t *testing.T) {
	h := newAPIHarness(t, nil)
	seedAPIPool(t, h.app)
	base := "/vpngate/api/iphone/?key=" + testAPIToken + "&config=0"

	cases := []struct {
		query string
		want  []string // 期望的 HostName 顺序
	}{
		{"&country=JP", []string{"vpn-high"}},
		{"&country=JP,KR", []string{"vpn-high", "vpn-noconfig"}},
		{"&proto=udp", []string{"vpn-mid"}},
		{"&q=noconfig", []string{"vpn-noconfig"}},
		// dir 说的是这一列的值：desc = Score 从大到小（跟界面那个 dir 不是一套口径）。
		{"&sort=score&dir=desc", []string{"vpn-high", "vpn-mid", "vpn-noconfig"}},
		{"&sort=score&dir=asc", []string{"vpn-noconfig", "vpn-mid", "vpn-high"}},
		// 不写 sort/dir 就该跟官方一样：分数高的在前。
		{"", []string{"vpn-high", "vpn-mid", "vpn-noconfig"}},
		{"&sort=speed&dir=asc", nil},
		{"&sort=hostname&dir=asc", []string{"vpn-high", "vpn-mid", "vpn-noconfig"}},
		{"&limit=2&offset=2", []string{"vpn-noconfig"}},
	}
	for _, c := range cases {
		_, hdr, rows, raw := apiGet(t, h, base+c.query, "")
		got := make([]string, 0, len(rows))
		for _, r := range rows {
			got = append(got, r["HostName"].(string))
		}
		if c.want == nil {
			continue
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s 给了 %v，期望 %v\n%s", c.query, got, c.want, raw)
		}
		if hdr.Get("X-Vpngate-Agg-Total") == "" {
			t.Errorf("%s 少了 X-Vpngate-Agg-Total", c.query)
		}
	}

	for _, bad := range []string{"limit=abc", "max_ping=abc", "ping_source=nope", "offset=-1x", "sort=uptime", "sort=总分"} {
		if code, _, _, _ := apiGet(t, h, base+"&"+bad, ""); code != http.StatusUnprocessableEntity {
			t.Errorf("%s = %d，参数写错该 422", bad, code)
		}
	}
}

// 带不带尾斜杠都得通，且查询参数不能被 301 弄丢（不少客户端跳转时会丢）。
func TestVpngateAPIBothPathSpellings(t *testing.T) {
	h := newAPIHarness(t, nil)
	seedAPIPool(t, h.app)

	for _, p := range []string{"/vpngate/api/iphone", "/vpngate/api/iphone/"} {
		code, hdr, rows, raw := apiGet(t, h, p+"?key="+testAPIToken+"&config=0", "")
		if code != http.StatusOK {
			t.Errorf("%s = %d: %s", p, code, raw)
			continue
		}
		if len(rows) != 3 {
			t.Errorf("%s 行数 = %d，期望 3（?config=0 时不跳过缺正文的）", p, len(rows))
		}
		if hdr.Get("X-Vpngate-Agg-Rows") != "3" {
			t.Errorf("%s 的 X-Vpngate-Agg-Rows = %q", p, hdr.Get("X-Vpngate-Agg-Rows"))
		}
	}
}

func TestVpngateAPIRateLimitPerIP(t *testing.T) {
	h := newAPIHarness(t, func(c *config.Config) { c.API.RatePerMinute = 2 })
	seedAPIPool(t, h.app)

	for i := 1; i <= 2; i++ {
		if code, _, _, _ := apiGet(t, h, "/vpngate/api/iphone/?key="+testAPIToken, ""); code != http.StatusOK {
			t.Fatalf("第 %d 次 = %d，限流前两次该放行", i, code)
		}
	}
	code, hdr, _, _ := apiGet(t, h, "/vpngate/api/iphone/?key="+testAPIToken, "")
	if code != http.StatusTooManyRequests {
		t.Fatalf("第 3 次 = %d，期望 429", code)
	}
	if hdr.Get("Retry-After") == "" {
		t.Error("429 该带 Retry-After，脚本才知道要等多久")
	}
	// 401 的请求也计数：否则限流形同虚设，乱猜 token 的循环打不动自己。
	if code, _, _, _ := apiGet(t, h, "/vpngate/api/iphone/", ""); code != http.StatusTooManyRequests {
		t.Errorf("超限后不带 token = %d，期望 429（限流在鉴权之前）", code)
	}
}

// 限流表不能只进不出：伪造 IP 扫一轮就把内存吃定了。
func TestAPIRateWindowResets(t *testing.T) {
	l := newAPIRate()
	if !l.allow("1.2.3.4", 0) {
		t.Error("limit<=0 应当不限流")
	}
	for i := 0; i < 3; i++ {
		if !l.allow("1.2.3.4", 3) {
			t.Fatalf("第 %d 次不该被限", i+1)
		}
	}
	if l.allow("1.2.3.4", 3) {
		t.Error("第 4 次该被限")
	}
	if !l.allow("5.6.7.8", 3) {
		t.Error("换一个 IP 不该受别人的窗口影响")
	}
	// 把窗口推到下一分钟：格子该重来。
	l.mu.Lock()
	for k := range l.slots {
		s := l.slots[k]
		s.minute -= 1
		l.slots[k] = s
	}
	l.mu.Unlock()
	if !l.allow("1.2.3.4", 3) {
		t.Error("换到下一分钟该重新计数")
	}
	l.mu.Lock()
	before := len(l.slots)
	l.lastPrune = time.Now().Add(-5 * time.Minute)
	l.mu.Unlock()
	if !l.allow("9.9.9.9", 3) {
		t.Fatal("清理后仍要正常放行")
	}
	l.mu.Lock()
	_, staleStillThere := l.slots["5.6.7.8"]
	after := len(l.slots)
	l.mu.Unlock()
	if staleStillThere {
		t.Errorf("过期的格子该被清掉（伪造 IP 扫一轮就会把 map 吃定）：%d 格，%q 还在", before, "5.6.7.8")
	}
	if after > before {
		t.Errorf("格子数只增不减：%d → %d", before, after)
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
