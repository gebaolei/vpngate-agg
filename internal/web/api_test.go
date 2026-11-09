package web

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
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

const harnessPassword = "harness-login-pass"

// harness 起一个真的 HTTP 服务（内嵌前端 + 全部接口），但不联网：
// 池子里的数据是自己塞的。
type harness struct {
	t      *testing.T
	ts     *httptest.Server
	app    *app.App
	csrf   string
	cookie *http.Cookie
}

func newHarness(t *testing.T, title string, tweak func(*config.Config)) *harness {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Title = title
	cfg.Auth.Password = harnessPassword
	cfg.Purity.Providers = map[string]bool{"builtin": true, "ipquery": false, "ipinfo": false,
		"scamalytics": false, "abuseipdb": false, "ipregistry": false, "ipqualityscore": false}
	if tweak != nil {
		tweak(&cfg)
	}
	a, err := app.New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("装配 App 失败: %v", err)
	}
	s, err := New(cfg, a, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("装配 Server 失败: %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &harness{t: t, ts: ts, app: a}
}

func (h *harness) login() {
	h.t.Helper()
	if strings.TrimSpace(h.app.Config().Auth.Password) == "" {
		h.t.Fatal("这个 harness 没设口令")
	}
	resp, body := h.do(http.MethodPost, "/api/login", `{"username":"admin","password":"`+harnessPassword+`"}`, nil)
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("登录失败 %d: %v", resp.StatusCode, body)
	}
	for _, c := range resp.Cookies() {
		if c.Name == CookieName {
			h.cookie = c
		}
	}
	if h.cookie == nil {
		h.t.Fatal("登录成功却没发会话 cookie")
	}
	if v, ok := body["csrf"].(string); !ok || v == "" {
		h.t.Fatal("登录响应没带 CSRF token")
	} else {
		h.csrf = v
	}
}

type callOpts struct {
	csrf        string // 覆盖要发的 X-CSRF-Token（"-" 表示不发）
	contentType string // 覆盖 Content-Type
	noCookie    bool
	csrfQuery   bool // 用 ?csrf= 传
	noRedirect  bool // 看 302/307 本身，不跟着跳
}

// do 发一个请求。body 非空时按 JSON 发并默认带上 CSRF token ——
// 这正是前端的调用方式，写错任何一环测试就该红。
func (h *harness) do(method, path, body string, o *callOpts) (*http.Response, map[string]any) {
	h.t.Helper()
	if o == nil {
		o = &callOpts{}
	}
	url := h.ts.URL + path
	if o.csrfQuery && h.csrf != "" {
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		url += sep + "csrf=" + h.csrf
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if body != "" {
		ct := o.contentType
		if ct == "" {
			ct = "application/json"
		}
		if ct != "-" {
			req.Header.Set("Content-Type", ct)
		}
		token := o.csrf
		if token == "" {
			token = h.csrf
		}
		if token != "-" && token != "" {
			req.Header.Set("X-CSRF-Token", token)
		}
	}
	if h.cookie != nil && !o.noCookie {
		req.AddCookie(h.cookie)
	}
	client := h.ts.Client()
	if o.noRedirect {
		c := *client
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &c
	}
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s 请求失败: %v", method, path, err)
	}
	h.t.Cleanup(func() { resp.Body.Close() })
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(raw, &out); err != nil {
			h.t.Fatalf("%s %s 的响应不是 JSON: %v\n%s", method, path, err, raw)
		}
		return resp, out
	}
	return resp, map[string]any{"_raw": string(raw)}
}

func (h *harness) get(path string) (*http.Response, map[string]any) {
	h.t.Helper()
	return h.do(http.MethodGet, path, "", nil)
}

func TestStaticAndSecurityHeaders(t *testing.T) {
	h := newHarness(t, "我的节点池 <script>alert(1)</script>", nil)

	resp, body := h.get("/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("首页 = %d", resp.StatusCode)
	}
	html := rawOf(body)
	// 标题是可配的，但它会被写进 <title>：不转义就等于在登录页上开一个 XSS。
	if strings.Contains(html, "<script>alert(1)") {
		t.Error("标题里的 HTML 没被转义")
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("标题应转义后出现")
	}
	for _, leftover := range []string{"{{ASSET_TAG}}", "{{TITLE}}", "{{VERSION}}"} {
		if strings.Contains(html, leftover) {
			t.Errorf("模板占位符 %s 没被替换", leftover)
		}
	}
	tag := assetTag()
	if !strings.Contains(html, "v="+tag) {
		t.Errorf("页面没带 ?v=%s，改了前端用户还拿旧的", tag)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("首页必须 no-store（它决定要不要重新拉 app.js），实得 %q", got)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}

	// CSP 禁 inline script 是最硬的 XSS 防线；改任何一个来源都要先看这里。
	csp := resp.Header.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "script-src 'self'", "style-src 'self'",
		"connect-src 'self'", "frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP 缺 %q：%q", want, csp)
		}
	}
	if strings.Contains(csp, "cdn.") || strings.Contains(csp, "http:") {
		t.Errorf("CSP 里出现了外部源，内嵌前端不该依赖 CDN: %q", csp)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q", got)
	}
	if got := resp.Header.Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("Referrer-Policy = %q", got)
	}

	// 静态资源：URL 带内容 hash，所以可以 immutable 长缓存。
	resp, _ = h.get("/style.css")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("style.css = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Errorf("style.css 的 Content-Type = %q（MIME 不对浏览器会拒绝应用样式）", ct)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Errorf("静态资源应长缓存: %q", got)
	}
	resp, _ = h.get("/app.js")
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/javascript") {
		t.Errorf("app.js 的 Content-Type = %q（严格 MIME 下不是 JS 就不执行）", ct)
	}
	resp, _ = h.get("/favicon.svg")
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "image/svg") {
		t.Errorf("favicon.svg 的 Content-Type = %q", ct)
	}
	resp, _ = h.get("/favicon.ico")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("favicon.ico = %d", resp.StatusCode)
	}
	// 老的书签/浏览器会自动请 .ico：转到 svg，不必再往二进制里塞一份 ico。
	resp, _ = h.do(http.MethodGet, "/favicon.ico", "", &callOpts{noRedirect: true})
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Errorf("favicon.ico 应 307 到 svg，实得 %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/favicon.svg?v=") {
		t.Errorf("Location = %q", loc)
	}

	// 健康检查不设鉴权，运维探针要用。
	resp, body = h.get("/healthz")
	if resp.StatusCode != http.StatusOK || body["ok"] != true {
		t.Errorf("healthz = %d %v", resp.StatusCode, body)
	}
	if _, ok := body["version"]; !ok {
		t.Error("healthz 要带版本号")
	}
}

// 鉴权与 CSRF 必须在服务端拦死：前端的判断只是体验。
func TestAuthGateOverHTTP(t *testing.T) {
	h := newHarness(t, "gate", nil)

	// 没登录：接口要 401，响应体要能告诉前端「没登录」而不是一个空 body。
	resp, body := h.get("/api/stats")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("未登录访问 /api/stats = %d，期望 401", resp.StatusCode)
	}
	if body["ok"] != false || body["error"] == "" {
		t.Errorf("401 的响应体 = %v，前端要靠 ok/error 切登录视图", body)
	}
	// 静态资源不设鉴权：打开就是登录页，不该多一次跳转。
	if resp, _ := h.get("/"); resp.StatusCode != http.StatusOK {
		t.Errorf("未登录也该能拿到首页，实得 %d", resp.StatusCode)
	}
	// /api/session 是前端启动时第一个调用，它自己就是「有没有会话」的探针。
	resp, body = h.get("/api/session")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("session = %d", resp.StatusCode)
	}
	if body["authed"] != false {
		t.Errorf("未登录时 authed = %v", body["authed"])
	}
	if body["title"] != "gate" || body["asset_tag"] == "" {
		t.Errorf("session 响应要带标题和资源 tag，实得 %v", body)
	}

	// 口令错：401，且错误信息不能告诉攻击者哪个字段对了。
	resp, body = h.do(http.MethodPost, "/api/login", `{"username":"admin","password":"错的"}`, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("错口令登录 = %d", resp.StatusCode)
	}
	if body["ok"] != false || body["error"] == "" {
		t.Errorf("登录失败响应 = %v", body)
	}
	// 请求体不是 JSON：422，不是 500。
	if resp, _ = h.do(http.MethodPost, "/api/login", `{"username":`, nil); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("坏 JSON 登录 = %d，期望 422", resp.StatusCode)
	}

	h.login()

	resp, body = h.get("/api/session")
	if body["authed"] != true || body["username"] != "admin" {
		t.Errorf("登录后 session = %v", body)
	}
	if body["expires"] == nil || body["expires"] == "" {
		t.Error("登录态要带过期时间，界面才好提示「快过期了」")
	}
	if resp, body = h.get("/api/stats"); resp.StatusCode != http.StatusOK || body["ok"] != true {
		t.Errorf("登录后 /api/stats = %d %v", resp.StatusCode, body)
	}

	// 写操作少了 CSRF token 要 403。
	resp, body = h.do(http.MethodPost, "/api/cancel", `{"kind":"probe"}`, &callOpts{csrf: "-"})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("缺 CSRF token 的写请求 = %d，期望 403（响应 %v）", resp.StatusCode, body)
	}
	// token 不对也要 403。
	if resp, _ = h.do(http.MethodPost, "/api/cancel", `{"kind":"probe"}`, &callOpts{csrf: "deadbeef"}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("错误 CSRF token = %d，期望 403", resp.StatusCode)
	}
	// 跨站表单提交能自动带 cookie，但拿不到 JSON 的 Content-Type。
	if resp, _ = h.do(http.MethodPost, "/api/cancel", `kind=probe`, &callOpts{contentType: "application/x-www-form-urlencoded"}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("form-encoded 写请求 = %d，期望 403", resp.StatusCode)
	}
	// ?csrf= 也算（方便手搓 URL 和下载链接）。
	if resp, _ = h.do(http.MethodPost, "/api/cancel", `{"kind":"probe"}`, &callOpts{csrf: "-", csrfQuery: true}); resp.StatusCode != http.StatusOK {
		t.Errorf("?csrf= 传 token 应通过，实得 %d", resp.StatusCode)
	}
	// 读操作不需要 token。
	if resp, _ = h.do(http.MethodGet, "/api/jobs", "", &callOpts{csrf: "-"}); resp.StatusCode != http.StatusOK {
		t.Errorf("GET 不该被 CSRF 拦，实得 %d", resp.StatusCode)
	}

	// 伪造的会话 cookie 要 401，而不是 500。
	fake := h.cookie
	h.cookie = &http.Cookie{Name: CookieName, Value: "bogus.deadbeef"}
	if resp, _ = h.get("/api/stats"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("伪造会话 = %d，期望 401", resp.StatusCode)
	}
	h.cookie = fake

	// 退出登录后 cookie 被清掉，接口要回到 401。
	resp, _ = h.do(http.MethodPost, "/api/logout", `{}`, nil)
	for _, c := range resp.Cookies() {
		if c.Name == CookieName && c.MaxAge >= 0 {
			t.Errorf("logout 没让 cookie 过期: %+v", c)
		}
	}
	h.cookie = nil
	if resp, _ = h.get("/api/stats"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("登出后 = %d，期望 401", resp.StatusCode)
	}
}

// 关掉登录（纯内网自用）时接口默认全开，但写操作仍要 token ——
// 否则本机上任何页面都能跨站戳一下「开始探测」。
func TestDisableAuthStillChecksCSRF(t *testing.T) {
	h := newHarness(t, "noauth", func(c *config.Config) { c.Auth.DisableAuth = true })

	resp, body := h.get("/api/stats")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("关掉登录后 GET /api/stats = %d", resp.StatusCode)
	}
	if body["ok"] != true {
		t.Errorf("响应 = %v", body)
	}
	resp, body = h.get("/api/session")
	if body["authed"] != true || body["csrf"] == "" {
		t.Errorf("关掉登录时 session 也要给 csrf（前端要靠它发写请求）: %v", body)
	}
	token, _ := body["csrf"].(string)

	resp, _ = h.do(http.MethodPost, "/api/cancel", `{"kind":"probe"}`, &callOpts{csrf: "-"})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("关掉登录时缺 token 的写请求 = %d，期望 403", resp.StatusCode)
	}
	h.csrf = token
	if resp, _ = h.do(http.MethodPost, "/api/cancel", `{"kind":"probe"}`, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("带 token 应通过，实得 %d", resp.StatusCode)
	}
}

func TestNodesAPI(t *testing.T) {
	h := newHarness(t, "nodes", nil)
	seedNodes(t, h.app)
	h.login()

	resp, body := h.get("/api/nodes")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("nodes = %d", resp.StatusCode)
	}
	if body["total"].(float64) != 4 {
		t.Errorf("total = %v，期望 4", body["total"])
	}
	items, _ := body["items"].([]any)
	if len(items) != 4 {
		t.Fatalf("items = %d 条", len(items))
	}
	first, _ := items[0].(map[string]any)
	for _, key := range []string{"id", "hostname", "ip", "country_code", "proto", "port", "health", "purity", "upstream_score", "first_seen", "last_seen"} {
		if _, ok := first[key]; !ok {
			t.Errorf("列表项缺字段 %q（表格按这个名字渲染）", key)
		}
	}
	// 可达档位必须后端算好：界面徽章和 ?level= 筛选共用这一个值，
	// 前端自己再推一遍就会出现「显示已挂、按已挂筛不出」。
	if lvl, _ := pathOf(t, first, "health", "level").(string); lvl != "stable" && lvl != "reachable" {
		t.Errorf("实测连通过的节点 health.level = %q（%+v）", lvl, pathOf(t, first, "health"))
	}
	// 列表默认按推荐分排（后端已经把「越大越好」的列归一成升序=好在前，
	// 所以前端默认发 dir=asc 就是最优在前）。
	if body["sort"] != "recommend" || body["desc"] != false {
		t.Errorf("默认排序 = %v desc=%v", body["sort"], body["desc"])
	}
	if first["hostname"] != "vpn-tokyo" {
		t.Errorf("默认首条 = %v，期望实测可达+家宽的那个（health=%v）", first["hostname"], first["health"])
	}

	cases := []struct {
		path string
		want float64
		why  string
	}{
		{"/api/nodes?q=vpn-tokyo", 1, "按节点名搜"},
		{"/api/nodes?q=BBTech", 1, "按运营商搜"},
		{"/api/nodes?q=8.8.8.2", 1, "按 IP 搜"},
		{"/api/nodes?country=JP", 2, "按国家（同 IP 的两个都在日本）"},
		{"/api/nodes?country=jp,de", 3, "多国逗号分隔"},
		{"/api/nodes?country=?", 0, "未知国家这一桶是空的"},
		{"/api/nodes?proto=udp", 1, "按协议"},
		{"/api/nodes?level=untested", 2, "按可达状态"},
		{"/api/nodes?level=down", 1, "按挂了筛"},
		{"/api/nodes?probed=1", 2, "只看测过的"},
		{"/api/nodes?purity_only=1", 2, "只看测过纯净度的（同 IP 的两个都拿到了结论）"},
		{"/api/nodes?min_purity=80", 2, "纯净度下限"},
		{"/api/nodes?max_purity=50", 0, "纯净度上限：没测过的不参与该筛选"},
		{"/api/nodes?residential=1", 1, "只看志愿者家宽"},
		{"/api/nodes?fresh=1", 4, "还在本轮名单里的"},
		{"/api/nodes?ids=v1:" + strings.Repeat("1", 64) + ",v1:" + strings.Repeat("2", 64), 2, "按 ID 批量取"},
		{"/api/nodes?sort=hostname&dir=asc&limit=2", 4, "按名称升序分页（total 不受分页影响）"},
		{"/api/nodes?sort=purity&limit=1", 4, "按纯净度排序不影响 total"},
		{"/api/nodes?max_ping=1000&ping_source=local", 1, "本地实测延迟筛选（只有一个测出过延迟）"},
		{"/api/nodes?max_ping=1000&ping_source=upstream", 3, "官方 Ping 口径下四个都有数，但已判定不可达的那个不参与延迟筛选"},
		{"/api/nodes?max_ping=1000&ping_source=upstream&level=down", 0, "已挂节点不管哪个延迟口径都不在 max_ping 里"},
	}
	for _, c := range cases {
		resp, body := h.get(c.path)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s = %d（%s）", c.path, resp.StatusCode, c.why)
			continue
		}
		if got := body["total"].(float64); got != c.want {
			t.Errorf("%s 筛出 %.0f 条，期望 %.0f（%s）", c.path, got, c.want, c.why)
		}
	}
	// 分页只影响 items，不影响 total。
	resp, body = h.get("/api/nodes?limit=2&offset=3")
	if items, _ := body["items"].([]any); len(items) != 1 {
		t.Errorf("offset=3&limit=2 给了 %d 条", len(items))
	}

	for _, bad := range []string{"/api/nodes?limit=abc", "/api/nodes?min_purity=x", "/api/nodes?ping_source=随便", "/api/nodes?offset=abc", "/api/nodes?max_ping=慢"} {
		if resp, _ := h.get(bad); resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("%s = %d，参数不对该 422", bad, resp.StatusCode)
		}
	}

	// 详情：带推荐分、同 IP 节点、配置预览。
	resp, body = h.get("/api/nodes/v1:" + strings.Repeat("1", 64))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("详情 = %d", resp.StatusCode)
	}
	nodeMap, _ := body["node"].(map[string]any)
	if nodeMap == nil || nodeMap["hostname"] != "vpn-tokyo" {
		t.Fatalf("详情里的 node = %v", body["node"])
	}
	if body["recommend"] == nil {
		t.Error("详情要给推荐分")
	}
	if preview, _ := body["config_preview"].(string); !strings.Contains(preview, "remote 8.8.8.1") {
		t.Errorf("配置预览没带上正文: %v", body["config_preview"])
	}
	if body["config_local"] != true {
		t.Errorf("正文在本地就该标 config_local=true")
	}
	sibs, _ := body["same_ip"].([]any)
	if len(sibs) != 1 {
		t.Errorf("同 IP 节点应列出 1 个，实得 %v", body["same_ip"])
	}

	// 列表要把每个来源的原始响应剥掉（那是纯净度里最大的一块），
	// 详情里再给全 —— 否则一次列表就是几百 KB。
	resp, body = h.get("/api/nodes?q=vpn-tokyo")
	items, _ = body["items"].([]any)
	listItem, _ := items[0].(map[string]any)
	listPurity, _ := listItem["purity"].(map[string]any)
	if listPurity == nil {
		t.Fatal("列表里的节点该带纯净度结论")
	}
	listProviders, _ := listPurity["providers"].([]any)
	if len(listProviders) != 1 {
		t.Fatalf("列表里的来源明细 = %v", listPurity["providers"])
	}
	if p0, _ := listProviders[0].(map[string]any); p0["raw"] != nil {
		t.Errorf("列表里的纯净度原始响应没剥掉: %v", p0["raw"])
	}
	resp, body = h.get("/api/nodes/v1:" + strings.Repeat("1", 64))
	detailNode, _ := body["node"].(map[string]any)
	detailPurity, _ := detailNode["purity"].(map[string]any)
	detailProviders, _ := detailPurity["providers"].([]any)
	if p0, _ := detailProviders[0].(map[string]any); p0["raw"] == nil {
		t.Error("详情里要留着原始响应给用户核对「谁说了什么」")
	}

	for _, bad := range []string{"/api/nodes/不存在", "/api/nodes/v1:zz", "/api/nodes/v1:" + strings.Repeat("9", 64)} {
		if resp, _ := h.get(bad); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s = %d，不存在该 404", bad, resp.StatusCode)
		}
	}
}

func TestConfigDownloadAndExport(t *testing.T) {
	h := newHarness(t, "export", nil)
	seedNodes(t, h.app)
	h.login()

	resp, body := h.get("/api/nodes/v1:" + strings.Repeat("1", 64) + "/config")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("下载配置 = %d (%v)", resp.StatusCode, body["_raw"])
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "openvpn-profile") {
		t.Errorf("Content-Type = %q", ct)
	}
	// hostname 里的奇怪字符要被换掉：文件名不能带引号或路径分隔符。
	cd := resp.Header.Get("Content-Disposition")
	if !strings.Contains(cd, "vpn-tokyo") || strings.Contains(cd, `" vpn`) {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if !strings.Contains(rawOf(body), "remote 8.8.8.1 1194 tcp") {
		t.Errorf("下载的正文不对: %.80s", rawOf(body))
	}

	// ovpn 导出：按 ids 导出，中间用分隔行；取不到的要写清楚。
	resp, body = h.get("/api/export?ids=v1:" + strings.Repeat("1", 64) + ",v1:" + strings.Repeat("2", 64) + ",v1:" + strings.Repeat("f", 64))
	ovpn := rawOf(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("导出 = %d", resp.StatusCode)
	}
	// 分隔行本身在头部说明里也出现一次，所以数「带节点名的分隔行」。
	if n := strings.Count(ovpn, "# ==== vpn"); n != 2 {
		t.Errorf("导出里有 %d 个分隔块，期望 2 个", n)
	}
	if !strings.Contains(ovpn, "client") || !strings.Contains(ovpn, "remote 8.8.8.2 443 udp") {
		t.Errorf("导出内容缺配置正文: %.120s", ovpn)
	}
	if !strings.Contains(ovpn, "取不到配置的节点") {
		t.Error("取不到配置的节点要在结尾列出来，否则用户以为导出全成功了")
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, ".ovpn") {
		t.Errorf("Content-Disposition = %q", cd)
	}

	// 不指定 ids 时按当前筛选导出一批（「筛完直接导出」不用再全选）。
	if resp, body = h.get("/api/export?country=DE"); resp.StatusCode != http.StatusOK || strings.Count(rawOf(body), "# ==== vpn") != 1 {
		t.Errorf("按筛选导出 = %d / %d 块", resp.StatusCode, strings.Count(rawOf(body), "# ==== vpn"))
	}

	resp, body = h.get("/api/export?format=json&ids=v1:" + strings.Repeat("1", 64) + ",v1:" + strings.Repeat("f", 64))
	if resp.StatusCode != http.StatusOK || body["ok"] != true {
		t.Fatalf("json 导出 = %d %v", resp.StatusCode, body)
	}
	nodesOut, _ := body["nodes"].([]any)
	if len(nodesOut) != 1 {
		t.Errorf("nodes = %d 条，期望 1 条（不存在的进 missing）", len(nodesOut))
	}
	if entry, _ := nodesOut[0].(map[string]any); entry["config"] == "" {
		t.Error("json 导出要带配置正文")
	}
	missing, _ := body["missing"].([]any)
	if len(missing) != 1 {
		t.Errorf("missing = %v", body["missing"])
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, ".json") {
		t.Errorf("Content-Disposition = %q", cd)
	}

	if resp, _ := h.get("/api/export?format=xml"); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("未知 format = %d，期望 422", resp.StatusCode)
	}
	tooMany := "/api/export?ids=" + strings.TrimSuffix(strings.Repeat("v1:"+strings.Repeat("1", 64)+",", 501), ",")
	if resp, _ := h.get(tooMany); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("超过 500 个 = %d，期望 422", resp.StatusCode)
	}
}

func TestSettingsMasksAPIKeys(t *testing.T) {
	h := newHarness(t, "settings", func(c *config.Config) {
		c.Purity.Keys = map[string]string{"ipinfo": "secret-token-123", "abuseipdb": "short"}
	})
	h.login()

	resp, body := h.get("/api/settings")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("settings = %d", resp.StatusCode)
	}
	if dumpJSON(body) == "" || strings.Contains(dumpJSON(body), "secret-token-123") {
		t.Error("API key 明文回到前端了 —— 界面上「显示」按钮不该把 key 整串带出来")
	}
	keys, _ := pathOf(t, body, "purity_keys").(map[string]any)
	if keys["ipinfo"] == "secret-token-123" {
		t.Errorf("ipinfo key = %v", keys["ipinfo"])
	}
	if keys["abuseipdb"] == nil {
		t.Error("abuseipdb 的 key 也要回显（短 key 整个打星）")
	}
	// purity.keys 是同一个配置的原始位置，也必须已被脱敏（前端另一处读它）。
	if got, ok := pathOf(t, body, "purity", "keys").(map[string]any); !ok || got["ipinfo"] == nil || got["ipinfo"] == "secret-token-123" {
		t.Errorf("purity.keys = %v，期望是脱敏后的值", pathOf(t, body, "purity", "keys"))
	}
	for _, key := range []string{"sources", "probe", "purity", "purity_providers", "data_dir", "version", "config_path"} {
		if _, ok := body[key]; !ok {
			t.Errorf("设置响应缺 %q", key)
		}
	}
	// 设置页的源卡片要三个源都在，字段名要跟前端对上。
	sources, _ := pathOf(t, body, "sources").(map[string]any)
	for _, name := range []string{"vpngate", "mirrors", "cdn"} {
		if _, ok := sources[name].(map[string]any); !ok {
			t.Errorf("sources 里缺 %s", name)
		}
	}
	if _, ok := pathOf(t, body, "sources", "vpngate").(map[string]any)["enabled"]; !ok {
		t.Error("sources.vpngate.enabled 要有（开关显示靠它）")
	}
}

func TestJobsAndHealthReflectStore(t *testing.T) {
	h := newHarness(t, "jobs", nil)
	seedNodes(t, h.app)
	h.login()

	resp, body := h.get("/api/jobs")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jobs = %d", resp.StatusCode)
	}
	if _, ok := body["jobs"].(map[string]any); !ok {
		t.Errorf("jobs 字段缺失: %v", body)
	}
	if _, ok := body["running"].([]any); !ok {
		t.Errorf("running 必须是数组（前端直接 .map）: %v", body["running"])
	}
	if _, ok := body["meta"].(map[string]any); !ok {
		t.Error("meta 要有")
	}

	resp, body = h.get("/api/stats")
	stats, _ := pathOf(t, body, "stats").(map[string]any)
	if stats == nil {
		t.Fatal("stats 缺失")
	}
	if stats["nodes"].(float64) != 4 {
		t.Errorf("stats.nodes = %v", stats["nodes"])
	}
	if _, ok := pathOf(t, body, "countries").([]any); !ok {
		t.Error("countries 必须是数组（国家下拉用它）")
	}
	if _, ok := pathOf(t, body, "purity", "providers").([]any); !ok {
		t.Error("purity.providers 要有（设置页的来源健康表）")
	}
	if _, ok := body["running"].([]any); !ok {
		t.Error("running 要有")
	}
	resp, body = h.get("/healthz")
	if body["nodes"].(float64) != 4 {
		t.Errorf("healthz.nodes = %v", body["nodes"])
	}
}

// SSE 是界面上唯一的实时通道：没登录不该能连上（它会长期占一个连接）。
func TestEventsEndpoint(t *testing.T) {
	h := newHarness(t, "sse", nil)
	h.login()

	// 先投一条：新订阅者会收到最近的事件，这样断言不依赖时序。
	h.app.Bus().Publish("probe:progress", map[string]any{"done": 7, "total": 10})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.ts.URL+"/api/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.AddCookie(h.cookie)
	resp, err := h.ts.Client().Do(req)
	if err != nil {
		t.Fatalf("连 SSE 失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SSE = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q", ct)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
		t.Errorf("SSE 不该被缓存: %q", got)
	}
	if got := resp.Header.Get("X-Accel-Buffering"); got != "no" {
		t.Error("SSE 必须带 X-Accel-Buffering: no，否则 Nginx 会把响应缓冲住，进度条就不实时了")
	}
	// 首条要是 hello（前端靠它确认通道活着），紧接着是订阅时的补发。
	sc := bufio.NewScanner(resp.Body)
	deadline := time.Now().Add(3 * time.Second)
	seen := map[string]bool{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "data: ") {
			payload := strings.TrimPrefix(line, "data: ")
			if strings.Contains(payload, `"type":"hello"`) {
				seen["hello"] = true
			}
			if strings.Contains(payload, "probe:progress") {
				seen["progress"] = true
			}
		}
		if seen["hello"] && seen["progress"] {
			break
		}
		if time.Now().After(deadline) {
			break
		}
	}
	if !seen["hello"] {
		t.Errorf("没读到首条 hello 事件（前端靠它关掉「连接中」提示）")
	}
	if !seen["progress"] {
		t.Error("订阅时的补发没生效：刷新页面就看不到正在跑的任务进度")
	}

	// 没登录不该能连上。
	h.cookie = nil
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	req2, _ := http.NewRequestWithContext(ctx2, http.MethodGet, h.ts.URL+"/api/events", nil)
	resp2, err := h.ts.Client().Do(req2)
	if err != nil {
		t.Fatalf("未登录连 SSE: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("未登录连 SSE = %d，期望 401", resp2.StatusCode)
	}
}

/* ---------------- 塞数据 ---------------- */

// seedNodes 造 4 个节点：一个实测可达+家宽+有正文，一个明确挂了，
// 一个同 IP 的兄弟节点，一个没测过的。覆盖列表/详情/导出要走的分支。
func seedNodes(t *testing.T, a *app.App) {
	t.Helper()
	st := a.Store()
	mk := func(id, host, ip, country, code, proto string, port int, sha string) *model.Node {
		if err := st.SaveConfig(sha, []byte("client\nremote "+ip+" "+strconv.Itoa(port)+" "+proto+"\ntls-client\nkey-direction 1\n")); err != nil {
			t.Fatal(err)
		}
		return &model.Node{
			ID: id, HostName: host, IP: ip, Server: ip, Port: port, Proto: proto,
			Country: country, CountryCode: code,
			ConfigSHA256: sha, ConfigLocal: true, ConfigBytes: 60,
			UpstreamScore: 300, UpstreamPingMS: 120, UpstreamSpeedBps: 50_000_000,
			FirstSeen: time.Now().UTC().Add(-48 * time.Hour), LastSeen: time.Now().UTC(),
		}
	}
	n1 := mk("v1:"+strings.Repeat("1", 64), "vpn-tokyo", "8.8.8.1", "Japan (Tokyo)", "JP", "tcp", 1194, strings.Repeat("a", 64))
	n1.Operator = "BBTech" // 只给一个节点设运营商，才能测「按运营商搜」只命中它
	n2 := mk("v1:"+strings.Repeat("2", 64), "vpn-seoul", "8.8.8.2", "Korea (Republic of)", "KR", "udp", 443, strings.Repeat("b", 64))
	n3 := mk("v1:"+strings.Repeat("3", 64), "vpn-same-ip", "8.8.8.1", "Japan (Tokyo)", "JP", "tcp", 995, strings.Repeat("c", 64))
	n4 := mk("v1:"+strings.Repeat("4", 64), "vpn-berlin", "8.8.8.3", "Germany", "DE", "tcp", 443, strings.Repeat("d", 64))

	agg := &source.Aggregated{
		Nodes:       map[string]*model.Node{n1.ID: n1, n2.ID: n2, n3.ID: n3, n4.ID: n4},
		Configs:     map[string][]byte{},
		CountsByURL: map[string]int{},
	}
	st.ApplyRefresh(agg, store.Eviction{KeepDays: 7})

	// n1 实测可达（家宽判定由 app 层写，这里直接写结论）；n2 连拒两次。
	if n := st.ApplyProbeResults(map[string]*model.ProbeResult{
		n1.ID: {At: time.Now().UTC().Add(-time.Hour), OK: true, Host: n1.IP, Port: n1.Port, Proto: n1.Proto, RTTMS: 60, Service: model.ServiceSoftEther},
		n2.ID: {At: time.Now().UTC().Add(-2 * time.Hour), OK: false, Host: n2.IP, Port: n2.Port, Proto: n2.Proto, Service: model.ServiceRefused},
	}, 8); n != 2 {
		t.Fatalf("探测结果写入 %d 条", n)
	}
	st.ApplyProbeResults(map[string]*model.ProbeResult{
		n2.ID: {At: time.Now().UTC().Add(-time.Hour), OK: false, Host: n2.IP, Port: n2.Port, Proto: n2.Proto, Service: model.ServiceRefused},
	}, 8)

	yes := true
	st.SetResidential(n1.ID, yes)
	st.ApplyPurity(&model.PurityResult{
		IP: "8.8.8.1", CheckedAt: time.Now().UTC(), Score: 92, Level: model.PurityExcellent,
		IPType: model.TypeResidential, TypeLabel: "住宅宽带", Confidence: 100, TTLHours: 72,
		ASN: "AS9405", Org: "BB Tech", Reasons: []string{"两个来源都判为住宅宽带"},
		Providers: []model.ProviderVerdict{{
			Name: "ipquery", OK: true, Raw: []byte(`{"type":"isp","org":"BB Tech"}`),
			Factors: model.PurityFactors{Datacenter: boolp(false)},
		}},
	})
}

func boolp(v bool) *bool { return &v }

// dumpJSON 把响应体压成一行，用于「整个响应里不该出现明文 key」这类断言。
func dumpJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// rawOf 取非 JSON 响应的正文（do 里已经读完了，不能再读第二次）。
func rawOf(body map[string]any) string {
	s, _ := body["_raw"].(string)
	return s
}

// pathOf 按名字往下取字段，取不到就报错（比一串类型断言可读）。
func pathOf(t *testing.T, v any, keys ...string) any {
	t.Helper()
	cur := v
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("取 %q 时当前值不是对象，而是 %T", k, cur)
		}
		cur, ok = m[k]
		if !ok {
			t.Fatalf("响应里没有字段 %q", k)
		}
	}
	return cur
}

// 来源开关必须真的生效并写回文件：界面上点了开关，用户指望下一轮就不拉这个源。
func TestSettingsUpdateToggles(t *testing.T) {
	h := newHarness(t, "开关测试", nil)
	h.login()

	resp, body := h.get("/api/settings")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/settings = %d", resp.StatusCode)
	}
	src := body["sources"].(map[string]any)
	if src["cdn"].(map[string]any)["enabled"] != false {
		t.Errorf("第三方名单（vpngate-list-mirror）默认应关着，实际 %v", src["cdn"])
	}
	if src["keep_vpngate_own"] != false {
		t.Errorf("自营机房节点（public-vpn-* / 自营网段）默认应不保留，实际 %v", src["keep_vpngate_own"])
	}
	if src["mirrors"].(map[string]any)["max_mirrors"].(float64) != 0 {
		t.Errorf("官方镜像站默认应「每轮全抓」，实际 max_mirrors=%v", src["mirrors"])
	}

	// 开第三方名单：没提的字段不能被顺手关掉。
	resp, body = h.do(http.MethodPost, "/api/settings",
		`{"cdn_enabled":true,"cdn_pool_enabled":false,"keep_vpngate_own":true}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/settings = %d: %v", resp.StatusCode, body)
	}
	src = body["sources"].(map[string]any)
	cdn := src["cdn"].(map[string]any)
	if cdn["enabled"] != true || cdn["use_pool"] != false {
		t.Errorf("CDN 开关没写进响应: %v", cdn)
	}
	if src["vpngate"].(map[string]any)["enabled"] != true {
		t.Errorf("没提的官方主站被改掉了: %v", src["vpngate"])
	}
	if src["keep_vpngate_own"] != true {
		t.Errorf("保留自营机房节点的开关没写进响应: %v", src["keep_vpngate_own"])
	}

	// 开关要能关回去：关掉以后下一轮刷新会把池里已有的自营节点清掉。
	resp, body = h.do(http.MethodPost, "/api/settings", `{"keep_vpngate_own":false}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("关掉自营机房开关 = %d: %v", resp.StatusCode, body)
	}
	if got := body["sources"].(map[string]any)["keep_vpngate_own"]; got != false {
		t.Errorf("自营机房开关关不掉，回的是 %v", got)
	}

	// 再 GET 一次：App 里那份配置真的换了，不是只回了个好看的响应。
	_, body = h.get("/api/settings")
	src = body["sources"].(map[string]any)
	if src["cdn"].(map[string]any)["enabled"] != true {
		t.Errorf("改完再读，CDN 还是 %v", src["cdn"])
	}
	// 改完要落盘，否则一重启开关就回到旧值。harness 没给 -config，所以落在数据目录里。
	path, _ := body["config_path"].(string)
	if path == "" {
		t.Error("改完开关后 config_path 仍是空，说明没写回文件")
	} else if _, err := os.Stat(path); err != nil {
		t.Errorf("配置文件没写出来: %v", err)
	}

	// 数值项：三类配置里的「最长缺席天数 / 最大失败次数」「探测间隔 / 并发 / 两个超时」
	// 「纯净度限流」都要能改，并且回包里就是新值。
	resp, body = h.do(http.MethodPost, "/api/settings",
		`{"keep_days":30,"purge_fail_rounds":5,"probe_interval_minutes":120,`+
			`"probe_concurrency":128,"probe_tcp_timeout_seconds":8,"probe_udp_timeout_seconds":6,"purity_rpm":90}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("改数值项 = %d: %v", resp.StatusCode, body)
	}
	src = body["sources"].(map[string]any)
	if src["keep_days"].(float64) != 30 || src["purge_fail_rounds"].(float64) != 5 {
		t.Errorf("节点配置没写进去: keep_days=%v purge_fail_rounds=%v", src["keep_days"], src["purge_fail_rounds"])
	}
	pr := body["probe"].(map[string]any)
	if pr["interval_minutes"].(float64) != 120 || pr["concurrency"].(float64) != 128 ||
		pr["tcp_timeout_seconds"].(float64) != 8 || pr["udp_timeout_seconds"].(float64) != 6 {
		t.Errorf("探测参数没写进去: %v", pr)
	}
	if pu := body["purity"].(map[string]any); pu["requests_per_minute"].(float64) != 90 {
		t.Errorf("纯净度限流没写进去: %v", pu["requests_per_minute"])
	}

	// 越界的数值要 422，而且不能把一半改动留在配置里。
	for _, bad := range []string{`{"keep_days":0}`, `{"keep_days":500}`, `{"probe_concurrency":99999}`, `{"purity_rpm":-5}`} {
		resp, body = h.do(http.MethodPost, "/api/settings", bad, nil)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("%s = %d，期望 422: %v", bad, resp.StatusCode, body)
		}
	}
	_, body = h.get("/api/settings")
	if src = body["sources"].(map[string]any); src["keep_days"].(float64) != 30 {
		t.Errorf("被拒的补丁动到了配置: keep_days=%v", src["keep_days"])
	}

	// 官方主站是必开来源：界面没有这个开关，接口也不接受把它关掉。
	// 镜像 + 第三方同时关掉是允许的（只剩主站约 100 个节点，仍然能拉到新节点）。
	resp, body = h.do(http.MethodPost, "/api/settings",
		`{"vpngate_enabled":false,"mirrors_enabled":false,"cdn_enabled":false}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("关掉镜像和第三方 = %d，期望 200: %v", resp.StatusCode, body)
	}
	src = body["sources"].(map[string]any)
	if src["vpngate"].(map[string]any)["enabled"] != true {
		t.Error("官方主站被关掉了：接口不该接受 vpngate_enabled=false")
	}
	if src["mirrors"].(map[string]any)["enabled"] != false || src["cdn"].(map[string]any)["enabled"] != false {
		t.Errorf("镜像 / 第三方没关掉: %v", src)
	}
	if resp, _ = h.do(http.MethodPost, "/api/settings", `{"mirrors_enabled":true}`, nil); resp.StatusCode != http.StatusOK {
		t.Errorf("恢复镜像开关失败 = %d", resp.StatusCode)
	}

	// 和别的写接口一样要 CSRF。
	resp, _ = h.do(http.MethodPost, "/api/settings", `{"cdn_enabled":false}`, &callOpts{csrf: "-"})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("缺 CSRF = %d，期望 403", resp.StatusCode)
	}
	// 非法 JSON 是请求格式问题，给 400 而不是 422。
	resp, _ = h.do(http.MethodPost, "/api/settings", `{`, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("非法 JSON = %d，期望 400", resp.StatusCode)
	}
	// 未登录改不了。
	resp, _ = h.do(http.MethodPost, "/api/settings", `{"cdn_enabled":true}`, &callOpts{noCookie: true})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("未登录改开关 = %d，期望 401", resp.StatusCode)
	}
}
