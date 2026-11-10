package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/app"
	"github.com/gebaolei/vpngate-agg/internal/config"
	"github.com/gebaolei/vpngate-agg/internal/model"
	"github.com/gebaolei/vpngate-agg/internal/store"
)

// 本文件是全部 JSON 接口。约定：
//   - 响应一律 {"ok":bool,...}；错误带 error 字段
//   - 401 未登录、403 CSRF、404 不存在、409 已有同类任务在跑、422 参数不对
//   - 长任务（刷新/探测/纯净度）立即返回，进展走 /api/events 的 SSE

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"nodes":   s.app.Store().Count(),
		"version": Version,
		"dirty":   s.app.Store().Dirty(),
	})
}

// handleSession 是前端启动时第一个调用：判断有没有会话、拿 CSRF token。
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"auth_disabled": s.app.Config().Auth.DisableAuth,
		"title":         s.cfg.Title,
		"version":       Version,
		"asset_tag":     s.staticTag,
	}
	if s.auth.Disabled() {
		out["authed"] = true
		out["username"] = s.auth.Username()
		out["csrf"] = s.auth.CSRF("disabled")
		writeOK(w, out)
		return
	}
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		out["authed"] = false
		writeOK(w, out)
		return
	}
	sess, ok := s.auth.ParseSession(c.Value)
	if !ok {
		out["authed"] = false
		writeOK(w, out)
		return
	}
	out["authed"] = true
	out["username"] = sess.User
	out["csrf"] = s.auth.CSRF(c.Value)
	out["expires"] = time.Unix(sess.Exp, 0).UTC()
	writeOK(w, out)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	ip := realIP(r)
	val, exp, err := s.auth.Login(body.Username, body.Password, ip)
	if err != nil {
		// 401 而不是 403：让前端的登录表单能区分「口令错」和「没权限」。
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.auth.SetSessionCookie(w, val, exp)
	writeOK(w, map[string]any{
		"username": s.auth.Username(),
		"csrf":     s.auth.CSRF(val),
		"expires":  exp,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.auth.ClearSessionCookie(w)
	writeOK(w, map[string]any{})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current string `json:"current"`
		Next    string `json:"next"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err := s.auth.ChangePassword(body.Current, body.Next); err != nil {
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	writeOK(w, map[string]any{"updated": true})
}

// handleStats 给仪表盘头部：汇总数字、国家分布、任务状态、来源健康。
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st := s.app.Store()
	meta := st.Meta()
	writeOK(w, map[string]any{
		"stats":           st.Stats(),
		"countries":       st.Countries(),
		"jobs":            st.Jobs(),
		"sources":         meta.SourceStats,
		"mirrors":         meta.Mirrors,
		"mirrors_fetched": meta.MirrorsFetched,
		"max_nodes":       s.app.Config().Sources.MaxNodes, // 0 = 不限；界面拿它跟 pool_nodes 对比
		"running":         s.app.Running(),
		"purity": map[string]any{
			"providers":  s.app.Purity().Stats(),
			"enabled":    s.app.Purity().Enabled(),
			"cache_size": s.app.Purity().CacheSize(),
		},
		"last_save":      st.LastSave(),
		"sources_config": sourcesSummary(s.cfg),
	})
}

// handleNodes 是列表接口。参数见 parseFilter。
func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	f, err := parseFilter(r)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	res := s.app.Store().List(f)
	items := make([]*model.Node, 0, len(res.Items))
	for _, n := range res.Items {
		items = append(items, slimNode(n))
	}
	writeOK(w, map[string]any{
		"total":  res.Total,
		"offset": res.Offset,
		"limit":  res.Limit,
		"items":  items,
		"sort":   f.Sort,
		"desc":   f.Desc,
	})
}

func (s *Server) handleNodeDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, ok := s.app.Store().Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	out := map[string]any{"node": n, "recommend": store.RecommendScore(n, "best")}
	// 配置正文只在本地有时给个预览；没有就标出来，让界面显示「点开时按需拉取」。
	if cfg, ok := s.app.Store().Config(n.ConfigSHA256); ok {
		preview := string(cfg)
		if len(preview) > 4000 {
			out["config_preview"] = preview[:4000]
			out["config_truncated"] = true
		} else {
			out["config_preview"] = preview
		}
		out["config_local"] = true
	} else {
		out["config_local"] = false
	}
	// 同一 IP 上的其他节点：纯净度是按 IP 查的，这几个共享同一份结论。
	sibs := s.app.Store().NodesWithIP(n.IP)
	var same []map[string]any
	for _, sid := range sibs {
		if sid == id {
			continue
		}
		if o, ok := s.app.Store().Get(sid); ok {
			same = append(same, map[string]any{"id": o.ID, "hostname": o.HostName, "port": o.Port, "proto": o.Proto, "country_code": o.CountryCode})
		}
	}
	out["same_ip"] = same
	writeOK(w, out)
}

// handleConfig 下载一份 .ovpn。累积池节点会在这里按需拉取，所以给了 30 秒。
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, ok := s.app.Store().Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	cfg, err := s.app.EnsureConfig(ctx, id)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "取配置失败: "+err.Error())
		return
	}
	name := safeName(n.HostName) + "-" + short(n.ConfigSHA256) + ".ovpn"
	w.Header().Set("Content-Type", "application/x-openvpn-profile; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Cache-Control", "private, max-age=300")
	_, _ = w.Write(cfg)
}

func (s *Server) handleProbeOne(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	res, err := s.app.ProbeOne(ctx, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	n, _ := s.app.Store().Get(id)
	writeOK(w, map[string]any{"probe": res, "node": n})
}

func (s *Server) handlePurityOne(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		Force bool `json:"force"`
	}
	// 这个接口允许空 body（界面上直接点按钮），解析失败按默认走。
	_ = decodeJSON(r, &body)
	n, ok := s.app.Store().Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "节点不存在")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res, err := s.app.CheckPurityForNode(ctx, id, body.Force)
	if res == nil {
		writeErr(w, http.StatusBadGateway, "纯净度检测失败: "+errOr(err, "未知错误"))
		return
	}
	code := http.StatusOK
	if err != nil {
		// 有部分来源失败：仍然给结论，但把 err 带上，界面要显示「不完整」。
		code = http.StatusOK
	}
	writeJSON(w, code, map[string]any{"ok": true, "purity": res, "node": n, "warning": errOr(err, "")})
}

// handleRefresh / handleProbe / handlePurity 都是「后台跑，立刻返回」。
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	go func() {
		if _, err := s.app.Refresh(context.Background()); err != nil {
			s.log.Printf("[web] 手动刷新失败: %v", err)
		}
	}()
	writeOK(w, map[string]any{"started": true})
}

func (s *Server) handleProbe(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Limit       int      `json:"limit"`
		Selection   string   `json:"selection"`
		Countries   []string `json:"countries"`
		Protocols   []string `json:"protocols"`
		IDs         []string `json:"ids"`
		Force       bool     `json:"force"`
		Fast        bool     `json:"fast"` // 只测 TCP 握手，不做 OpenVPN 握手
		Concurrency int      `json:"concurrency"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if len(body.IDs) > 2000 {
		writeErr(w, http.StatusUnprocessableEntity, "一次最多指定 2000 个节点")
		return
	}
	o := app.ProbeOptions{
		Limit: body.Limit, Selection: body.Selection, Countries: body.Countries,
		Protocols: body.Protocols, IDs: body.IDs, Force: body.Force, Concurrency: body.Concurrency,
	}
	if body.Fast {
		f := false
		o.Handshake = &f
	}
	// 预估先算：界面要知道「本轮到底会测几个、跳过了什么」，
	// 而不是点完按钮看着进度条从 0 慢慢猜。
	targets, skipped := s.app.Targets(o)
	go func() {
		if _, err := s.app.ProbeRound(context.Background(), o); err != nil {
			s.log.Printf("[web] 手动探测失败: %v", err)
		}
	}()
	writeOK(w, map[string]any{"started": true, "targets": len(targets), "skipped": skipped})
}

func (s *Server) handlePurity(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Limit     int      `json:"limit"`
		Selection string   `json:"selection"`
		Countries []string `json:"countries"`
		IPs       []string `json:"ips"`
		Force     bool     `json:"force"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	o := app.PurityOptions{Limit: body.Limit, Selection: body.Selection, Countries: body.Countries, IPs: body.IPs, Force: body.Force}
	go func() {
		if _, err := s.app.PurityScan(context.Background(), o); err != nil {
			s.log.Printf("[web] 手动纯净度扫描失败: %v", err)
		}
	}()
	writeOK(w, map[string]any{"started": true, "sources": s.app.Purity().Enabled()})
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Kind string `json:"kind"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	switch body.Kind {
	case "refresh", "probe", "purity":
	default:
		writeErr(w, http.StatusUnprocessableEntity, "kind 只能是 refresh/probe/purity")
		return
	}
	// 先回再取消：handler 里同步取消会让响应等到任务清理完才发出去。
	go s.app.Cancel(body.Kind)
	writeOK(w, map[string]any{"cancelling": body.Kind})
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{
		"jobs":    s.app.Store().Jobs(),
		"running": s.app.Running(),
		"meta":    s.app.Store().Meta(),
	})
}

// handleSettings 回显配置（API key 只给掩码），界面据此渲染设置页。
// 改开关走 POST /api/settings（见 handleSettingsUpdate）；路由按方法分开，
// 这里就不用再判一遍 r.Method。
func (s *Server) handleSettings(w http.ResponseWriter, _ *http.Request) {
	writeOK(w, s.settingsPayload(s.app.Config()))
}

// settingsPayload 组装设置页要的那摞参数。GET 和 POST 都走这里，密钥掩码只做一次，
// 不会出现两个入口一个遮了、一个忘了遮的情况。
func (s *Server) settingsPayload(cfg config.Config) map[string]any {
	keys := map[string]string{}
	for name, v := range cfg.Purity.Keys {
		keys[name] = config.MaskedKey(v)
	}
	// purity 段里原本就带着 keys，不改写一份就会把明文 token 一起回给浏览器：
	// 界面又会在设置页里把它显示出来，带笔记本去咖啡店的人不想 API key 被人看到。
	shown := cfg.Purity
	shown.Keys = keys
	return map[string]any{
		"title":            cfg.Title,
		"listen":           cfg.Listen,
		"data_dir":         cfg.DataDir,
		"sources":          cfg.Sources,
		"probe":            cfg.Probe,
		"purity":           shown,
		"purity_keys":      keys,
		"purity_providers": s.app.Purity().Stats(),
		"config_path":      cfg.Path(),
		"version":          Version,
	}
}

// maxNodesText 把池子容量上限渲染成人话：0 = 不限。日志里写「上限=0」会被读成
// 「池子空了」。
func maxNodesText(n int) string {
	if n <= 0 {
		return "不限"
	}
	return strconv.Itoa(n)
}

// handleSettingsUpdate 接受界面上的配置项更新（POST /api/settings，走全局 CSRF 闸门）。
func (s *Server) handleSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	var p app.ConfigPatch
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
	if err := dec.Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return
	}
	cfg, err := s.app.PatchConfig(p)
	if err != nil {
		// 校验或写盘失败时 App 里那份配置也没动，界面看到的就是生效值。
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.log.Printf("[web] 配置已更新（写回 %s）：镜像=%v 自营=%v 缺席天数=%d 淘汰连负=%d 容量上限=%s 探测间隔=%dm 并发=%d TCP超时=%ds UDP超时=%ds 纯净度=%v RPM=%d",
		cfg.Path(), cfg.Sources.Mirrors.Enabled, cfg.Sources.KeepVpngateOwn,
		cfg.Sources.KeepDays, cfg.Sources.PurgeFailRounds, maxNodesText(cfg.Sources.MaxNodes),
		cfg.Probe.IntervalMinutes, cfg.Probe.Concurrency,
		cfg.Probe.TCPTimeoutSeconds, cfg.Probe.UDPTimeoutSeconds,
		cfg.Purity.Enabled, cfg.Purity.RequestsPerMinute)
	// 广播一下：另一个标签页开着时能立刻把开关改成新的，不会两边显示得不一样。
	s.app.Bus().Publish("settings:changed", map[string]any{
		"vpngate":   cfg.Sources.Vpngate.Enabled,
		"mirrors":   cfg.Sources.Mirrors.Enabled,
		"max_nodes": cfg.Sources.MaxNodes,
		"probe":     cfg.Probe.Enabled,
		"purity":    cfg.Purity.Enabled,
	})
	writeOK(w, s.settingsPayload(cfg))
}

// mirrorsPerRound 把 max_mirrors=0 翻成界面上看得懂的说法（0 的语义是「全部抓」）。
func mirrorsPerRound(n int) string {
	if n <= 0 {
		return "全部"
	}
	return strconv.Itoa(n)
}

// handleExport 导出 .ovpn 或 JSON。ids 用逗号分隔，上限 500 个。
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	ids := splitList(r.URL.Query().Get("ids"))
	if len(ids) == 0 {
		// 没指定 ids 就按当前筛选条件导出一批，这样「筛选完直接导出」不用先全选。
		f, err := parseFilter(r)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		// 界面上的「导出」不传 limit（默认导出一批），命令行或手搓 URL 传了就照办。
		if !r.URL.Query().Has("limit") {
			f.Limit = 500
		}
		f.Offset = 0
		for _, n := range s.app.Store().List(f).Items {
			ids = append(ids, n.ID)
		}
	}
	if len(ids) > 500 {
		writeErr(w, http.StatusUnprocessableEntity, "一次最多导出 500 个节点")
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "ovpn"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	var parts []string
	var missing []string
	switch format {
	case "json":
		list := make([]map[string]any, 0, len(ids))
		for _, id := range ids {
			n, ok := s.app.Store().Get(id)
			if !ok {
				missing = append(missing, id)
				continue
			}
			cfg, err := s.app.EnsureConfig(ctx, id)
			entry := map[string]any{"id": n.ID, "hostname": n.HostName, "ip": n.IP, "port": n.Port, "proto": n.Proto, "country_code": n.CountryCode}
			if err == nil {
				entry["config"] = string(cfg)
			} else {
				entry["config_error"] = err.Error()
				missing = append(missing, id)
			}
			list = append(list, entry)
		}
		name := fmt.Sprintf("vpngate-nodes-%s.json", time.Now().UTC().Format("20060102-1504"))
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
		writeOK(w, map[string]any{"count": len(parts), "nodes": list, "missing": missing})
		return
	case "ovpn":
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("# VPN Gate 节点导出（vpngate-agg %s）\n", Version))
		sb.WriteString(fmt.Sprintf("# 时间 %s UTC，共 %d 个节点\n", time.Now().UTC().Format("2006-01-02 15:04"), len(ids)))
		sb.WriteString("# 每个文件之间用一行 '# ==== 名称 ====' 分隔；OpenVPN 客户端请逐个导入。\n")
		okCount := 0
		for _, id := range ids {
			n, ok := s.app.Store().Get(id)
			if !ok {
				missing = append(missing, id)
				continue
			}
			cfg, err := s.app.EnsureConfig(ctx, id)
			if err != nil {
				missing = append(missing, fmt.Sprintf("%s(%s)", n.HostName, err.Error()))
				continue
			}
			okCount++
			sb.WriteString(fmt.Sprintf("\n# ==== %s | %s:%d/%s | %s ====\n", n.HostName, n.IP, n.Port, n.Proto, n.Country))
			sb.Write(cfg)
			if !strings.HasSuffix(string(cfg), "\n") {
				sb.WriteString("\n")
			}
		}
		if len(missing) > 0 {
			sb.WriteString(fmt.Sprintf("\n# 取不到配置的节点 %d 个：%s\n", len(missing), strings.Join(missing, ", ")))
		}
		name := fmt.Sprintf("vpngate-nodes-%s.ovpn", time.Now().UTC().Format("20060102-1504"))
		w.Header().Set("Content-Type", "application/x-openvpn-profile; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(sb.String()))
		s.log.Printf("[web] 导出 %d/%d 个节点配置", okCount, len(ids))
	default:
		writeErr(w, http.StatusUnprocessableEntity, "format 只能是 ovpn 或 json")
	}
}

// ---------- 参数解析 ----------

// parseFilter 把查询参数变成 store.Filter。
//
// 所有边界都在这里一次性校验，handler 里就不再重复判空了。
func parseFilter(r *http.Request) (store.Filter, error) {
	q := r.URL.Query()
	f := store.Filter{
		Q:          strings.TrimSpace(q.Get("q")),
		Sort:       strings.ToLower(strings.TrimSpace(q.Get("sort"))),
		PingSource: strings.ToLower(strings.TrimSpace(q.Get("ping_source"))),
		Countries:  upperList(q.Get("country")),
		Protocols:  lowerList(q.Get("proto")),
		Levels:     lowerList(q.Get("level")),
		IDs:        splitList(q.Get("ids")),
	}
	if f.Sort == "" {
		f.Sort = "recommend"
	}
	f.Desc = strings.EqualFold(q.Get("dir"), "desc")
	switch f.PingSource {
	case "best", "":
		f.PingSource = "best"
	case "local", "upstream", "cloudflare":
	default:
		return f, fmt.Errorf("ping_source 只能是 best/local/upstream/cloudflare")
	}
	intPtr := func(name string) (*int, error) {
		s := strings.TrimSpace(q.Get(name))
		if s == "" {
			return nil, nil
		}
		v, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("%s 不是整数: %q", name, s)
		}
		return &v, nil
	}
	var err error
	if f.MinPurity, err = intPtr("min_purity"); err != nil {
		return f, err
	}
	if f.MaxPurity, err = intPtr("max_purity"); err != nil {
		return f, err
	}
	if v, err := intPtr("max_ping"); err != nil {
		return f, err
	} else if v != nil {
		n := int64(*v)
		f.MaxPing = &n
	}
	f.ResidentialOnly = isTruthy(q.Get("residential"))
	f.PurityOnly = isTruthy(q.Get("purity_only"))
	f.FreshOnly = isTruthy(q.Get("fresh"))
	f.HasProbeLog = isTruthy(q.Get("probed"))
	if f.Limit, err = atoiDefault(q.Get("limit"), 100, 1, 500); err != nil {
		return f, fmt.Errorf("limit: %w", err)
	}
	if f.Offset, err = atoiDefault(q.Get("offset"), 0, 0, 1<<30); err != nil {
		return f, fmt.Errorf("offset: %w", err)
	}
	return f, nil
}

func atoiDefault(s string, def, min, max int) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def, fmt.Errorf("%q 不是整数", s)
	}
	if v < min {
		v = min
	}
	if v > max {
		v = max
	}
	return v, nil
}

func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func upperList(s string) []string {
	list := splitList(s)
	for i := range list {
		list[i] = strings.ToUpper(list[i])
	}
	return list
}

func lowerList(s string) []string {
	list := splitList(s)
	for i := range list {
		list[i] = strings.ToLower(list[i])
	}
	return list
}

// slimNode 把列表用的节点瘦身：纯净度里每个来源的原始响应是最大的一块，
// 列表里用不到，留在详情接口里给。
func slimNode(n *model.Node) *model.Node {
	if n == nil || n.Purity == nil {
		return n
	}
	kept := make([]model.ProviderVerdict, 0, len(n.Purity.Providers))
	for _, p := range n.Purity.Providers {
		p.Raw = nil
		if len(p.Err) > 160 {
			p.Err = p.Err[:160]
		}
		kept = append(kept, p)
	}
	n.Purity.Providers = kept
	return n
}

// safeName 把 hostname 变成安全的文件名片段。
func safeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "node"
	}
	if len(out) > 48 {
		out = out[:48]
	}
	return out
}

func short(s string) string {
	if len(s) < 8 {
		return s
	}
	return s[:8]
}

func errOr(err error, def string) string {
	if err == nil {
		return def
	}
	return err.Error()
}

// sourcesSummary 给界面的「数据源」卡片：三源各自的关键参数。
func sourcesSummary(cfg config.Config) []map[string]any {
	return []map[string]any{
		{
			"name": "vpngate", "label": "VPN Gate 官方主站", "enabled": cfg.Sources.Vpngate.Enabled,
			"url": config.DefaultAPI, "timeout": cfg.Sources.Vpngate.TimeoutSeconds,
		},
		{
			"name": "mirrors", "label": "官方镜像站", "enabled": cfg.Sources.Mirrors.Enabled,
			"url": cfg.Sources.Mirrors.SitesPage, "max_mirrors": cfg.Sources.Mirrors.MaxMirrors,
		},
	}
}
