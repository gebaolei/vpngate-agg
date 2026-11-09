package web

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/app"
	"github.com/gebaolei/vpngate-agg/internal/config"
)

// Version 是构建版本，Makefile 里用 -ldflags 注入。
var Version = "dev"

// Server 是 HTTP 服务。
type Server struct {
	cfg  config.Config
	app  *app.App
	auth *Auth
	log  *log.Logger
	mux  *http.ServeMux
	// apiRate 管对外接口（/vpngate/*）的按 IP 限流。阈值每次从配置读，
	// 这张表只记「这一分钟这个 IP 打了几次」。
	apiRate *apiRate
	// staticTag 是给静态资源加的缓存标记（内容 hash 前 8 位）。
	// 内嵌资源不会变，但用户的浏览器会缓存 —— 换个 tag 就能强制刷新。
	staticTag string
}

// New 装配路由与中间件。
func New(cfg config.Config, a *app.App, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.Default()
	}
	auth, err := NewAuth(Config{
		Username:     cfg.Auth.Username,
		Password:     cfg.Auth.Password,
		PBKDF2:       cfg.Auth.PBKDF2,
		SessionHours: cfg.Auth.SessionHours,
		CookieSecure: cfg.Auth.CookieSecure,
		DisableAuth:  cfg.Auth.DisableAuth,
	}, cfg.DataDir)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, app: a, auth: auth, log: logger, mux: http.NewServeMux(), apiRate: newAPIRate()}
	s.staticTag = assetTag()
	s.routes()
	return s, nil
}

// routes 注册全部路由。
//
// 静态资源不设鉴权（登录页本身要用），鉴权只加在 /api/* 上；
// 前端在没有会话时自己渲染登录视图。这样「打开就是登录页」的体验
// 和「302 到 /login」相比，少一次往返，也让 API 的错误码保持诚实。
func (s *Server) routes() {
	s.mux.HandleFunc("GET /{$}", s.handleIndex)
	s.mux.Handle("GET /app.js", s.staticFile("app.js"))
	s.mux.Handle("GET /style.css", s.staticFile("style.css"))
	s.mux.Handle("GET /world-map.js", s.staticFile("world-map.js"))
	s.mux.Handle("GET /favicon.svg", s.staticFile("favicon.svg"))
	s.mux.HandleFunc("GET /favicon.ico", s.handleFavicon)
	s.mux.HandleFunc("GET /healthz", s.handleHealth)

	s.mux.HandleFunc("GET /api/session", s.handleSession)
	s.mux.HandleFunc("POST /api/login", s.handleLogin)
	s.mux.HandleFunc("POST /api/logout", s.handleLogout)
	s.mux.HandleFunc("POST /api/password", s.requireAuth(s.handlePassword))

	s.mux.HandleFunc("GET /api/stats", s.requireAuth(s.handleStats))
	s.mux.HandleFunc("GET /api/nodes", s.requireAuth(s.handleNodes))
	s.mux.HandleFunc("GET /api/nodes/{id}", s.requireAuth(s.handleNodeDetail))
	s.mux.HandleFunc("POST /api/nodes/{id}/probe", s.requireAuth(s.handleProbeOne))
	s.mux.HandleFunc("POST /api/nodes/{id}/purity", s.requireAuth(s.handlePurityOne))
	s.mux.HandleFunc("GET /api/nodes/{id}/config", s.requireAuth(s.handleConfig))

	s.mux.HandleFunc("POST /api/refresh", s.requireAuth(s.handleRefresh))
	s.mux.HandleFunc("POST /api/probe", s.requireAuth(s.handleProbe))
	s.mux.HandleFunc("POST /api/purity", s.requireAuth(s.handlePurity))
	s.mux.HandleFunc("POST /api/cancel", s.requireAuth(s.handleCancel))
	s.mux.HandleFunc("GET /api/jobs", s.requireAuth(s.handleJobs))
	s.mux.HandleFunc("GET /api/settings", s.requireAuth(s.handleSettings))
	// 开关写入单独一条路由：跟 GET 分开，方法级别的权限闸门不用在 handler 里再判一遍。
	s.mux.HandleFunc("POST /api/settings", s.requireAuth(s.handleSettingsUpdate))
	s.mux.HandleFunc("GET /api/export", s.requireAuth(s.handleExport))
	s.mux.HandleFunc("GET /api/events", s.requireAuth(s.handleEvents))

	// 对外只读接口：字段名对齐官方 /api/iphone/，用 api.token 鉴权（默认关）。
	// 带不带尾斜杠都注册一条：只注册带斜杠那条时，无斜杠的请求会被 mux 301 到
	// 带斜杠的地址，而不少客户端跳转时把查询参数（包括 ?key=）丢了，现场很难查。
	s.mux.HandleFunc("GET /vpngate/api/iphone", s.requireAPI(s.handleVpngateAPI))
	s.mux.HandleFunc("GET /vpngate/api/iphone/", s.requireAPI(s.handleVpngateAPI))
}

// Handler 返回带中间件的根 handler。
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	h = s.middlewareGzip(h)
	h = s.middlewareSecurity(h)
	h = s.middlewareRecover(h)
	return h
}

// Serve 启动监听并优雅退出。
func (s *Server) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout 不能设太短：SSE 是长连接，导出几百个配置也可能是秒级。
		// 这里给 0（不限），靠各自的 context 与 handler 自己控制。
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}
	// SSE 需要 flush 即时生效，别被缓冲吃掉。
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("监听 %s 失败: %w", s.cfg.Listen, err)
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			s.log.Printf("[web] 优雅关闭失败: %v", err)
		}
	}()
	ips := localAddrs(ln)
	if len(ips) > 0 {
		s.log.Printf("[web] 界面已启动: %s（本机 %s）", s.cfg.Listen, strings.Join(ips, ", "))
	} else {
		s.log.Printf("[web] 界面已启动: %s", s.cfg.Listen)
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// localAddrs 打印可直接点开的地址，省得用户去猜 IP。
func localAddrs(ln net.Listener) []string {
	// 必须用监听器实际解析出的地址：配置里写的是 ":8080"，
	// 而 Addr() 会变成 "[::]:8080"，直接按 ":" 切字符串会得到
	// "http://127.0.0.1::]:8080" 这种点不开的东西。
	ta, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	url := func(ip string) string { return fmt.Sprintf("http://%s:%d", ip, ta.Port) }
	// 只绑了某个地址（比如 127.0.0.1:8080）时就报那一个，
	// 并列一堆其实访问不到的局域网地址只会让人以为能连。
	if !ta.IP.IsUnspecified() {
		return []string{url(ta.IP.String())}
	}
	out := []string{url("127.0.0.1")}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		if ipnet.IP.To4() == nil {
			continue // IPv6 展示要加方括号，收益不大，略过
		}
		out = append(out, url(ipnet.IP.String()))
	}
	return out
}

// ---------- 中间件 ----------

func (s *Server) middlewareRecover(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// panic 只可能是我们的 handler 里出了越界/nil；打全栈并回 500，
				// 别让一个坏请求把整个进程带走。
				s.log.Printf("[web] panic %v %s %s", rec, r.Method, r.URL.Path)
				http.Error(w, "内部错误", http.StatusInternalServerError)
			}
		}()
		h.ServeHTTP(w, r)
	})
}

func (s *Server) middlewareSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		// CSP 全部 self：本项目的 JS/CSS 都是内嵌文件，没有外部 CDN，
		// 因此可以直接禁掉 inline script —— 这是最硬的一条 XSS 防线。
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"connect-src 'self'; font-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		h.Set("Server", "vpngate-agg/"+Version)
		next.ServeHTTP(w, r)
	})
}

// gzipWriter 复用 gzip.Writer。列表接口一次几百 KB，压完能小一个数量级。
var (
	gzPool = sync.Pool{New: func() any {
		g, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		return g
	}}
	gzSkip = map[string]bool{"/api/events": true} // SSE 自己控制 flush，别叠压缩
)

func (s *Server) middlewareGzip(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gzSkip[r.URL.Path] || !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			h.ServeHTTP(w, r)
			return
		}
		gz, ok := gzPool.Get().(*gzip.Writer)
		if !ok {
			h.ServeHTTP(w, r)
			return
		}
		defer gzPool.Put(gz)
		gz.Reset(w)
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		rw := &gzipResponseWriter{ResponseWriter: w, gz: gz}
		h.ServeHTTP(rw, r)
		// 没写 body 的响应（204/304/错误）也必须 Close，否则 gzip 尾块缺失。
		_ = gz.Close()
	})
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gz     *gzip.Writer
	wrote  bool
	status int
}

func (g *gzipResponseWriter) Write(p []byte) (int, error) {
	g.wrote = true
	return g.gz.Write(p)
}

func (g *gzipResponseWriter) WriteHeader(code int) {
	if g.status == 0 {
		g.status = code
	}
	// 状态码 >= 400 时我们可能已经写过头，这里只透传一次。
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipResponseWriter) Flush() {
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		_ = g.gz.Flush()
		f.Flush()
	}
}

// requireAuth 是 API 的鉴权闸门。
//
// 除了「有没有会话」，写操作还额外要求 X-CSRF-Token 与 Content-Type:
// application/json。两条都是必要的：跨站能自动带 cookie，但读不到响应也算不出
// CSRF token；而跨站表单提交拿不到 JSON 的 Content-Type。
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.auth.Disabled() {
			if !s.checkCSRF(r, "disabled") {
				writeErr(w, http.StatusForbidden, "缺少 X-CSRF-Token")
				return
			}
			next(w, r)
			return
		}
		c, err := r.Cookie(CookieName)
		if err != nil || c.Value == "" {
			writeErr(w, http.StatusUnauthorized, "未登录")
			return
		}
		sess, ok := s.auth.ParseSession(c.Value)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "会话已过期，请重新登录")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !s.checkCSRF(r, c.Value) {
				writeErr(w, http.StatusForbidden, "CSRF 校验失败（缺少或错误的 X-CSRF-Token）")
				return
			}
		}
		r.Header.Set("X-Session-User", sess.User)
		next(w, r)
	}
}

// checkCSRF 校验写请求。禁用登录时也要 token，只是 token 由一个固定输入推导。
func (s *Server) checkCSRF(r *http.Request, sessionValue string) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	// 只接受 JSON 请求体：跨站表单只能发 form-encoded/text/plain，光这一条
	// 就已经挡住经典 CSRF，再叠 token 是双保险。
	ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if ct != "" && !strings.HasPrefix(ct, "application/json") {
		return false
	}
	want := s.auth.CSRF(sessionValue)
	got := strings.TrimSpace(r.Header.Get("X-CSRF-Token"))
	if got == "" {
		got = strings.TrimSpace(r.URL.Query().Get("csrf"))
	}
	return got != "" && subtleEqual(got, want)
}

// subtleEqual 定长比较 CSRF token。用 crypto/subtle 而不是 bytes.Equal：
// bytes.Equal 会在第一个不同字节就返回，理论上能被时序攻击用来逐字节猜 token。
func subtleEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------- 通用响应 ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// 头已经发出去了，这里只能记一下。
		log.Printf("[web] 编码响应失败: %v", err)
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}

func writeOK(w http.ResponseWriter, v map[string]any) {
	out := map[string]any{"ok": true}
	for k, val := range v {
		out[k] = val
	}
	writeJSON(w, http.StatusOK, out)
}

// assetTag 是静态资源的内容指纹，拼在 ?v= 后面。
// 内嵌文件改了就必须让用户拿到新的，但不能靠不缓存 —— 那就失去内嵌的意义了。
func assetTag() string {
	names := []string{"app.js", "style.css", "world-map.js"}
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n))
		if b, err := staticFS.ReadFile("static/" + n); err == nil {
			h.Write(b)
		}
	}
	return hex.EncodeToString(h.Sum(nil))[:12]
}
