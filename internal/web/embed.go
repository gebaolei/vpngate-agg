package web

import (
	"bytes"
	"embed"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"time"
)

// staticFS 是内嵌的前端资源。整个工具对外只有一个二进制：
// 复制一个文件到服务器上就能跑，不需要 rsync 一个 dist 目录。
//
//go:embed static
var staticFS embed.FS

// staticSub 剥掉 static/ 前缀，方便 http.ServeFileFS 之类复用。
var staticSub = mustSub()

func mustSub() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("内嵌资源异常: %v", err)
	}
	return sub
}

// staticFile 提供 app.js / style.css / favicon.svg 这类固定资源。
//
// 缓存策略：URL 上带 ?v=<内容 hash>，所以文件可以 immutable 长缓存。
// 内容变了 tag 就变，浏览器自然拿到新的。
func (s *Server) staticFile(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := staticFS.ReadFile("static/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentTypeFor(name))
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		http.ServeContent(w, r, name, s.buildTime(), bytes.NewReader(b))
	})
}

// buildTime 是内嵌资源的「最后修改时间」。用固定 epoch 就够：
// 真正的版本区分在 ?v= 的 tag 上，不该依赖构建机器的时间戳。
func (s *Server) buildTime() time.Time { return time.Unix(0, 0).UTC() }

// handleIndex 返回首页 HTML。
//
// 这个响应必须 no-store：它是唯一一个决定「要不要重新拉 app.js」的文件。
// 缓存了它，换新版本时浏览器就会一直用旧的 tag。
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	b, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "缺少内嵌页面", http.StatusInternalServerError)
		return
	}
	// {{ASSET_TAG}} 和 {{TITLE}} 在运行时替换：标题是可配的，
	// 而 tag 是内容 hash，编译期不知道。
	html := strings.ReplaceAll(string(b), "{{ASSET_TAG}}", s.staticTag)
	html = strings.ReplaceAll(html, "{{TITLE}}", htmlEscape(s.cfg.Title))
	html = strings.ReplaceAll(html, "{{VERSION}}", Version)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(html))
}

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/favicon.svg?v="+s.staticTag, http.StatusTemporaryRedirect)
}

func contentTypeFor(name string) string {
	switch {
	case strings.HasSuffix(name, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(name, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(name, ".svg"):
		return "image/svg+xml; charset=utf-8"
	case strings.HasSuffix(name, ".html"):
		return "text/html; charset=utf-8"
	}
	return "application/octet-stream"
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}
