package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/app"
)

// handleEvents 是 SSE 事件流。
//
// 为什么用 SSE 而不是 WebSocket：这里只有服务端到客户端的单向推送
// （任务进度、单条结果、统计刷新），SSE 走普通 HTTP，不用升级协议、
// 不用处理重连握手，反代配置也简单（Nginx 只要 proxy_buffering off）。
//
// 前端断线重连由 EventSource 自己做（浏览器原生带 retry），
// 服务端在订阅时会补发最近的事件，避免刷新页面后看不到正在跑的任务进度。
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "当前连接不支持流式输出")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	// Nginx/Caddy 默认会缓冲响应；这一条是让进度条真的「实时」的关键。
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	_, _ = io.WriteString(w, "retry: 3000\n\n")
	flusher.Flush()

	events, cancel := s.app.Bus().Subscribe()
	defer cancel()

	hello := app.Event{Type: "hello", Data: map[string]any{
		"time":    time.Now().UTC(),
		"running": s.app.Running(),
		"nodes":   s.app.Store().Count(),
		"version": Version,
	}, At: time.Now().UTC()}
	writeEvent(w, flusher, hello)

	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-events:
			if !ok {
				return // 总线那边已经关掉这个订阅
			}
			writeEvent(w, flusher, e)
		case <-ticker.C:
			// 心跳：反代的空闲超时通常在 60 秒，一条注释就够续命，
			// 也让客户端能区分「连接死了」和「只是没事件」。
			if _, err := io.WriteString(w, ": ping "+fmt.Sprint(time.Now().Unix())+"\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func writeEvent(w http.ResponseWriter, flusher http.Flusher, e app.Event) {
	line, err := app.EncodeEvent(e)
	if err != nil {
		return
	}
	if _, err := w.Write(line); err != nil {
		return
	}
	flusher.Flush()
}

// decodeJSON 读请求体。上限 1 MB：这些接口都是参数类请求，
// 超过这个量级就是客户端写错了（或者在拿 POST 传数据）。
func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("缺少请求体")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("读取请求体失败: %w", err)
	}
	if len(body) == 0 {
		return errors.New("缺少请求体")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("请求体不是合法 JSON: %v", err)
	}
	return nil
}
