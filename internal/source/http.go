// Package source 负责把 VPN Gate 的节点目录搬进本地节点池。
//
// 三个来源，各自独立失败、独立记状态：
//  1. 官方主站 https://www.vpngate.net/api/iphone/ （实时，但只返回按它自己
//     分数排的前 ~100 个）
//  2. 官方列出的镜像站（sites.aspx 上那批 IP:PORT，实测 6 个里有 4 个在同一
//     /24，所以按 /24 + location 去重后轮转取用）
//  3. vpngate-list-mirror 的 GitHub/jsDelivr 镜像（含 4900+ 的累积池，
//     还带 Cloudflare Worker 的 TCP 观测）
package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// 单次响应的字节上限。实测官方 CSV 约 1.3 MB、mirror 的 pool/servers.json
// 约 7 MB，给的值已经是「明显不对」的量级：超过就是被拦截、返回门户页，
// 或者上游改了格式。
const (
	CSVMaxBytes      = 4 << 20
	IndexMaxBytes    = 64 << 10
	DataMaxBytes     = 24 << 20
	PoolMaxBytes     = 32 << 10 << 10 // pool/servers.json，给 32 MB
	SitesPageMaxByte = 1 << 20
)

// ErrTooBig 单独一个错误类型：调用方要能区分「超限（内容不对，保留旧数据）」
// 和「网络抖动（可以重试）」。
var ErrTooBig = errors.New("响应超过字节上限")

// transport 是多源共用的传输层。
//
// DisableCompression 不是优化，是必需的：官方镜像站对带 Accept-Encoding: gzip
// 的请求会先回 200 再一个字节都不发，一直挂到客户端超时（实测同一 URL 不带
// 这个头 1.3 MB 4 秒拉完，带了 30 秒 0 字节）。Go 默认 Transport 会自动加这个
// 头，不关掉等于所有官方镜像源永远失败。
var transport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DisableCompression = true
	t.MaxIdleConns = 32
	t.MaxIdleConnsPerHost = 4
	t.IdleConnTimeout = 60 * time.Second
	t.TLSHandshakeTimeout = 15 * time.Second
	t.ExpectContinueTimeout = 2 * time.Second
	return t
}()

// Client 是本包的 HTTP 客户端。UA 可配，因为部分镜像会挑 UA。
type Client struct {
	h         *http.Client
	userAgent string
}

func NewClient(userAgent string) *Client {
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (compatible; vpngate-agg)"
	}
	return &Client{
		h:         &http.Client{Transport: transport},
		userAgent: userAgent,
	}
}

// Get 拉一个 URL：状态码校验 + 字节上限 + 有限重试。
//
// 多读 1 字节用来判超限：直接 LimitReader(max) 会把半截内容当完整内容交给
// 解析器，而 CSV 解析器对截断是宽容的（少了结束标记照样能解出一堆节点），
// 于是残缺列表会覆盖掉好好的节点池。
//
// 重试只针对「连接类错误 + 429 + 5xx」这类瞬时问题；4xx 直接返回，
// 免得把一个被 WAF 拦截的页面重试三轮还当成网络问题。
func (c *Client) Get(ctx context.Context, url string, maxBytes int64, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			// 退避要能被取消，否则关停时会卡在这里。
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(600*attempt) * time.Millisecond):
			}
		}
		raw, retryable, err := c.getOnce(ctx, url, maxBytes, timeout)
		if err == nil {
			return raw, nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
	}
	return nil, fmt.Errorf("三次尝试都失败: %w", lastErr)
}

func (c *Client) getOnce(ctx context.Context, url string, maxBytes int64, timeout time.Duration) ([]byte, bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, fmt.Errorf("构造请求失败: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/plain, application/json, */*")
	// 官方与 mirror 都支持 CORS；不带这个头不影响，但自建反代时好用。
	req.Header.Set("Accept-Language", "en-US,en;q=0.8")

	resp, err := c.h.Do(req)
	if err != nil {
		var ne *net.OpError
		// 超时/EOF/连接重置都值得重试一次。
		retryable := errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) ||
			strings.Contains(err.Error(), "connection reset") ||
			strings.Contains(err.Error(), "EOF")
		return nil, retryable, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("HTTP %d", resp.StatusCode)
	default:
		return nil, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		// 读到一半断了：可能是对端提前关连接，也可能是超时，两者都值得重试。
		return nil, true, fmt.Errorf("读取响应失败: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, false, fmt.Errorf("%w（>%d 字节）", ErrTooBig, maxBytes)
	}
	if len(raw) == 0 {
		return nil, true, errors.New("响应 0 字节")
	}
	return raw, false, nil
}
