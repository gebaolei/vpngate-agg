package source

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/config"
)

const testConfig = "client\ndev tun\nproto tcp\nremote 203.0.113.7 1194\ncipher AES-128-CBC\n<ca>\nabc\n</ca>\n"

func shaHexOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type cdnFixture struct {
	servers    []byte
	index      []byte
	pool       []byte
	poolIndex  []byte
	poolConfig []byte

	commit     string
	poolCommit string
	configSHA  string
}

func (f *cdnFixture) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/latest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.index)
	})
	mux.HandleFunc("/pool/latest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.poolIndex)
	})
	mux.HandleFunc("/"+f.commit+"/data/servers.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(f.servers)
	})
	mux.HandleFunc("/"+f.poolCommit+"/pool/servers.json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(f.pool)
	})
	mux.HandleFunc("/"+f.poolCommit+"/pool/configs/"+f.configSHA+".json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(f.poolConfig)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return mux
}

func newCDNFixture(t *testing.T, poolAge time.Duration, staleAge time.Duration) *cdnFixture {
	t.Helper()
	f := &cdnFixture{
		commit:     strings.Repeat("a", 40),
		poolCommit: strings.Repeat("b", 40),
		configSHA:  shaHexOf([]byte(testConfig)),
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(testConfig))

	srvDoc := map[string]any{
		"schema_version": 1,
		"server_count":   1,
		"servers": []any{map[string]any{
			"hostname":              "vpn100",
			"ip":                    "203.0.113.7",
			"country_code":          "jp",
			"country_name":          "Japan",
			"score":                 123,
			"ping_ms":               10,
			"speed_bps":             456,
			"num_vpn_sessions":      7,
			"openvpn_config_base64": b64,
			"openvpn_config_sha256": f.configSHA,
			"openvpn_config_bytes":  len(testConfig),
			"source_record_id":      "x",
		}},
	}
	f.servers = marshal(t, srvDoc)

	poolDoc := map[string]any{
		"schema_version": 1,
		"server_count":   3,
		"servers": []any{
			map[string]any{
				"id":                       "",
				"hostname":                 "vpn-pool-1",
				"ip":                       "198.51.100.10",
				"country_code":             "US",
				"country_name":             "United States",
				"score":                    900,
				"openvpn_config_sha256":    f.configSHA,
				"openvpn_config_bytes":     len(testConfig),
				"first_seen_at":            time.Now().Add(-72 * time.Hour).UTC().Format(time.RFC3339),
				"last_seen_at":             time.Now().Add(-poolAge).UTC().Format(time.RFC3339),
				"present_in_latest_source": true,
				"probe_targets":            []any{map[string]any{"ip": "198.51.100.10", "port": 1194}},
				"tcp_probe": map[string]any{
					"status":               "reachable",
					"checked_at":           time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
					"last_success_at":      time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
					"connect_ms":           42,
					"connected_endpoint":   map[string]any{"ip": "198.51.100.10", "port": 1194},
					"consecutive_failures": 0,
					"probe_source":         "cloudflare",
					"round":                12,
				},
			},
			map[string]any{
				"hostname":                 "vpn-pool-udp",
				"ip":                       "198.51.100.11",
				"country_code":             "DE",
				"openvpn_config_sha256":    f.configSHA,
				"first_seen_at":            time.Now().Add(-10 * time.Hour).UTC().Format(time.RFC3339),
				"last_seen_at":             time.Now().Add(-poolAge).UTC().Format(time.RFC3339),
				"present_in_latest_source": true,
				"probe_reason":             "udp",
			},
			map[string]any{
				"hostname":                 "vpn-pool-stale",
				"ip":                       "198.51.100.12",
				"country_code":             "FR",
				"openvpn_config_sha256":    f.configSHA,
				"last_seen_at":             time.Now().Add(-staleAge).UTC().Format(time.RFC3339),
				"present_in_latest_source": false,
				"probe_targets":            []any{map[string]any{"ip": "198.51.100.12", "port": 443}},
			},
		},
	}
	f.pool = marshal(t, poolDoc)

	f.poolConfig = marshal(t, map[string]any{
		"kind":                  "openvpn_config",
		"schema_version":        1,
		"openvpn_config_base64": b64,
		"openvpn_config_sha256": f.configSHA,
		"openvpn_config_bytes":  len(testConfig),
	})

	f.index = marshal(t, map[string]any{
		"schema_version":      1,
		"kind":                "index",
		"source_url":          "https://www.vpngate.net/api/iphone/",
		"fetched_at":          time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339),
		"data_commit":         f.commit,
		"source_record_count": 100,
		"server_count":        1,
		"country_count":       1,
		"files": map[string]any{
			"data/servers.json": map[string]any{
				"sha256":       shaHexOf(f.servers),
				"bytes":        len(f.servers),
				"server_count": 1,
			},
		},
	})
	f.poolIndex = marshal(t, map[string]any{
		"schema_version": 1,
		"kind":           "pool-index",
		"fetched_at":     time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339),
		"data_commit":    f.poolCommit,
		"server_count":   3,
		"files": map[string]any{
			"pool/servers.json": map[string]any{
				"sha256": shaHexOf(f.pool),
				"bytes":  len(f.pool),
			},
		},
	})
	return f
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("构造测试 JSON 失败: %v", err)
	}
	return b
}

func cdnConfig(tsURL, commitBase string, usePool bool, maxNodes, poolMaxAge int) config.CDNSource {
	return config.CDNSource{
		Enabled:         true,
		Repo:            "o/r",
		IndexURL:        tsURL + "/latest.json",
		CDNBase:         tsURL + "/",
		FallbackRaw:     false,
		UsePool:         usePool,
		PoolMaxAgeHours: poolMaxAge,
		MaxNodes:        maxNodes,
		TimeoutSeconds:  5,
	}
}

func TestCDNFetchSnapshot(t *testing.T) {
	f := newCDNFixture(t, time.Hour, 60*24*time.Hour)
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	res, err := NewCDN(NewClient("test"), cdnConfig(srv.URL, f.commit, false, 0, 0)).Fetch(context.Background())
	if err != nil {
		t.Fatalf("抓取失败: %v", err)
	}
	if res.Commit != f.commit {
		t.Errorf("commit = %s，期望锚定到 %s", res.Commit, f.commit)
	}
	if res.Checked["data/servers.json"] != shaHexOf(f.servers) {
		t.Errorf("校验记录不对: %v", res.Checked)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("行数 = %d", len(res.Rows))
	}
	n := res.Rows[0].Node
	if n.HostName != "vpn100" || n.IP != "203.0.113.7" {
		t.Errorf("节点 = %s / %s", n.HostName, n.IP)
	}
	if n.ID != "v1:"+shaHexOf([]byte("vpngate-node-v1\x00vpn100\x00203.0.113.7")) {
		t.Errorf("ID 未按协议推导: %s", n.ID)
	}
	if n.CountryCode != "JP" {
		t.Errorf("国家码应归一为大写，实得 %q", n.CountryCode)
	}
	if n.UpstreamScore != 123 || n.UpstreamPingMS != 10 || n.UpstreamSpeedBps != 456 || n.Sessions != 7 {
		t.Errorf("上游指标不对: %+v", n)
	}
	if !n.ConfigLocal {
		t.Error("单快照里配置就在文件里，ConfigLocal 应为 true")
	}
	if string(res.Rows[0].Config) != testConfig {
		t.Errorf("配置正文解码后与源不符: %q", res.Rows[0].Config)
	}
	if n.Port != 1194 || n.Proto != "tcp" || !n.HasCerts {
		t.Errorf("连接参数未按 .ovpn 解析: %+v", n)
	}
	if n.LastSource != "cdn" {
		t.Errorf("来源标记 = %q", n.LastSource)
	}
	if len(res.PoolRows) != 0 {
		t.Errorf("没开累积池却拿到了池数据: %d", len(res.PoolRows))
	}
}

// 索引给的 sha 与文件真实 sha 不符时必须报错：jsDelivr 的 @main 有长缓存，
// 不锚 commit + 不校 hash 就可能读到跨 commit 的混合快照。
func TestCDNSHAMismatch(t *testing.T) {
	f := newCDNFixture(t, time.Hour, 60*24*time.Hour)
	f.index = marshal(t, map[string]any{
		"schema_version": 1,
		"data_commit":    f.commit,
		"files": map[string]any{
			"data/servers.json": map[string]any{"sha256": strings.Repeat("0", 64), "bytes": len(f.servers)},
		},
	})
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	_, err := NewCDN(NewClient("test"), cdnConfig(srv.URL, f.commit, false, 0, 0)).Fetch(context.Background())
	if err == nil || !strings.Contains(err.Error(), "SHA-256 不匹配") {
		t.Fatalf("sha 不匹配应报错，实得 %v", err)
	}
}

func TestCDNBytesMismatch(t *testing.T) {
	f := newCDNFixture(t, time.Hour, 60*24*time.Hour)
	f.index = marshal(t, map[string]any{
		"schema_version": 1,
		"data_commit":    f.commit,
		"files": map[string]any{
			"data/servers.json": map[string]any{"sha256": shaHexOf(f.servers), "bytes": len(f.servers) + 1},
		},
	})
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	if _, err := NewCDN(NewClient("test"), cdnConfig(srv.URL, f.commit, false, 0, 0)).Fetch(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "字节数不匹配") {
		t.Fatalf("字节数不匹配应报错，实得 %v", err)
	}
}

func TestCDNIndexValidation(t *testing.T) {
	cases := []struct {
		name string
		idx  map[string]any
		want string
	}{
		{"schema 不支持", map[string]any{"schema_version": 2, "data_commit": strings.Repeat("a", 40), "files": map[string]any{}}, "schema_version"},
		{"commit 太短", map[string]any{"schema_version": 1, "data_commit": "abc", "files": map[string]any{}}, "data_commit"},
		{"commit 大写", map[string]any{"schema_version": 1, "data_commit": strings.Repeat("A", 40), "files": map[string]any{}}, "data_commit"},
		{"缺文件", map[string]any{"schema_version": 1, "data_commit": strings.Repeat("a", 40), "files": map[string]any{}}, "索引里没有"},
		{"sha 格式不对", map[string]any{"schema_version": 1, "data_commit": strings.Repeat("a", 40), "files": map[string]any{
			"data/servers.json": map[string]any{"sha256": "ZZZ", "bytes": 10},
		}}, "sha256"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newCDNFixture(t, time.Hour, 60*24*time.Hour)
			f.index = marshal(t, c.idx)
			srv := httptest.NewServer(f.handler(t))
			defer srv.Close()
			_, err := NewCDN(NewClient("test"), cdnConfig(srv.URL, f.commit, false, 0, 0)).Fetch(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("应报 %q，实得 %v", c.want, err)
			}
		})
	}
}

func TestCDNServersCountMismatch(t *testing.T) {
	f := newCDNFixture(t, time.Hour, 60*24*time.Hour)
	f.servers = marshal(t, map[string]any{"schema_version": 1, "server_count": 9, "servers": []any{}})
	// 索引里的 sha/bytes 要跟着换，否则会先在校验那一步就失败。
	f.index = marshal(t, map[string]any{
		"schema_version": 1,
		"data_commit":    f.commit,
		"files":          map[string]any{"data/servers.json": map[string]any{"sha256": shaHexOf(f.servers), "bytes": len(f.servers)}},
	})
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	if _, err := NewCDN(NewClient("test"), cdnConfig(srv.URL, f.commit, false, 0, 0)).Fetch(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "server_count") {
		t.Fatalf("server_count 与实际条数不符应报错，实得 %v", err)
	}
}

func TestCDNPool(t *testing.T) {
	f := newCDNFixture(t, time.Hour, 60*24*time.Hour)
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	cfg := cdnConfig(srv.URL, f.commit, true, 10, 24*7)
	res, err := NewCDN(NewClient("test"), cfg).Fetch(context.Background())
	if err != nil {
		t.Fatalf("抓取失败: %v", err)
	}
	if res.PoolCommit != f.poolCommit {
		t.Errorf("池 commit 必须用自己索引里的（不能混用根索引）: %s", res.PoolCommit)
	}
	if len(res.PoolRows) != 2 {
		t.Fatalf("池行数 = %d，期望 2（超过 PoolMaxAgeHours 的那个应被丢掉）", len(res.PoolRows))
	}

	tcp, udp := res.PoolRows[0].Node, res.PoolRows[1].Node
	if tcp.ConfigLocal {
		t.Error("池里的节点正文不在文件里，ConfigLocal 应为 false")
	}
	if tcp.Server != "198.51.100.10" || tcp.Port != 1194 || tcp.Proto != "tcp" {
		t.Errorf("端点应取池子给的 probe_targets，实得 %+v", tcp)
	}
	if tcp.CFProbe == nil || tcp.CFProbe.Status != "reachable" || tcp.CFProbe.ConnectMS == nil || *tcp.CFProbe.ConnectMS != 42 {
		t.Errorf("Cloudflare 观测没接进来: %+v", tcp.CFProbe)
	}
	if tcp.CFProbe != nil && tcp.CFProbe.Endpoint != "198.51.100.10:1194" {
		t.Errorf("成功端点 = %q", tcp.CFProbe.Endpoint)
	}
	if tcp.InLatestSource == nil || !*tcp.InLatestSource {
		t.Errorf("present_in_latest_source 应保留: %v", tcp.InLatestSource)
	}
	if tcp.LastSeen.IsZero() || tcp.FirstSeen.IsZero() {
		t.Error("池里的 first/last seen 应带过来")
	}
	if udp.Proto != "udp" || udp.Port != 0 {
		t.Errorf("probe_reason=udp 的节点不该有可探测端点: %+v", udp)
	}
	if !hasNoteContaining(udp.Notes, "UDP") {
		t.Errorf("UDP 节点应留痕说明为什么没有端点，实得 %v", udp.Notes)
	}
	if udp.CFProbe != nil {
		t.Errorf("没有 tcp_probe 就不该造出观测: %+v", udp.CFProbe)
	}
}

func TestCDNPoolTruncatesToMaxNodes(t *testing.T) {
	f := newCDNFixture(t, time.Hour, 60*24*time.Hour)
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	res, err := NewCDN(NewClient("test"), cdnConfig(srv.URL, f.commit, true, 1, 24*30)).Fetch(context.Background())
	if err != nil {
		t.Fatalf("抓取失败: %v", err)
	}
	if len(res.PoolRows) != 1 {
		t.Fatalf("MaxNodes=1 应只留 1 个，实得 %d", len(res.PoolRows))
	}
	// 截断要留最新最值钱的：三个里分数 900 的那个信息量最大。
	if got := res.PoolRows[0].Node.HostName; got != "vpn-pool-1" {
		t.Errorf("保留的是 %s，期望 vpn-pool-1", got)
	}
}

// 累积池挂了不该把已经到手的单快照一起丢掉。
func TestCDNPoolFailureKeepsSnapshot(t *testing.T) {
	f := newCDNFixture(t, time.Hour, 60*24*time.Hour)
	f.poolIndex = []byte("not json")
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	res, err := NewCDN(NewClient("test"), cdnConfig(srv.URL, f.commit, true, 0, 24*7)).Fetch(context.Background())
	if err != nil {
		t.Fatalf("池坏了不该整体失败: %v", err)
	}
	if len(res.Rows) != 1 {
		t.Errorf("单快照数据应保留，实得 %d 行", len(res.Rows))
	}
	if !strings.HasPrefix(res.Checked["pool/latest.json"], "parse-failed") {
		t.Errorf("应记录池索引失败原因，实得 %v", res.Checked)
	}
}

func TestCDNPoolIndexMissing(t *testing.T) {
	f := newCDNFixture(t, time.Hour, 60*24*time.Hour)
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	cfg := cdnConfig(srv.URL, f.commit, true, 0, 24*7)
	cfg.IndexURL = srv.URL + "/pool/nope.json" // poolIndexURL 拼出一个不存在的路径
	cfg.IndexURL = srv.URL + "/latest.json"
	f.poolIndex = nil
	res, err := NewCDN(NewClient("test"), cfg).Fetch(context.Background())
	if err != nil {
		t.Fatalf("池索引 404 不该整体失败: %v", err)
	}
	if !strings.HasPrefix(res.Checked["pool/latest.json"], "fetch-failed") {
		t.Errorf("应记录拉取失败: %v", res.Checked)
	}
	if len(res.Rows) != 1 {
		t.Errorf("单快照还在: %d", len(res.Rows))
	}
}

func TestCDNFetchPoolConfig(t *testing.T) {
	f := newCDNFixture(t, time.Hour, 60*24*time.Hour)
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	cfg, err := NewCDN(NewClient("test"), cdnConfig(srv.URL, f.commit, true, 0, 0)).FetchPoolConfig(context.Background(), f.poolCommit, f.configSHA)
	if err != nil {
		t.Fatalf("按需拉配置失败: %v", err)
	}
	if string(cfg) != testConfig {
		t.Errorf("正文不对: %q", cfg)
	}

	if _, err := NewCDN(NewClient("test"), cdnConfig(srv.URL, f.commit, true, 0, 0)).FetchPoolConfig(context.Background(), "short", f.configSHA); err == nil {
		t.Error("commit 格式不对应报错")
	}
	if _, err := NewCDN(NewClient("test"), cdnConfig(srv.URL, f.commit, true, 0, 0)).FetchPoolConfig(context.Background(), f.poolCommit, "ZZ"); err == nil {
		t.Error("配置 sha 格式不对应报错")
	}
	// 文件里的 sha 与请求的不是同一个 → 内容不对，不能拿。
	if _, err := NewCDN(NewClient("test"), cdnConfig(srv.URL, f.commit, true, 0, 0)).FetchPoolConfig(context.Background(), f.poolCommit, strings.Repeat("c", 64)); err == nil {
		t.Error("按需路径找不到对应文件应报错")
	}
}

func TestCDNFetchPoolConfigBadSHA(t *testing.T) {
	f := newCDNFixture(t, time.Hour, 60*24*time.Hour)
	// 文件里声明的 sha 对，但正文换了 —— 解码后求 hash 必须拦下来。
	bad := marshal(t, map[string]any{
		"schema_version":        1,
		"openvpn_config_base64": base64.StdEncoding.EncodeToString([]byte("client\ndev tun\n")),
		"openvpn_config_sha256": f.configSHA,
		"openvpn_config_bytes":  len(testConfig),
	})
	f.poolConfig = bad
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	if _, err := NewCDN(NewClient("test"), cdnConfig(srv.URL, f.commit, true, 0, 0)).FetchPoolConfig(context.Background(), f.poolCommit, f.configSHA); err == nil ||
		!strings.Contains(err.Error(), "SHA-256 不匹配") {
		t.Fatalf("解码后 sha 不匹配应报错，实得 %v", err)
	}
}

func TestCDNClientFailure(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := NewCDN(NewClient("test"), cdnConfig(srv.URL, "x", false, 0, 0)).Fetch(context.Background()); err == nil {
		t.Error("索引 404 应报错")
	}
}
