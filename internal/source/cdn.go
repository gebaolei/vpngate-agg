package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/config"
	"github.com/gebaolei/vpngate-agg/internal/model"
)

// vpngate-list-mirror 的文档把「索引 → 定 commit → 校 hash → 再解析」写得很硬，
// 这里照做，一条不省。原因是 jsDelivr 的 @latest/@main 有 12 小时到 7 天的缓存，
// 不锚定 commit + 不校验 SHA 的话，一轮刷新可能读到跨 commit 的混合快照，
// 表现出来就是「节点数莫名其妙变了」，而你还以为是上游轮换。
var reCommitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var reLowerSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)

type cdnIndex struct {
	SchemaVersion     int       `json:"schema_version"`
	Kind              string    `json:"kind,omitempty"`
	SourceURL         string    `json:"source_url"`
	SourceUpdatedAt   *string   `json:"source_updated_at"`
	FetchedAt         time.Time `json:"fetched_at"`
	GeneratedAt       time.Time `json:"generated_at"`
	IndexGeneratedAt  time.Time `json:"index_generated_at"`
	DataCommit        string    `json:"data_commit"`
	SourceRecordCount int       `json:"source_record_count"`
	ServerCount       int       `json:"server_count"`
	CountryCount      int       `json:"country_count"`
	WorkflowRunURL    string    `json:"workflow_run_url,omitempty"`
	Files             map[string]struct {
		SHA256      string `json:"sha256"`
		Bytes       int64  `json:"bytes"`
		ServerCount int    `json:"server_count,omitempty"`
	} `json:"files"`
}

type cdnServers struct {
	SchemaVersion   int    `json:"schema_version"`
	SourceCSVSHA256 string `json:"source_csv_sha256"`
	ServerCount     int    `json:"server_count"`
	Servers         []struct {
		ID                string  `json:"id"`
		Hostname          string  `json:"hostname"`
		IP                string  `json:"ip"`
		CountryCode       *string `json:"country_code"`
		CountryName       *string `json:"country_name"`
		Score             *int64  `json:"score"`
		PingMS            *int64  `json:"ping_ms"`
		SpeedBps          *int64  `json:"speed_bps"`
		NumVpnSessions    *int64  `json:"num_vpn_sessions"`
		OpenVPNConfigB64  string  `json:"openvpn_config_base64"`
		OpenVPNConfigSHA  string  `json:"openvpn_config_sha256"`
		OpenVPNConfigSize int     `json:"openvpn_config_bytes"`
		// 以下只在 pool/servers.json 里出现
		FirstSeenAt     time.Time `json:"first_seen_at,omitempty"`
		LastSeenAt      time.Time `json:"last_seen_at,omitempty"`
		PresentInLatest *bool     `json:"present_in_latest_source,omitempty"`
		ProbeReason     string    `json:"probe_reason,omitempty"`
		ProbeTargets    []struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		} `json:"probe_targets,omitempty"`
		TCPProbe *struct {
			Status            string     `json:"status"`
			CheckedAt         *time.Time `json:"checked_at"`
			LastSuccessAt     *time.Time `json:"last_success_at"`
			ConnectMS         *int64     `json:"connect_ms"`
			ConnectedEndpoint *struct {
				IP   string `json:"ip"`
				Port int    `json:"port"`
			} `json:"connected_endpoint"`
			ConsecutiveFailures int    `json:"consecutive_failures"`
			ProbeSource         string `json:"probe_source"`
			Round               int64  `json:"round"`
		} `json:"tcp_probe"`
		Config *struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
			Bytes  int64  `json:"bytes"`
		} `json:"config,omitempty"`
	} `json:"servers"`
}

// CDNResult 是一次镜像抓取的结果。
type CDNResult struct {
	Rows       []RawRow // 单快照（data/servers.json）
	PoolRows   []RawRow // 累积池（pool/servers.json）
	Commit     string
	SnapshotAt time.Time // index.fetched_at
	PoolCommit string
	PoolAt     time.Time
	Checked    map[string]string // path → sha256，界面显示「校验过的文件」
}

// CDNFetcher 抓 vpngate-list-mirror。
type CDNFetcher struct {
	client *Client
	cfg    config.CDNSource
}

func NewCDN(client *Client, cfg config.CDNSource) *CDNFetcher {
	return &CDNFetcher{client: client, cfg: cfg}
}

// Fetch 读索引并按需读单快照与累积池。
//
// 累积池单独一个 commit：mirror 项目明确说了「不要把根 latest.json 和
// pool/latest.json 混用」，所以池子的文件必须用它自己索引里的 data_commit。
func (f *CDNFetcher) Fetch(ctx context.Context) (*CDNResult, error) {
	timeout := time.Duration(f.cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	res := &CDNResult{Checked: map[string]string{}}

	idxRaw, err := f.client.Get(ctx, f.cfg.IndexURL, IndexMaxBytes, timeout)
	if err != nil {
		return nil, fmt.Errorf("读取镜像索引失败: %w", err)
	}
	var idx cdnIndex
	if err := json.Unmarshal(idxRaw, &idx); err != nil {
		return nil, fmt.Errorf("解析镜像索引失败: %w", err)
	}
	if idx.SchemaVersion != 1 {
		return nil, fmt.Errorf("镜像索引 schema_version=%d，本工具只支持 1", idx.SchemaVersion)
	}
	if !reCommitSHA.MatchString(idx.DataCommit) {
		return nil, fmt.Errorf("镜像索引 data_commit 不是完整 40 位小写 SHA: %q", idx.DataCommit)
	}
	res.Commit = idx.DataCommit
	res.SnapshotAt = idx.FetchedAt

	srvRaw, err := f.getVerified(ctx, idx, "data/servers.json", DataMaxBytes, timeout)
	if err != nil {
		return nil, fmt.Errorf("读取 data/servers.json 失败: %w", err)
	}
	res.Checked["data/servers.json"] = shaHex(srvRaw)
	rows, err := f.parseServersJSON(srvRaw, "cdn", false)
	if err != nil {
		return nil, fmt.Errorf("解析 data/servers.json 失败: %w", err)
	}
	res.Rows = rows

	if !f.cfg.UsePool {
		return res, nil
	}
	poolIdxRaw, err := f.client.Get(ctx, poolIndexURL(f.cfg), IndexMaxBytes, timeout)
	if err != nil {
		// 累积池挂了不该把已经到手的单快照一起丢掉：调用方照样能用 res.Rows。
		res.PoolRows = nil
		res.Checked["pool/latest.json"] = "fetch-failed: " + err.Error()
		return res, nil
	}
	var pidx cdnIndex
	if err := json.Unmarshal(poolIdxRaw, &pidx); err != nil {
		res.Checked["pool/latest.json"] = "parse-failed: " + err.Error()
		return res, nil
	}
	if pidx.SchemaVersion != 1 || !reCommitSHA.MatchString(pidx.DataCommit) {
		res.Checked["pool/latest.json"] = fmt.Sprintf("不支持的池索引 schema=%d commit=%q", pidx.SchemaVersion, pidx.DataCommit)
		return res, nil
	}
	res.PoolCommit = pidx.DataCommit
	res.PoolAt = pidx.FetchedAt
	poolRaw, err := f.getVerifiedAt(ctx, pidx, "pool/servers.json", PoolMaxBytes, timeout, pidx.DataCommit)
	if err != nil {
		res.Checked["pool/servers.json"] = "fetch-failed: " + err.Error()
		return res, nil
	}
	res.Checked["pool/servers.json"] = shaHex(poolRaw)
	poolRows, err := f.parseServersJSON(poolRaw, "cdn-pool", true)
	if err != nil {
		res.Checked["pool/servers.json"] = "parse-failed: " + err.Error()
		return res, nil
	}
	res.PoolRows = poolRows
	return res, nil
}

// poolIndexURL 拼池索引地址。索引只在 Raw 上取：它是唯一的可变发现文档，
// 放 CDN 上会有缓存一致性问题。
func poolIndexURL(cfg config.CDNSource) string {
	base := strings.TrimSuffix(cfg.IndexURL, "/latest.json")
	if base == cfg.IndexURL {
		// 自定义索引文件名（比如 repo/index.json）时不能把文件名当目录留下，
		// 否则拼出 .../index.json/pool/latest.json 这种必然 404 的路径。
		if i := strings.LastIndex(base, "/"); i > strings.Index(base, "//")+1 {
			base = base[:i]
		}
	}
	return strings.TrimSuffix(base, "/") + "/pool/latest.json"
}

// getVerified 按索引描述取文件并校验 SHA-256 与字节数。
func (f *CDNFetcher) getVerified(ctx context.Context, idx cdnIndex, path string, maxBytes int64, timeout time.Duration) ([]byte, error) {
	return f.getVerifiedAt(ctx, idx, path, maxBytes, timeout, idx.DataCommit)
}

func (f *CDNFetcher) getVerifiedAt(ctx context.Context, idx cdnIndex, path string, maxBytes int64, timeout time.Duration, commit string) ([]byte, error) {
	desc, ok := idx.Files[path]
	if !ok {
		return nil, fmt.Errorf("索引里没有 %s", path)
	}
	if !reLowerSHA.MatchString(desc.SHA256) {
		return nil, fmt.Errorf("%s 的 sha256 不是 64 位小写十六进制: %q", path, desc.SHA256)
	}
	if desc.Bytes <= 0 || desc.Bytes > maxBytes {
		return nil, fmt.Errorf("%s 声明 %d 字节，超出本地 %d 上限", path, desc.Bytes, maxBytes)
	}

	// jsDelivr 优先（国内可达性好得多），失败再退回 GitHub Raw 的同一个 commit。
	candidates := []string{f.cfg.CDNBase + commit + "/" + path}
	if f.cfg.FallbackRaw {
		candidates = append(candidates, "https://raw.githubusercontent.com/"+f.cfg.Repo+"/"+commit+"/"+path)
	}
	var lastErr error
	for _, u := range candidates {
		raw, err := f.client.Get(ctx, u, maxBytes, timeout)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", u, err)
			continue
		}
		// 校验的是 HTTP 解码后的字节，不能对重新序列化后的 JSON 求 hash。
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != desc.SHA256 {
			lastErr = fmt.Errorf("%s 的 SHA-256 不匹配：期望 %s，实际 %s", u, desc.SHA256, got)
			continue
		}
		if int64(len(raw)) != desc.Bytes {
			lastErr = fmt.Errorf("%s 字节数不匹配：期望 %d，实际 %d", u, desc.Bytes, len(raw))
			continue
		}
		return raw, nil
	}
	return nil, lastErr
}

// parseServersJSON 把镜像的 servers.json / pool/servers.json 变成 RawRow。
//
// pool=true 时配置正文不在文件里（只有 hash 与 probe_targets）：
// 这类节点 ConfigLocal=false，端点用池子给出的已校验端点，
// 配置正文等界面上点开/下载时再按 sha 拉。
func (f *CDNFetcher) parseServersJSON(raw []byte, src string, pool bool) ([]RawRow, error) {
	var doc cdnServers
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("不是合法的 JSON: %w", err)
	}
	if doc.SchemaVersion != 1 {
		return nil, fmt.Errorf("schema_version=%d，只支持 1", doc.SchemaVersion)
	}
	if doc.ServerCount > 0 && doc.ServerCount != len(doc.Servers) {
		return nil, fmt.Errorf("server_count=%d 与 servers 数组长度 %d 不符", doc.ServerCount, len(doc.Servers))
	}

	limit := f.cfg.MaxNodes
	if limit <= 0 {
		limit = len(doc.Servers)
	}
	now := time.Now().UTC()
	maxAge := time.Duration(f.cfg.PoolMaxAgeHours) * time.Hour

	out := make([]RawRow, 0, min(limit, len(doc.Servers)))
	for i := range doc.Servers {
		s := &doc.Servers[i]
		n := &model.Node{
			ID:         s.ID,
			HostName:   s.Hostname,
			IP:         s.IP,
			LastSource: src,
		}
		if s.CountryCode != nil {
			n.CountryCode = normalizeCountry(*s.CountryCode)
		}
		if s.CountryName != nil {
			n.Country = *s.CountryName
		}
		n.UpstreamScore = derefInt64(s.Score)
		n.UpstreamPingMS = derefInt64(s.PingMS)
		n.UpstreamSpeedBps = derefInt64(s.SpeedBps)
		n.Sessions = derefInt64(s.NumVpnSessions)
		n.ConfigSHA256 = s.OpenVPNConfigSHA
		n.ConfigBytes = s.OpenVPNConfigSize

		// ID 与 hostname/IP 的推导关系自己复算一遍：这是 mirror 协议里
		// 最强的约束，复算不过就说明对方（或我们的实现）理解错了身份规则。
		hn, note := normalizeHostName(s.Hostname)
		if note != "" {
			n.Notes = append(n.Notes, note)
		}
		ip, ipNote := canonicalIP(s.IP)
		if ipNote != "" {
			if strings.HasPrefix(ipNote, "fatal:") {
				n.Notes = append(n.Notes, ipNote)
				continue
			}
			n.Notes = append(n.Notes, ipNote)
		}
		want := "v1:" + shaHex([]byte("vpngate-node-v1\x00"+hn+"\x00"+ip))
		if n.ID == "" {
			n.ID = want
		} else if n.ID != want {
			n.Notes = append(n.Notes, fmt.Sprintf("镜像给的 id 与本工具按协议复算的不一致（%s vs %s）", n.ID, want))
		}
		if !reLowerSHA.MatchString(n.ConfigSHA256) {
			n.Notes = append(n.Notes, "配置的 openvpn_config_sha256 缺失或格式不对")
		}

		if pool {
			n.FirstSeen, n.LastSeen = s.FirstSeenAt.UTC(), s.LastSeenAt.UTC()
			n.InLatestSource = s.PresentInLatest
			if !n.LastSeen.IsZero() && maxAge > 0 && now.Sub(n.LastSeen) > maxAge {
				continue // 池子里太久没被官方见过的，按配置丢掉，控制一轮探测规模
			}
			if s.PresentInLatest != nil && !*s.PresentInLatest && maxAge > 0 && !n.LastSeen.IsZero() && now.Sub(n.LastSeen) > maxAge {
				continue
			}
			// 端点用池子给出的已校验端点；UDP/复杂配置没有端点，就只能标未知。
			if len(s.ProbeTargets) > 0 {
				t := s.ProbeTargets[0]
				if tip, _ := canonicalIP(t.IP); tip != "" && t.Port > 0 && t.Port <= 65535 {
					n.Server, n.Port, n.Proto = tip, t.Port, "tcp"
				}
			}
			if n.Server == "" {
				n.Proto = "udp"
				switch s.ProbeReason {
				case "udp":
					n.Notes = append(n.Notes, "累积池判定为 UDP，无可探测端点（mirror 只测 TCP）")
				case "":
				default:
					n.Notes = append(n.Notes, "累积池未给端点，原因: "+s.ProbeReason)
				}
			}
			if tp := s.TCPProbe; tp != nil {
				cf := &model.CFProbe{
					Status:    tp.Status,
					Fails:     tp.ConsecutiveFailures,
					Source:    tp.ProbeSource,
					Round:     tp.Round,
					ConnectMS: tp.ConnectMS,
				}
				if tp.CheckedAt != nil {
					cf.CheckedAt = tp.CheckedAt.UTC()
				}
				if tp.LastSuccessAt != nil {
					cf.LastSuccess = tp.LastSuccessAt.UTC()
				}
				if tp.ConnectedEndpoint != nil {
					cf.Endpoint = fmt.Sprintf("%s:%d", tp.ConnectedEndpoint.IP, tp.ConnectedEndpoint.Port)
				}
				n.CFProbe = cf
			}
			// 配置正文不在文件里，点开时再按 sha 拉。
			n.ConfigLocal = false
			out = append(out, RawRow{Node: n})
			continue
		}

		// 单快照：配置就在文件里，直接解码 + 校验 hash，然后按 CSV 那套抽连接参数。
		cfg, err := decodeConfig(s.OpenVPNConfigB64)
		if err != nil {
			n.Notes = append(n.Notes, "fatal: 配置 base64 无法解码: "+err.Error())
			continue
		}
		if len(cfg) > maxConfigBytes {
			n.Notes = append(n.Notes, fmt.Sprintf("fatal: 配置 %d 字节超过上限", len(cfg)))
			continue
		}
		if got := shaHex(cfg); s.OpenVPNConfigSHA != "" && got != s.OpenVPNConfigSHA {
			n.Notes = append(n.Notes, "fatal: 解码后的配置 SHA-256 与声明不符")
			continue
		}
		n.ConfigLocal = true
		FillFromConfig(n, cfg)
		out = append(out, RawRow{Node: n, Config: cfg})
	}

	if !pool || len(out) <= limit {
		return out, nil
	}
	// 池子有 4900+ 个节点，一轮全测太吵。按「最近被官方看到」优先、
	// 其次按上游分数排序后截断，保证截掉的是最旧最没信息量的那批。
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Node, out[j].Node
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		if a.UpstreamScore != b.UpstreamScore {
			return a.UpstreamScore > b.UpstreamScore
		}
		return a.ID < b.ID
	})
	return out[:limit], nil
}

func derefInt64(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// CDNConfigRef 是按需拉取配置正文需要的定位信息。
type CDNConfigRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Commit string `json:"commit"`
}

// FetchPoolConfig 按 openvpn_config_sha256 拉某个累积池节点的 .ovpn 正文。
//
// 池子把配置拆成每节点一个 JSON（pool/configs/<解码后 sha>.json），4900+ 个
// 文件逐个拉一遍会把一轮刷新变成十几分钟，所以只在界面上点开/下载时拉。
// 这些文件不在索引 manifest 里（按节点分的），但它自带解码正文的 sha256 与
// 字节数，所以校验还是做得成的：解码 → 求 hash → 比对声明值。
func (f *CDNFetcher) FetchPoolConfig(ctx context.Context, commit, configSHA string) ([]byte, error) {
	if !reCommitSHA.MatchString(commit) {
		return nil, fmt.Errorf("池 commit 不是完整 40 位 SHA: %q", commit)
	}
	if !reLowerSHA.MatchString(configSHA) {
		return nil, fmt.Errorf("配置 sha256 格式不对: %q", configSHA)
	}
	path := "pool/configs/" + configSHA + ".json"
	timeout := time.Duration(f.cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	candidates := []string{f.cfg.CDNBase + commit + "/" + path}
	if f.cfg.FallbackRaw {
		candidates = append(candidates, "https://raw.githubusercontent.com/"+f.cfg.Repo+"/"+commit+"/"+path)
	}
	var lastErr error
	for _, u := range candidates {
		raw, err := f.client.Get(ctx, u, 1<<20, timeout)
		if err != nil {
			lastErr = fmt.Errorf("%s: %w", u, err)
			continue
		}
		var doc struct {
			Kind   string `json:"kind"`
			Schema int    `json:"schema_version"`
			B64    string `json:"openvpn_config_base64"`
			SHA256 string `json:"openvpn_config_sha256"`
			Bytes  int    `json:"openvpn_config_bytes"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			lastErr = fmt.Errorf("%s 不是合法 JSON: %w", u, err)
			continue
		}
		if doc.Schema != 0 && doc.Schema != 1 {
			lastErr = fmt.Errorf("%s schema_version=%d 不支持", u, doc.Schema)
			continue
		}
		if doc.SHA256 != "" && doc.SHA256 != configSHA {
			lastErr = fmt.Errorf("%s 声明的配置 sha 与请求不符", u)
			continue
		}
		cfg, err := decodeConfig(doc.B64)
		if err != nil {
			lastErr = fmt.Errorf("%s 里的 base64 无法解码: %w", u, err)
			continue
		}
		if got := shaHex(cfg); got != configSHA {
			lastErr = fmt.Errorf("%s 解码后的 SHA-256 不匹配：期望 %s，实际 %s", u, configSHA, got)
			continue
		}
		if doc.Bytes > 0 && doc.Bytes != len(cfg) {
			lastErr = fmt.Errorf("%s 解码字节数不匹配：期望 %d，实际 %d", u, doc.Bytes, len(cfg))
			continue
		}
		return cfg, nil
	}
	return nil, lastErr
}
