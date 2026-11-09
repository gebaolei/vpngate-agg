package web

// 对外只读接口：GET /vpngate/api/iphone/
//
// 为什么要单独一条路由，而不是让外面直接调 /api/nodes：
// 那套接口是给内嵌前端用的，鉴权是「签名 cookie + 写操作 CSRF」，机器对机器
// 要借用它就得先登录、再解析 csrf，口令一改就断，也没法按调用方审计。
// 这条路由只读、只吃 api.token，字段名对齐官方 https://www.vpngate.net/api/iphone/
// 的 15 列，调用方把 host 换掉就能用；它跟 UI 的 /api/* 完全分开，反代上可以给
// 这个前缀单独放行或单独限流。
//
// 约定：
//   - 成功是 JSON 数组（不是 {"ok":true,...} 那层壳）——因为调用方按官方形状解析
//   - 失败仍是 {"ok":false,"error":...}，用 HTTP 状态码区分：
//     401 token 不对、404 接口没开、422 参数不对、429 超速率
//   - 默认按 Score 从高到低（官方就是这顺序），?sort=&dir=&offset= 可以翻页

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// vpngateRow 是官方 /api/iphone/ 的一行，字段名与列顺序跟它一致。
//
// 这里刻意不用本地字段名（upstream_score 之类）：这条接口的全部意义就是
// 「长得跟官方一样」，改名就得让调用方写转换层。本地的观测（探测档位、
// 纯净度分数）不走这里，要那些走 /api/nodes。
//
// 只有 OpenVPN_ConfigData_Base64 带 omitempty：?config=0 或配置里关掉正文列时
// 这一列整个不出现，而不是给一个空串让调用方以为「有配置但是空的」。
type vpngateRow struct {
	HostName         string `json:"HostName"`
	IP               string `json:"IP"`
	Score            int64  `json:"Score"`
	Ping             int64  `json:"Ping"`
	Speed            int64  `json:"Speed"`
	CountryLong      string `json:"CountryLong"`
	CountryShort     string `json:"CountryShort"`
	NumVpnSessions   int64  `json:"NumVpnSessions"`
	Uptime           int64  `json:"Uptime"`
	TotalUsers       int64  `json:"TotalUsers"`
	TotalTraffic     int64  `json:"TotalTraffic"`
	LogType          string `json:"LogType"`
	Operator         string `json:"Operator"`
	Message          string `json:"Message"`
	OpenVPNConfigB64 string `json:"OpenVPN_ConfigData_Base64,omitempty"`
}

// handleVpngateAPI 吐节点名单，形状对齐官方接口。
func (s *Server) handleVpngateAPI(w http.ResponseWriter, r *http.Request) {
	cfg := s.app.Config().API
	f, err := parseFilter(r) // 参数与界面那套完全一致：country/proto/q/limit/offset…
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	q := r.URL.Query()
	// sort / dir 是对外契约的一部分，得自己把关：store 里未知的 sort 会默默退回
	// recommend，那等于调用方写了 ?sort=uptime 却拿到另一套顺序。
	sortKey := strings.ToLower(strings.TrimSpace(q.Get("sort")))
	if sortKey == "" {
		sortKey = "score" // 官方名单就是按 Score 从高到低给的
	}
	if _, ok := apiSortKeys[sortKey]; !ok {
		writeErr(w, http.StatusUnprocessableEntity, "sort 只能是 "+strings.Join(apiSortKeyList, "/")+"，实得 "+strconv.Quote(sortKey))
		return
	}
	f.Sort = sortKey
	// dir 说的是「这一列的值从大到小」，跟界面那个 dir 不是一套口径：store 里
	// 「越大越好」的列（score/speed/sessions/purity/recommend/seen）内部先把值取负
	// 归一成「越小越好」，所以 Desc=false 才是分数最高的在前（见 store/query.go）。
	// 调用方看的是 Score 这一列，不该被内部归一化反噬 —— 这里把方向换算回来。
	rawDesc := true
	if v := strings.TrimSpace(q.Get("dir")); v != "" {
		rawDesc = strings.EqualFold(v, "desc")
	}
	f.Desc = rawDesc
	if apiBiggerIsBetter[sortKey] {
		f.Desc = !rawDesc
	}
	limit := cfg.MaxNodes
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	if q.Has("limit") {
		if f.Limit > limit {
			f.Limit = limit
		}
	} else {
		f.Limit = limit
	}
	wantConfig := cfg.IncludeConfig && !isFalsyFlag(q.Get("config"))

	res := s.app.Store().List(f)
	rows := make([]vpngateRow, 0, len(res.Items))
	skipped := 0
	for _, n := range res.Items {
		row := vpngateRow{
			HostName:       n.HostName,
			IP:             n.IP,
			Score:          n.UpstreamScore,
			Ping:           n.UpstreamPingMS,
			Speed:          n.UpstreamSpeedBps,
			CountryLong:    n.Country,
			CountryShort:   n.CountryCode,
			NumVpnSessions: n.Sessions,
			Uptime:         n.UptimeSeconds,
			TotalUsers:     n.TotalUsers,
			TotalTraffic:   n.TotalTraffic,
			LogType:        n.LogType,
			Operator:       n.Operator,
			Message:        n.Message,
		}
		if wantConfig {
			// 正文按 sha 读盘，不信 config_local —— 那个标记只说「抓取那一轮有没有
			// 拿到正文」，盘上其实有没有得问文件系统。
			body, ok := s.app.Store().Config(n.ConfigSHA256)
			if !ok {
				// 累积池导入的老节点可能从没拉过正文。官方格式里这一列就是可连接的
				// 配置本体，给空串等于塞一个连不上的节点进名单，所以整行跳过并报数。
				skipped++
				continue
			}
			row.OpenVPNConfigB64 = base64.StdEncoding.EncodeToString(body)
		}
		rows = append(rows, row)
	}

	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	// 名单本身分钟级变（刷新是一小时一轮），给 30 秒私有缓存能挡住脚本连打，
	// 又不会让调用方读到十几分钟前的老数据。
	h.Set("Cache-Control", "private, max-age=30")
	h.Set("X-Vpngate-Agg-Rows", strconv.Itoa(len(rows)))
	h.Set("X-Vpngate-Agg-Skipped", strconv.Itoa(skipped)) // 缺正文被跳过的行数
	h.Set("X-Vpngate-Agg-Total", strconv.Itoa(res.Total)) // 筛选命中总数（不等于本次返回数）
	h.Set("X-Vpngate-Agg-Limit", strconv.Itoa(f.Limit))
	h.Set("X-Vpngate-Agg-Offset", strconv.Itoa(f.Offset))
	if err := json.NewEncoder(w).Encode(rows); err != nil {
		log.Printf("[web] 对外接口编码失败: %v", err)
	}
}

// requireAPI 是对外接口的闸门：没开就 404（不给外面「这里有个东西但不让你进」的
// 探测信号），token 不对 401，超速率 429。
//
// 用 Authorization: Bearer 而不是会话 cookie，就是为了这条路由不需要 CSRF：
// 浏览器要跨站带上自定义头必须先过 preflight，而我们不给 CORS 头 —— 天然挡住。
func (s *Server) requireAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := s.app.Config().API
		if !cfg.Enabled || strings.TrimSpace(cfg.Token) == "" {
			writeErr(w, http.StatusNotFound, "接口不存在")
			return
		}
		if !s.apiRate.allow(realIP(r), cfg.RatePerMinute) {
			w.Header().Set("Retry-After", "15")
			writeErr(w, http.StatusTooManyRequests, "请求过于频繁，请稍后再试")
			return
		}
		if !apiTokenOK(r, cfg.Token) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="vpngate-agg"`)
			writeErr(w, http.StatusUnauthorized, "缺少或错误的 api token")
			return
		}
		next(w, r)
	}
}

// apiTokenOK 取 token：优先 Authorization: Bearer，其次 ?key=（给 curl 和
// 只能填 URL 的客户端留着）。裸 token 不带 "Bearer " 前缀也认，少一层踩坑。
// 比较走定长比较，别让人用时序差逐字节猜。
func apiTokenOK(r *http.Request, want string) bool {
	var got string
	if h := strings.TrimSpace(r.Header.Get("Authorization")); h != "" {
		if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
			got = strings.TrimSpace(h[7:])
		} else {
			got = h
		}
	}
	if got == "" {
		got = strings.TrimSpace(r.URL.Query().Get("key"))
	}
	return got != "" && subtleEqual(got, want)
}

// apiSortKeys 是对外接口认的排序键。名字尽量贴着官方列名（Score/Ping/Speed/
// NumVpnSessions），本地才有的几个（purity/rtt/seen/recommend）另列。
var apiSortKeys = map[string]string{
	"score":     "Score",
	"ping":      "Ping",
	"speed":     "Speed",
	"sessions":  "NumVpnSessions",
	"hostname":  "HostName",
	"purity":    "纯净度分数",
	"rtt":       "本地实测延迟",
	"seen":      "最后一次见到",
	"recommend": "本工具的推荐分",
}

// apiSortKeyList 是给错误提示用的固定顺序（map 遍历顺序不稳定，报错文案会飘）。
var apiSortKeyList = []string{"score", "ping", "speed", "sessions", "hostname", "purity", "rtt", "seen", "recommend"}

// apiBiggerIsBetter 标记「值越大越该排在前面」的列，用来把 dir 换算成 store 的口径。
var apiBiggerIsBetter = map[string]bool{
	"score": true, "speed": true, "sessions": true,
	"purity": true, "recommend": true, "seen": true,
}

// isFalsyFlag 认 0/false/no/off 三种关法：?config=0 是「关掉这一列」，
// 而 ?config=1 / ?config=true 是显式要。缺参数不算关。
//
// 注意方向：include_config=false 是运维层面的上限（不给外面送正文），
// 查询参数只能往下关，不能把这一列要回来 —— 否则配置里那个开关形同虚设。
func isFalsyFlag(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off":
		return true
	}
	return false
}

// apiRate 是按来源 IP 的固定窗口限流（一分钟一格）。
//
// 只有一条只读查询要挡，用不着令牌桶：一分钟一格足以挡住「脚本每秒打一次扫全库」，
// 误伤的是同一个 NAT 后面几十台机器一起拉名单 —— 那种场景把 rate_per_minute 调大就行。
type apiRate struct {
	mu    sync.Mutex
	slots map[string]rateSlot
	// 上次清理时间：map 只进不出会被伪造 IP 撑爆，所以隔一阵删一次过期格子。
	lastPrune time.Time
}

type rateSlot struct {
	minute int64
	n      int
}

func newAPIRate() *apiRate {
	return &apiRate{slots: map[string]rateSlot{}, lastPrune: time.Now()}
}

// allow 记录一次访问并回答放不放行。limit<=0 表示不限流（也不记账，省得白占内存）。
func (l *apiRate) allow(ip string, limit int) bool {
	if limit <= 0 {
		return true
	}
	if ip == "" {
		ip = "?"
	}
	now := time.Now()
	minute := now.Unix() / 60
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastPrune) > 2*time.Minute {
		for k, v := range l.slots {
			if v.minute < minute {
				delete(l.slots, k)
			}
		}
		l.lastPrune = now
	}
	cur := l.slots[ip]
	if cur.minute != minute {
		cur = rateSlot{minute: minute}
	}
	cur.n++
	l.slots[ip] = cur
	return cur.n <= limit
}
