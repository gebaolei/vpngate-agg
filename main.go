// Command vpngate-agg 聚合 VPN Gate 节点、测试连通性、检测 IP 纯净度，并提供 Web 界面。
//
// 整个工具只有一个二进制（前端用 go:embed 打进来），配置文件可选，
// 状态是几个 JSON 文件 —— 拷到机器上就能跑，不需要数据库。
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/app"
	"github.com/gebaolei/vpngate-agg/internal/config"
	"github.com/gebaolei/vpngate-agg/internal/model"
	"github.com/gebaolei/vpngate-agg/internal/purity"
	"github.com/gebaolei/vpngate-agg/internal/store"
	"github.com/gebaolei/vpngate-agg/internal/web"
)

// version 由 Makefile 用 -ldflags -X main.version=... 注入（值来自 git describe）。
// 这里的是不带 git 信息时（go build 直提）的默认值，跟最新 tag 保持同一步。
var version = "0.5.0"

const usageText = `vpngate-agg —— VPN Gate 节点聚合 / 连通测试 / IP 纯净度

用法:
  vpngate-agg [-config 路径] <子命令> [参数]

子命令:
  serve    启动 Web 界面 + 定时流水线（默认子命令）
  refresh  拉一轮节点源，写盘后退出
  probe    跑一轮连通测试
  purity   跑一轮 IP 纯净度检测
  export   导出 .ovpn（--out 写文件，否则 stdout）
  passwd   设置登录口令（不带参数则生成随机口令）
  sources  看各来源最近一轮拿到多少、淘汰与容量上限、哪些源现在是关着的（只读磁盘，不联网）
  version  打印版本
  help     打印本帮助

probe / purity / export 常用参数:
  -limit N        本轮上限，0 = 用配置里的值
  -force          忽略「刚测过就跳过」「长期失败先放过」「缓存没过期就不查」
  -country JP,US  只处理这些国家
  -proto tcp,udp  只处理这些协议

示例:
  vpngate-agg serve
  vpngate-agg refresh
  vpngate-agg probe -limit 200
  vpngate-agg export -country JP -proto udp -limit 10 -min-purity 80 -out jp.ovpn
`

func main() {
	args := os.Args[1:]
	cfgPath, args := extractConfigFlag(args)

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("读取配置失败: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("配置不合法: %v", err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		log.Fatalf("创建数据目录 %s 失败: %v", cfg.DataDir, err)
	}

	logger := log.New(os.Stderr, "[vpngate-agg] ", log.LstdFlags|log.Lmsgprefix)
	// 界面、健康检查、导出文件头里的版本号从这里取。不接上的话，
	// Makefile 只注入了 main.version，界面上会一直显示 dev。
	web.Version = version
	switch strings.ToLower(cfg.LogLevel) {
	case "error", "fatal":
		logger.SetPrefix("[vpngate-agg] ") // 级别由调用处控制，这里只统一前缀
	}

	cmd := "serve"
	if len(args) > 0 {
		cmd, args = strings.ToLower(args[0]), args[1:]
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var runErr error
	switch cmd {
	case "serve":
		runErr = runServe(ctx, cfg, logger, args)
	case "refresh":
		runErr = runRefresh(ctx, cfg, logger, args)
	case "probe":
		runErr = runProbe(ctx, cfg, logger, args)
	case "purity":
		runErr = runPurity(ctx, cfg, logger, args)
	case "export":
		runErr = runExport(ctx, cfg, logger, args)
	case "passwd":
		runErr = runPasswd(cfg, logger, args)
	case "sources":
		runErr = runSources(cfg, logger, args)
	case "version", "-v", "--version":
		fmt.Printf("vpngate-agg %s (%s)\n", version, runtime.Version())
	case "help", "-h", "--help":
		fmt.Fprint(os.Stderr, usageText)
	default:
		fmt.Fprint(os.Stderr, usageText)
		runErr = fmt.Errorf("未知子命令 %q", cmd)
	}
	if runErr != nil && runErr != context.Canceled {
		logger.Fatalf("执行失败: %v", runErr)
	}
}

// extractConfigFlag 让 -config 能出现在子命令前后任意位置。
// stdlib flag 做子命令时，全局参数必须先摘出来，否则子命令的 FlagSet 会报未知参数。
func extractConfigFlag(args []string) (string, []string) {
	var cfgPath string
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-config" || a == "--config":
			if i+1 < len(args) {
				cfgPath = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "-config="), strings.HasPrefix(a, "--config="):
			cfgPath = strings.SplitN(a, "=", 2)[1]
		default:
			out = append(out, a)
		}
	}
	return cfgPath, out
}

func runServe(ctx context.Context, cfg config.Config, logger *log.Logger, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	a, err := app.New(cfg, logger)
	if err != nil {
		return err
	}
	srv, err := web.New(cfg, a, logger)
	if err != nil {
		return err
	}

	// 定时流水线（刷新 → 探测 → 纯净度）和 HTTP 服务共用一个可取消的 ctx：
	// 任何一侧退出就整体退出，避免「界面还开着但后台已经不刷新」的半死状态 ——
	// 端口被占用时 Serve 会立刻返回，这时也不该留一条没人访问的流水线在跑。
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer cancel()
		a.Run(runCtx)
	}()
	go func() {
		defer cancel()
		if err := srv.Serve(runCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("[web] %v", err)
		}
	}()

	logger.Printf("数据目录 %s，配置 %s", cfg.DataDir, orDefault(cfg.Path(), "内置默认值"))
	if cfg.Auth.DisableAuth {
		logger.Printf("登录已关闭（auth.disable_auth=true）：能访问该端口的人都能操作")
	}

	<-runCtx.Done()
	// 退出前落盘一次：定时落盘的间隔可能是几分钟，不该丢掉刚测出来的结论。
	if err := a.SaveState(); err != nil {
		logger.Printf("退出前保存失败: %v", err)
	} else {
		logger.Printf("已保存状态并退出")
	}
	return nil
}

func runRefresh(ctx context.Context, cfg config.Config, logger *log.Logger, args []string) error {
	fs := flag.NewFlagSet("refresh", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := app.New(cfg, logger)
	if err != nil {
		return err
	}

	start := time.Now()
	job, err := a.Refresh(ctx)
	if err != nil {
		return err
	}
	st := a.Store().Stats()
	fmt.Printf("拉取完成: 池内 %d 个节点（本轮名单 %d），国家 %d，TCP %d / UDP %d，耗时 %s\n",
		st.PoolNodes, st.FreshNodes, st.Countries, st.TCP, st.UDP, time.Since(start).Round(time.Millisecond))
	if job != nil && job.Message != "" {
		fmt.Printf("备注: %s\n", job.Message)
	}
	for _, s := range st.Sources {
		note := s.Via
		if s.Err != "" {
			note = "失败: " + s.Err
		}
		if s.Skipped > 0 {
			note += fmt.Sprintf("（丢弃 %d）", s.Skipped)
		}
		fmt.Printf("  %-12s %6d 节点 %7dms  %s\n", s.Name, s.Nodes, s.MS, note)
	}
	fmt.Printf("纯净度已覆盖 %d 个 IP，中位纯净度 %d\n", st.PurityChecked, st.MedianPurity)
	return a.SaveState()
}

// runSources 打印当前开关和最近一轮各来源的结果。
//
// 排查「节点数怎么不涨了」先看这里：源被关掉和源在报错，在界面上长得太像了。
// 它只读磁盘上的池子，不联网，所以对着正在跑 serve 的数据目录也能用。
func runSources(cfg config.Config, logger *log.Logger, args []string) error {
	fs := flag.NewFlagSet("sources", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := app.New(cfg, logger)
	if err != nil {
		return err
	}
	st := a.Store().Stats()
	on := func(v bool) string {
		if v {
			return "开"
		}
		return "关"
	}
	at := func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Local().Format("2006-01-02 15:04:05")
	}

	fmt.Printf("池内 %d 个节点（本轮名单 %d），数据更新于 %s\n\n", st.PoolNodes, st.FreshNodes, at(st.UpdatedAt))
	fmt.Printf("开关: 官方主站 %s · 官方镜像 %s（每轮%s）· 自营机房 %s\n",
		on(cfg.Sources.Vpngate.Enabled), on(cfg.Sources.Mirrors.Enabled),
		mirrorsPerRoundText(cfg.Sources.Mirrors.MaxMirrors), on(cfg.Sources.KeepVpngateOwn))
	fmt.Printf("淘汰: 缺席满 %d 天过期；TCP 缺席满 %d 小时且连负 %d 轮明确失败则提前剔除\n",
		cfg.Sources.KeepDays, cfg.Sources.PurgeAbsentHours, cfg.Sources.PurgeFailRounds)
	// 容量上限是另一套规则：过期淘汰只看「多久没见」，容量裁剪只看「池子多大」。
	fmt.Printf("容量: 上限 %s（当前 %d）· 超出先请走硬伤的（不可达 / 名单里没有 / 从没测过），再按推荐分从低到高\n",
		maxNodesText(cfg.Sources.MaxNodes), st.PoolNodes)
	// 家宽拆开数：来源认定和推导差一个可信度；「类型未知」必须说出来，
	// 否则这个比例会被读成「绝大多数不是家宽」，而事实是没数据。
	fmt.Printf("家宽: %d 个（%.1f%%）— 来源认定 %d · 推导 %d；查过但类型未知 %d\n",
		st.Residential, st.ResidentialShare, st.ResidentialVerified, st.ResidentialDerived, st.PurityTypeUnknown)

	if len(st.Sources) == 0 {
		fmt.Println("\n还没有拉取记录，先跑一次 refresh。")
		return nil
	}
	fmt.Printf("\n最近一轮（%s）:\n", at(st.Sources[0].At))
	seen := map[string]bool{}
	for _, s := range st.Sources {
		note := s.Via
		if s.Err != "" {
			note = "失败: " + s.Err
		}
		if s.Skipped > 0 {
			note += fmt.Sprintf("（丢弃 %d）", s.Skipped)
		}
		switch {
		case s.Name == "vpngate":
			seen["vpngate"] = true
		case strings.HasPrefix(s.Name, "mirror:"):
			seen["mirror"] = true
		}
		fmt.Printf("  %-28s %6d 节点 %7dms  %s\n", s.Name, s.Nodes, s.MS, note)
	}

	// 关掉的源不会出现在上面那张表里，单独说一句；开着却没记录的也要说 ——
	// 那通常是被 min_nodes / 骤降保护拦下，或者整轮失败。
	var off, silent []string
	if !cfg.Sources.Vpngate.Enabled {
		off = append(off, "官方主站")
	}
	if !cfg.Sources.Mirrors.Enabled {
		off = append(off, "官方镜像站")
	}
	if cfg.Sources.Vpngate.Enabled && !seen["vpngate"] {
		silent = append(silent, "官方主站")
	}
	if cfg.Sources.Mirrors.Enabled && !seen["mirror"] {
		silent = append(silent, "官方镜像站")
	}
	if len(off) > 0 {
		fmt.Printf("\n已关闭: %s（界面设置页或配置里可以打开）\n", strings.Join(off, "、"))
	}
	if len(silent) > 0 {
		fmt.Printf("\n开着但上一轮没有任何记录: %s（多半是整轮失败，或被数量下限 / 骤降保护拦下）\n", strings.Join(silent, "、"))
	}
	return nil
}

// mirrorsPerRoundText 把 max_mirrors=0 说成「全部」，别让人以为每轮抓 0 个。
func mirrorsPerRoundText(n int) string {
	if n <= 0 {
		return "全部"
	}
	return strconv.Itoa(n)
}

// maxNodesText 把池子容量上限渲染成人话：0 = 不限。
func maxNodesText(n int) string {
	if n <= 0 {
		return "不限"
	}
	return strconv.Itoa(n)
}

func runProbe(ctx context.Context, cfg config.Config, logger *log.Logger, args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	limit := fs.Int("limit", 0, "本轮节点上限，0 用配置值")
	force := fs.Bool("force", false, "忽略冷却，全部重测")
	all := fs.Bool("all", false, "等价于 -force -limit 0")
	country := fs.String("country", "", "只测这些国家，逗号分隔")
	proto := fs.String("proto", "", "只测这些协议，逗号分隔")
	selection := fs.String("selection", "", "all / fresh / suspect，留空用配置值")
	concurrency := fs.Int("concurrency", 0, "并发数，0 用配置值")
	noHandshake := fs.Bool("no-handshake", false, "只测 TCP 连通，不发 OpenVPN 握手包")
	if err := fs.Parse(args); err != nil {
		return err
	}

	a, err := app.New(cfg, logger)
	if err != nil {
		return err
	}
	if a.Store().Count() == 0 {
		logger.Printf("节点池是空的，先拉一轮节点源")
		if _, err := a.Refresh(ctx); err != nil {
			return err
		}
	}

	o := app.ProbeOptions{
		Limit:       *limit,
		Selection:   *selection,
		Countries:   upperList(*country),
		Protocols:   lowerList(*proto),
		Force:       *force || *all,
		Concurrency: *concurrency,
	}
	if *all {
		o.Limit = 0
	}
	if *noHandshake {
		off := false
		o.Handshake = &off
	}

	// 先把本轮要打谁算出来打印：否则进度条从 0 开始爬，用户不知道还要等多久。
	targets, skipped := a.Targets(o)
	if len(targets) == 0 {
		printSkipped(skipped)
		return fmt.Errorf("本轮没有可探测的目标（先 refresh，或放宽 -country / -proto）")
	}
	fmt.Printf("本轮探测 %d 个端点…\n", len(targets))

	job, err := a.ProbeRound(ctx, o)
	if err != nil {
		return err
	}
	st := a.Store().Stats()
	fmt.Printf("探测完成: %d/%d 可达（失败 %d），中位延迟 %s，耗时 %s\n",
		job.OK, job.Total, job.Failed, store.FormatMS(st.MedianPingMS), jobDuration(job))
	if job.Message != "" {
		fmt.Printf("备注: %s\n", job.Message)
	}
	printSkipped(skipped)
	fmt.Printf("当前池: 可达 %d · 未知 %d · 不可达 %d · 未测 %d\n", st.Alive, st.Unknown, st.Down, st.Untested)
	return a.SaveState()
}

func runPurity(ctx context.Context, cfg config.Config, logger *log.Logger, args []string) error {
	fs := flag.NewFlagSet("purity", flag.ExitOnError)
	limit := fs.Int("limit", 0, "本轮 IP 上限，0 用配置值")
	force := fs.Bool("force", false, "忽略缓存有效期，全部重查")
	country := fs.String("country", "", "只查这些国家，逗号分隔")
	selection := fs.String("selection", "", "all / fresh / unchecked，留空用配置值")
	if err := fs.Parse(args); err != nil {
		return err
	}

	a, err := app.New(cfg, logger)
	if err != nil {
		return err
	}
	enabled := a.Purity().Enabled()
	if len(enabled) == 0 {
		return fmt.Errorf("没有可用的纯净度来源（免费源也被关掉了）")
	}
	fmt.Printf("使用来源: %s\n", strings.Join(enabled, ", "))

	job, err := a.PurityScan(ctx, app.PurityOptions{
		Limit:     *limit,
		Selection: *selection,
		Countries: upperList(*country),
		Force:     *force,
	})
	if err != nil {
		return err
	}
	fmt.Printf("纯净度检测完成: %d/%d 个 IP 查询成功，耗时 %s\n", job.OK, job.Total, jobDuration(job))
	if job.Message != "" {
		fmt.Printf("备注: %s\n", job.Message)
	}
	st := a.Store().Stats()
	fmt.Printf("已覆盖 %d 个 IP，中位纯净度 %d，家宽占比 %.1f%%\n",
		st.PurityChecked, st.MedianPurity, st.ResidentialShare)
	return a.SaveState()
}

func runExport(ctx context.Context, cfg config.Config, logger *log.Logger, args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	out := fs.String("out", "", "输出文件，留空写 stdout")
	q := fs.String("q", "", "关键词过滤（节点名 / IP / 运营商 / 留言 / 国家）")
	country := fs.String("country", "", "只导这些国家，逗号分隔")
	proto := fs.String("proto", "", "只导这些协议，逗号分隔")
	level := fs.String("level", "", "只导这些可达档位，如 stable,reachable")
	minPurity := fs.Int("min-purity", -1, "只导纯净度不低于该值的节点（-1 不限）")
	maxPing := fs.Int("max-ping", 0, "只导延迟不高于该值的节点（0 不限）")
	pingSource := fs.String("ping-source", "best", "延迟口径: best(本机实测 EWMA) / local(本机实测最近一次) / upstream(官方 Ping) / cloudflare")
	residential := fs.Bool("residential", false, "只导判定为志愿者家宽的节点")
	ownOnly := fs.Bool("own-only", false, "只导 VPN Gate 自营机房的节点（与 -residential 相反）")
	fresh := fs.Bool("fresh", false, "只导本轮官方名单里还在的节点")
	limit := fs.Int("limit", 50, "最多导出多少个，0 不限")
	list := fs.Bool("list", false, "只打印清单，不输出配置正文")
	if err := fs.Parse(args); err != nil {
		return err
	}

	a, err := app.New(cfg, logger)
	if err != nil {
		return err
	}
	if a.Store().Count() == 0 {
		return fmt.Errorf("节点池是空的，先跑一次 refresh")
	}

	f := store.Filter{
		Q:               strings.TrimSpace(*q),
		Countries:       upperList(*country),
		Protocols:       lowerList(*proto),
		Levels:          lowerList(*level),
		PingSource:      *pingSource,
		ResidentialOnly: *residential,
		FreshOnly:       *fresh,
		Sort:            "recommend",
		Desc:            false, // recommend 归一成「越小越好」，升序即最佳在前
		Limit:           max(*limit, 0),
	}
	if *minPurity >= 0 {
		v := *minPurity
		f.MinPurity = &v
	}
	if *maxPing > 0 {
		v := int64(*maxPing)
		f.MaxPing = &v
	}
	nodes := a.Store().List(f).Items
	// 「自营机房」是反向条件，store 里没有对应过滤项，只能在这里用内置规则筛。
	// 用内置规则而不是纯净度结论：后者要联网，导出最好离线也能用。
	if *ownOnly {
		var kept []*model.Node
		for _, n := range nodes {
			if own, _ := ownHosted(n); own {
				kept = append(kept, n)
			}
		}
		nodes = kept
	}
	if len(nodes) == 0 {
		return fmt.Errorf("没有符合条件的节点")
	}

	var w io.Writer = os.Stdout
	if *out != "" {
		fh, err := os.Create(*out)
		if err != nil {
			return err
		}
		defer fh.Close()
		w = fh
	}

	if *list {
		for _, n := range nodes {
			fmt.Fprintf(w, "%-30s %-16s:%-6d %-4s %-4s %8s  purity %-4s %s\n",
				n.HostName, n.IP, n.Port, strings.ToUpper(n.Proto), n.CountryCode,
				store.FormatMS(pingOf(n, *pingSource)), purityText(n.Purity), model.HealthLevelLabels[model.HealthLevel(n.Health)])
		}
		fmt.Fprintf(os.Stderr, "共 %d 个节点\n", len(nodes))
		return nil
	}

	fmt.Fprintf(os.Stderr, "正在取 %d 个节点的 .ovpn 正文（累积池节点的正文是按需拉的）…\n", len(nodes))
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# VPN Gate 节点导出（vpngate-agg %s）\n", version))
	sb.WriteString(fmt.Sprintf("# 时间 %s UTC · 条件: %s · 共 %d 个节点\n",
		time.Now().UTC().Format("2006-01-02 15:04"), exportCondition(f, *ownOnly), len(nodes)))
	ok := 0
	for _, n := range nodes {
		text, err := a.EnsureConfig(ctx, n.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  跳过 %s: %v\n", n.HostName, err)
			continue
		}
		ok++
		sb.WriteString(fmt.Sprintf("\n# ==== %s | %s:%d/%s | %s | 纯净度 %s ====\n",
			n.HostName, n.IP, n.Port, strings.ToUpper(n.Proto), n.Country, purityText(n.Purity)))
		sb.Write(text)
		if !strings.HasSuffix(string(text), "\n") {
			sb.WriteString("\n")
		}
	}
	if _, err := w.Write([]byte(sb.String())); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "已写出 %d/%d 个配置\n", ok, len(nodes))
	return nil
}

// runPasswd 直接写 dataDir/credentials.json。
// 磁盘上的凭据优先于 config 里的明文 —— 和界面上改过密码后重启不被覆盖是同一套规则。
func runPasswd(cfg config.Config, logger *log.Logger, args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	user := fs.String("user", "", "用户名，留空沿用现有的")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pw := strings.Join(fs.Args(), " ")

	type credentials struct {
		Username string    `json:"username"`
		PBKDF2   string    `json:"pbkdf2"`
		Updated  time.Time `json:"updated"`
	}
	path := cfg.DataDir + "/credentials.json"
	var cur credentials
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &cur) // 读不懂就重建，反正口令也要覆盖
	}
	if *user != "" {
		cur.Username = *user
	}
	if cur.Username == "" {
		cur.Username = orDefault(cfg.Auth.Username, "admin")
	}
	if pw == "" {
		buf := make([]byte, 12)
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		pw = hex.EncodeToString(buf)
		fmt.Printf("新生成的随机口令: %s\n", pw)
	}
	sum, err := web.HashPassword(pw)
	if err != nil {
		return err
	}
	cur.PBKDF2 = sum
	cur.Updated = time.Now().UTC()
	b, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	logger.Printf("口令已写入 %s（用户 %s）", path, cur.Username)
	return nil
}

// ownHosted 认「VPN Gate 自营机房」。store 里没有这个过滤维度，只能在导出侧判断。
// 连接地址要用 Addr() 给出的那个（.ovpn 里的 remote 优先），节点名才是规则的依据。
func ownHosted(n *model.Node) (bool, string) {
	return purity.BuiltinHosting(n.IP, n.HostName)
}

func pingOf(n *model.Node, src string) int64 {
	switch src {
	case "upstream":
		return n.UpstreamPingMS
	case "local":
		if n.Health.EWMAPingMS > 0 {
			return n.Health.EWMAPingMS
		}
		if n.Probe != nil && n.Probe.OK {
			return n.Probe.RTTMS
		}
		return 0
	case "cloudflare":
		if n.CFProbe != nil && n.CFProbe.ConnectMS != nil {
			return *n.CFProbe.ConnectMS
		}
		return 0
	default:
		// best：只看本机实测（EWMA → 最近一次成功的 RTT），不兜底官方 Ping 也
		// 不用 Cloudflare 观测 —— 要和界面上「延迟」列、与 store 的 best 口径一致。
		if n.Health.EWMAPingMS > 0 {
			return n.Health.EWMAPingMS
		}
		if n.Probe != nil && n.Probe.OK {
			return n.Probe.RTTMS
		}
		return 0
	}
}

func purityText(p *model.PurityResult) string {
	if p == nil {
		return "-"
	}
	return fmt.Sprintf("%d", p.Score)
}

func jobDuration(job *model.JobState) time.Duration {
	if job == nil || job.StartedAt.IsZero() {
		return 0
	}
	end := job.EndedAt
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(job.StartedAt).Round(time.Millisecond)
}

func printSkipped(skipped map[string]int) {
	if len(skipped) == 0 {
		return
	}
	fmt.Println("跳过统计:")
	for _, k := range sortedKeys(skipped) {
		fmt.Printf("  %-24s %d\n", k, skipped[k])
	}
}

func exportCondition(f store.Filter, ownOnly bool) string {
	var parts []string
	if len(f.Countries) > 0 {
		parts = append(parts, "国家="+strings.Join(f.Countries, "/"))
	}
	if len(f.Protocols) > 0 {
		parts = append(parts, "协议="+strings.Join(f.Protocols, "/"))
	}
	if f.Q != "" {
		parts = append(parts, "关键词="+f.Q)
	}
	if f.ResidentialOnly {
		parts = append(parts, "仅志愿者家宽")
	}
	if ownOnly {
		parts = append(parts, "仅自营机房")
	}
	if f.FreshOnly {
		parts = append(parts, "仅本轮名单")
	}
	if f.MinPurity != nil {
		parts = append(parts, fmt.Sprintf("纯净度≥%d", *f.MinPurity))
	}
	if f.MaxPing != nil {
		parts = append(parts, fmt.Sprintf("延迟≤%dms", *f.MaxPing))
	}
	if len(parts) == 0 {
		return "无（按推荐分取前若干）"
	}
	return strings.Join(parts, " · ")
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func upperList(s string) []string {
	l := splitList(s)
	for i := range l {
		l[i] = strings.ToUpper(l[i])
	}
	return l
}

func lowerList(s string) []string {
	l := splitList(s)
	for i := range l {
		l[i] = strings.ToLower(l[i])
	}
	return l
}

func splitList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
