package app

import (
	"context"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/config"
	"github.com/gebaolei/vpngate-agg/internal/model"
	"github.com/gebaolei/vpngate-agg/internal/purity"
	"github.com/gebaolei/vpngate-agg/internal/source"
	"github.com/gebaolei/vpngate-agg/internal/store"
)

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func testApp(t *testing.T) *App {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	// 纯净度只用内置规则：这些用例测的是「挑哪些目标」，不碰网络。
	cfg.Purity.Providers = map[string]bool{"builtin": true, "ipquery": false, "ipinfo": false,
		"scamalytics": false, "abuseipdb": false, "ipregistry": false, "ipqualityscore": false}
	a, err := New(cfg, discardLogger())
	if err != nil {
		t.Fatalf("装配 App 失败: %v", err)
	}
	return a
}

func aggOf(nodes ...*model.Node) *source.Aggregated {
	agg := &source.Aggregated{Nodes: map[string]*model.Node{}, Configs: map[string][]byte{}, CountsByURL: map[string]int{}}
	for _, n := range nodes {
		agg.Nodes[n.ID] = n
	}
	return agg
}

func seed(t *testing.T, a *App, nodes ...*model.Node) {
	t.Helper()
	a.store.ApplyRefresh(aggOf(nodes...), store.Eviction{KeepDays: 7})
}

// 一轮探测结束要把「明确失败」结算成连续失败轮数 —— 提前淘汰全看这个数。
//
// 127.0.0.1 会被探测当成「本地策略拦截」（回环地址出现在节点名单里本身就是脏数据），
// 这是确定结论，所以该计数。「连上就清零」和「超时不算」在 store 层的
// TestApplyRefreshPurgesDeadTCPEarly 里测，那里不用碰本机网络。
func TestProbeRoundSettlesFailRounds(t *testing.T) {
	a := testApp(t)
	seed(t, a, node("v1:dead", "127.0.0.1", "JP", "tcp", 1))

	if _, err := a.ProbeRound(context.Background(), ProbeOptions{}); err != nil {
		t.Fatalf("探测轮失败: %v", err)
	}
	if n, _ := a.store.Get("v1:dead"); n.DownRounds != 1 {
		t.Errorf("明确失败的节点轮数 = %d，期望 1；probe=%+v", n.DownRounds, n.Probe)
	}

	// 补测轮不能再算一轮，否则同一轮被数两次、淘汰提前一倍。
	if _, err := a.ProbeRound(context.Background(), ProbeOptions{
		RetryPass: true, Selection: "all", Force: true, Protocols: []string{"tcp"},
	}); err != nil {
		t.Fatalf("补测轮失败: %v", err)
	}
	if n, _ := a.store.Get("v1:dead"); n.DownRounds != 1 {
		t.Errorf("补测轮把轮数算成了 %d，期望仍是 1", n.DownRounds)
	}
}

func node(id, ip, country, proto string, port int) *model.Node {
	return &model.Node{
		ID: id, HostName: id, IP: ip, Server: ip, Port: port, Proto: proto,
		Country: country, CountryCode: country,
		ConfigSHA256: "sha-" + strings.Repeat("a", 61),
		FirstSeen:    time.Now().UTC().Add(-24 * time.Hour),
		LastSeen:     time.Now().UTC(),
	}
}

func probeAt(t *testing.T, a *App, id string, ago time.Duration, ok bool, service string) {
	t.Helper()
	n, found := a.store.Get(id)
	if !found {
		t.Fatalf("节点 %s 不在池子里", id)
	}
	a.store.ApplyProbeResults(map[string]*model.ProbeResult{
		id: {At: time.Now().UTC().Add(-ago), OK: ok, Host: n.IP, Port: n.Port, Proto: n.Proto, Service: service},
	}, 8)
}

// 探测目标挑选是整个工具最值钱的一段策略：一轮只有那么多个额度，
// 谁先进这一轮必须讲得出口。
func TestTargetsSelectionStrategies(t *testing.T) {
	a := testApp(t)
	seed(t, a,
		node("v1:fresh", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:stale", "8.8.8.2", "US", "udp", 1194))
	// 下一轮官方名单里只剩 fresh；stale 只是「本轮没见到」，不是死了。
	a.store.ApplyRefresh(aggOf(node("v1:fresh", "8.8.8.1", "JP", "tcp", 1194)), store.Eviction{KeepDays: 7})
	// stale 明确被拒过两次 → down；fresh 从没测过（untested）。
	probeAt(t, a, "v1:stale", 2*time.Hour, false, model.ServiceRefused)
	probeAt(t, a, "v1:stale", time.Hour, false, model.ServiceRefused)
	if n, _ := a.store.Get("v1:stale"); model.HealthLevel(n.Health) != "down" {
		t.Fatalf("前置条件不成立: %+v", n.Health)
	}
	if a.store.Count() != 2 {
		t.Fatalf("池内 %d 个", a.store.Count())
	}

	// fresh：只测本轮官方名单里的。
	targets, skipped := a.Targets(ProbeOptions{Selection: "fresh"})
	if len(targets) != 1 || targets[0].ID != "v1:fresh" {
		t.Errorf("fresh 选择应只给本轮名单里的节点，实得 %v（跳过 %v）", idsOf(targets), skipped)
	}
	if skipped["不在本轮官方名单"] != 1 {
		t.Errorf("跳过的原因要写清楚，界面和日志都靠它解释「为什么只测了一个」: %v", skipped)
	}

	// all：池子里的全部（含已经不在名单里的）。
	targets, _ = a.Targets(ProbeOptions{Selection: "all"})
	if len(targets) != 2 {
		t.Errorf("all 应给 2 个，实得 %v", idsOf(targets))
	}

	// suspect：只挑状态可疑的；没测过的不在 suspect 范围里（另有优先级）。
	targets, skipped = a.Targets(ProbeOptions{Selection: "suspect"})
	if len(targets) != 1 || targets[0].ID != "v1:stale" {
		t.Errorf("suspect 应只给状态可疑的，实得 %v（跳过 %v）", idsOf(targets), skipped)
	}
	if skipped["状态良好，本轮跳过"] != 1 {
		t.Errorf("被 suspect 放过的要记账: %v", skipped)
	}

	// ids：界面「测这一个」，不该被 selection 再过滤一遍。
	targets, _ = a.Targets(ProbeOptions{Selection: "fresh", IDs: []string{"v1:stale"}})
	if len(targets) != 1 || targets[0].ID != "v1:stale" {
		t.Errorf("指定 ID 时该无视 selection 过滤，实得 %v", idsOf(targets))
	}
	targets, _ = a.Targets(ProbeOptions{IDs: []string{"v1:不存在"}})
	if len(targets) != 0 {
		t.Errorf("指定了不存在的 ID 应给空，实得 %v", idsOf(targets))
	}

	// 写错的 selection 不该把一轮变成「什么都不测」。
	targets, skipped = a.Targets(ProbeOptions{Selection: "随便写的"})
	if len(targets) != 2 {
		t.Errorf("未知 selection 应按 all 处理，实得 %v（跳过 %v）", idsOf(targets), skipped)
	}
	if skipped["未知 selection，按 all 处理"] != 2 {
		t.Errorf("未知 selection 要记一笔，免得用户以为过滤器坏了: %v", skipped)
	}

	// 走配置默认（Selection 留空）。
	a.setCfg(func(c *config.Config) { c.Probe.Selection = "fresh" })
	targets, _ = a.Targets(ProbeOptions{})
	if len(targets) != 1 || targets[0].ID != "v1:fresh" {
		t.Errorf("留空时应回落到 probe.selection，实得 %v", idsOf(targets))
	}
}

func TestTargetsCountryAndProtoFilters(t *testing.T) {
	a := testApp(t)
	unknown := node("v1:none", "8.8.8.3", "", "tcp", 443)
	unknown.Country, unknown.CountryCode = "", ""
	seed(t, a,
		node("v1:jp", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:us", "8.8.8.2", "US", "udp", 1194),
		unknown)

	targets, skipped := a.Targets(ProbeOptions{Selection: "all", Countries: []string{"jp"}})
	if len(targets) != 1 || targets[0].ID != "v1:jp" {
		t.Errorf("国家过滤（小写也要认）= %v，跳过 %v", idsOf(targets), skipped)
	}
	if skipped["国家不符"] != 2 {
		t.Errorf("被国家过滤掉的要记账: %v", skipped)
	}
	// 没有国家码的节点落在 "?" 这一桶，不能两个筛选都漏掉它。
	targets, _ = a.Targets(ProbeOptions{Selection: "all", Countries: []string{"?"}})
	if len(targets) != 1 || targets[0].ID != "v1:none" {
		t.Errorf("未知国家该能用 ? 选中，实得 %v", idsOf(targets))
	}
	targets, skipped = a.Targets(ProbeOptions{Selection: "all", Protocols: []string{"UDP"}})
	if len(targets) != 1 || targets[0].ID != "v1:us" {
		t.Errorf("协议过滤 = %v，跳过 %v", idsOf(targets), skipped)
	}
	if skipped["协议不符"] != 2 {
		t.Errorf("协议跳过数 = %v", skipped)
	}
	// 国家写错了不该静默返回全部。
	if targets, _ := a.Targets(ProbeOptions{Selection: "all", Countries: []string{"ZZ"}}); len(targets) != 0 {
		t.Errorf("不存在的国家应筛出空，实得 %v", idsOf(targets))
	}
}

// 刚测过的不能 10 分钟内再打一遍：界面上连点两次、
// 或者定时器和手动触发撞在一起，都会对同一个端口造成 SYN 风暴。
func TestTargetsSkipsRecentlyProbedUnlessForced(t *testing.T) {
	a := testApp(t)
	seed(t, a, node("v1:recent", "8.8.8.1", "JP", "tcp", 1194), node("v1:old", "8.8.8.2", "JP", "tcp", 1194))
	probeAt(t, a, "v1:recent", 3*time.Minute, true, model.ServiceSoftEther)
	probeAt(t, a, "v1:old", 3*time.Hour, true, model.ServiceSoftEther)

	targets, skipped := a.Targets(ProbeOptions{Selection: "all"})
	if len(targets) != 1 || targets[0].ID != "v1:old" {
		t.Errorf("3 分钟前刚测过的该跳过，实得 %v（跳过 %v）", idsOf(targets), skipped)
	}
	if skipped["10 分钟内刚测过"] != 1 {
		t.Errorf("跳过原因不对: %v", skipped)
	}
	targets, _ = a.Targets(ProbeOptions{Selection: "all", Force: true})
	if len(targets) != 2 {
		t.Errorf("Force 该绕开「刚测过」，实得 %v", idsOf(targets))
	}
}

// 长期失败、很久没成功过的节点先放一放，把额度留给有变化的 ——
// 但必须留一条回来的路（Force，或者用户点「测一下」）。
func TestTargetsSkipLongDown(t *testing.T) {
	a := testApp(t)
	seed(t, a, node("v1:down", "8.8.8.1", "JP", "tcp", 1194))
	// 最后一次成功是 3 天前，之后连着被拒两次。
	probeAt(t, a, "v1:down", 72*time.Hour, true, model.ServiceSoftEther)
	probeAt(t, a, "v1:down", 2*time.Hour, false, model.ServiceRefused)
	probeAt(t, a, "v1:down", time.Hour, false, model.ServiceRefused)
	if n, _ := a.store.Get("v1:down"); model.HealthLevel(n.Health) != "down" {
		t.Fatalf("前置条件不成立: %+v", n.Health)
	}

	targets, skipped := a.Targets(ProbeOptions{Selection: "all"})
	if len(targets) != 0 || skipped["长期失败，暂缓"] != 1 {
		t.Errorf("长期失败的节点该被暂缓，实得 %v / %v", idsOf(targets), skipped)
	}
	if targets, _ := a.Targets(ProbeOptions{Selection: "all", Force: true}); len(targets) != 1 {
		t.Errorf("Force 该把它捞回来（用户手动点「测一下」时必须能测）: %v", idsOf(targets))
	}
	if targets, _ := a.Targets(ProbeOptions{Selection: "suspect"}); len(targets) != 0 {
		t.Errorf("暂缓的策略对 suspect 也要生效，实得 %v", idsOf(targets))
	}

	// 阈值设成 0 就等于关掉这个策略。
	a.setCfg(func(c *config.Config) { c.Probe.SkipDownForHours = 0 })
	if targets, _ := a.Targets(ProbeOptions{Selection: "all"}); len(targets) != 1 {
		t.Errorf("SkipDownForHours=0 时不该暂缓，实得 %v", idsOf(targets))
	}
}

// 一轮只有 MaxNodesPerRound 个额度，谁先进这一轮要有稳定的排序：
// 没测过的 > 最久没测的 > 推荐分高的。
func TestTargetsPrioritiesAndLimit(t *testing.T) {
	a := testApp(t)
	seed(t, a,
		node("v1:untested", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:oldest", "8.8.8.2", "JP", "tcp", 1194),
		node("v1:recent", "8.8.8.3", "JP", "tcp", 1194))
	probeAt(t, a, "v1:oldest", 20*time.Hour, true, model.ServiceSoftEther)
	probeAt(t, a, "v1:recent", 30*time.Minute, true, model.ServiceSoftEther)

	targets, _ := a.Targets(ProbeOptions{Selection: "all"})
	want := []string{"v1:untested", "v1:oldest", "v1:recent"}
	if got := idsOf(targets); !equalStrings(got, want) {
		t.Errorf("顺序 = %v，期望 %v（没测过的最优先，然后最久没测的）", got, want)
	}

	targets, skipped := a.Targets(ProbeOptions{Selection: "all", Limit: 2})
	if len(targets) != 2 {
		t.Errorf("Limit 没生效: %v", idsOf(targets))
	}
	if skipped["超出本轮上限"] != 1 {
		t.Errorf("被上限挤掉的要记账，界面才知道本轮为什么只测了两个: %v", skipped)
	}

	// 配置里的上限也要生效（Limit=0 时回落到它）。
	a.setCfg(func(c *config.Config) { c.Probe.MaxNodesPerRound = 1 })
	targets, _ = a.Targets(ProbeOptions{Selection: "all"})
	if len(targets) != 1 {
		t.Errorf("配置上限没生效: %v", idsOf(targets))
	}
}

// 同一个端点上往往挂着好几个 VPN Gate 节点（志愿者换了 hostname
// 但没换端口），一轮里同一个端点只该打一次。
func TestTargetsDedupeSameEndpoint(t *testing.T) {
	a := testApp(t)
	seed(t, a,
		node("v1:a", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:b", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:c", "8.8.8.1", "JP", "udp", 1194))

	targets, skipped := a.Targets(ProbeOptions{Selection: "all"})
	if len(targets) != 2 {
		t.Errorf("tcp/udp 各算一个端点，实得 %v", idsOf(targets))
	}
	if skipped["同端点重复"] != 1 {
		t.Errorf("同端点重复要记一笔: %v", skipped)
	}
	// 每个 target 都要带全字段：界面点「测这个」时要能对上号。
	for _, tg := range targets {
		if tg.ID == "" || tg.Host == "" || tg.Port <= 0 || (tg.Proto != "tcp" && tg.Proto != "udp") {
			t.Errorf("target 字段不全: %+v", tg)
		}
	}
}

func TestTargetsRejectsBrokenEndpoints(t *testing.T) {
	a := testApp(t)
	noHost := node("v1:nohost", "", "JP", "tcp", 1194)
	noHost.IP, noHost.Server = "", ""
	seed(t, a, noHost, node("v1:badproto", "8.8.8.2", "JP", "sctp", 1194))

	targets, skipped := a.Targets(ProbeOptions{Selection: "all"})
	if len(targets) != 0 {
		t.Errorf("坏端点不该进探测队列: %v", idsOf(targets))
	}
	if skipped["缺主机地址"] != 1 || skipped["proto 异常"] != 1 {
		t.Errorf("跳过原因 = %v", skipped)
	}
}

func TestPurityQueriesPolicies(t *testing.T) {
	a := testApp(t)
	seed(t, a,
		node("v1:a", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:b", "8.8.8.1", "JP", "udp", 443), // 同 IP：结论共用
		node("v1:c", "8.8.8.2", "US", "tcp", 1194),
		node("v1:d", "", "US", "tcp", 1194))

	qs, skipped := a.purityQueries(PurityOptions{Selection: "all"})
	if len(qs) != 2 {
		t.Errorf("按 IP 去重后应是 2 个，实得 %v（跳过 %v）", ipsOf(qs), skipped)
	}
	if skipped["缺 IP"] != 1 {
		t.Errorf("没有 IP 的节点要记账: %v", skipped)
	}

	// 缓存还新鲜时默认不重查（免费源配额很紧），
	// 但要把结论回写给那些「同 IP 上新出现」的节点。
	a.purity.Put(&model.PurityResult{
		IP: "8.8.8.1", CheckedAt: time.Now().UTC(), Score: 88, Level: model.PurityExcellent,
		IPType: model.TypeResidential, TTLHours: 24, Providers: []model.ProviderVerdict{{Name: "builtin", OK: true}},
	})
	qs, skipped = a.purityQueries(PurityOptions{Selection: "unchecked"})
	if len(qs) != 1 || ipsOf(qs)[0] != "8.8.8.2" {
		t.Errorf("缓存新鲜的 IP 不该再花配额，实得 %v（跳过 %v）", ipsOf(qs), skipped)
	}
	for _, id := range []string{"v1:a", "v1:b"} {
		if n, _ := a.store.Get(id); n.Purity == nil {
			t.Errorf("%s 该顺手补上缓存里的结论（同 IP 不必重查）", id)
		}
	}
	if skipped["缓存仍然新鲜"] != 1 {
		t.Errorf("跳过原因 = %v", skipped)
	}

	// all / Force 都要重查：用户点「重新检测」就是要重查。
	if qs, _ = a.purityQueries(PurityOptions{Selection: "all"}); len(qs) != 2 {
		t.Errorf("all 应重查全部，实得 %v", ipsOf(qs))
	}
	if qs, _ = a.purityQueries(PurityOptions{Selection: "unchecked", Force: true}); len(qs) != 2 {
		t.Errorf("Force 应绕过缓存，实得 %v", ipsOf(qs))
	}

	if qs, _ = a.purityQueries(PurityOptions{Selection: "all", IPs: []string{"8.8.8.2"}}); len(qs) != 1 || ipsOf(qs)[0] != "8.8.8.2" {
		t.Errorf("指定 IP 没生效: %v", ipsOf(qs))
	}
	if qs, _ = a.purityQueries(PurityOptions{Selection: "all", Countries: []string{"us"}}); len(qs) != 1 || ipsOf(qs)[0] != "8.8.8.2" {
		t.Errorf("国家过滤没生效: %v", ipsOf(qs))
	}
	if qs, _ = a.purityQueries(PurityOptions{Selection: "all", Limit: 1}); len(qs) != 1 {
		t.Errorf("上限没生效: %v", ipsOf(qs))
	}
	if qs, _ = a.purityQueries(PurityOptions{Selection: "随便写的"}); len(qs) == 0 {
		t.Error("未知 selection 不该导致什么都不查")
	}

	// 走配置默认（留空 = purity.selection，默认 unchecked）。
	a.setCfg(func(c *config.Config) { c.Purity.Selection = "unchecked" })
	if qs, _ := a.purityQueries(PurityOptions{}); ipsOf(qs)[0] != "8.8.8.2" {
		t.Errorf("留空时应回落到 purity.selection，实得 %v", ipsOf(qs))
	}

	// fresh：只查还在官方名单里的 IP。
	if qs, _ = a.purityQueries(PurityOptions{Selection: "fresh", Force: true}); len(qs) != 2 {
		t.Errorf("所有节点都还在名单里，应给 2 个，实得 %v", ipsOf(qs))
	}
	a.store.ApplyRefresh(aggOf(
		node("v1:a", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:b", "8.8.8.1", "JP", "udp", 443)), store.Eviction{KeepDays: 7})
	if qs, _ = a.purityQueries(PurityOptions{Selection: "fresh", Force: true}); len(qs) != 1 || ipsOf(qs)[0] != "8.8.8.1" {
		t.Errorf("fresh 只该给还在名单里的 IP，实得 %v", ipsOf(qs))
	}
}

func TestSmallHelpers(t *testing.T) {
	if got := errText(nil); got != "" {
		t.Errorf("errText(nil) = %q", got)
	}
	if got := errText(errBoom{}); got != "炸了" {
		t.Errorf("errText = %q", got)
	}

	// 空的跳过表也要有输出：日志里那行不能是空字符串。
	if got := summarize(nil); got != "0" {
		t.Errorf("summarize(nil) = %q，期望 \"0\"", got)
	}
	got := summarize(map[string]int{"国家不符": 12, "协议不符": 3, "10 分钟内刚测过": 40, "零项": 0})
	if !strings.HasPrefix(got, "10 分钟内刚测过 40") {
		t.Errorf("汇总要按数量降序（界面只显示一行）: %q", got)
	}
	if !strings.Contains(got, "国家不符 12") || !strings.Contains(got, "协议不符 3") {
		t.Errorf("汇总漏了项: %q", got)
	}
	if strings.Contains(got, "零项") {
		t.Errorf("数量为 0 的项不该出现在汇总里: %q", got)
	}

	if upperSet(nil) != nil || upperSet([]string{}) != nil {
		t.Error("空集合要返回 nil，调用方用 len()==0 判断「不限制」")
	}
	if !upperSet([]string{" jp "})["JP"] {
		t.Error("国家码要 trim 并转大写")
	}
	if len(upperSet([]string{""})) != 0 {
		t.Error("空字符串不该进集合")
	}
	if !lowerSet([]string{" TCP"})["tcp"] {
		t.Error("协议要转小写")
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "炸了" }

func idsOf(ts []Target) []string {
	out := []string{}
	for _, t := range ts {
		out = append(out, t.ID)
	}
	return out
}

func ipsOf(qs []purity.Query) []string {
	out := []string{}
	for _, q := range qs {
		out = append(out, q.IP)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
