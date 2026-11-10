package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/config"
	"github.com/gebaolei/vpngate-agg/internal/model"
	"github.com/gebaolei/vpngate-agg/internal/source"
)

func node(id, host, ip, country, proto string, port int) *model.Node {
	return &model.Node{
		ID: id, HostName: host, IP: ip,
		Country: country, CountryCode: country,
		Proto: proto, Port: port, Server: ip,
		ConfigSHA256: strings.Repeat("a", 64), ConfigLocal: true,
		FirstSeen: time.Now().UTC().Add(-24 * time.Hour), LastSeen: time.Now().UTC(),
	}
}

// 探测历史是按时间顺序追加的（ApplyProbeResults 用 append），
// ComputeHealth 因此把最后一个样本当最新。测试数据必须按同样的顺序喂。
func sample(ok bool, rtt int64, service, reason string, ago time.Duration) model.ProbeSample {
	return model.ProbeSample{At: time.Now().UTC().Add(-ago), OK: ok, RTTMS: rtt, Service: service, Reason: reason}
}

func oldestFirst(ss ...model.ProbeSample) []model.ProbeSample { return ss }

// 超时与 UDP 无响应必须落在「未知」，不能算死亡：
// 跨境链路丢一个 SYN 太常见，UDP 节点对硬重置包基本不响应（SoftEther 行为）。
func TestComputeHealthUnknownIsNotDown(t *testing.T) {
	for _, s := range []string{model.ServiceTimeout, model.ServiceNoReply} {
		h := ComputeHealth(oldestFirst(
			sample(false, 0, s, "探测超时", 3*time.Hour),
			sample(false, 0, s, "探测超时", 2*time.Hour),
			sample(false, 0, s, "探测超时", time.Hour),
		), 8)
		if h.Alive != nil {
			t.Errorf("%s 的结论应是未知，实得 Alive=%v", s, *h.Alive)
		}
		if model.HealthLevel(h) != "unknown" {
			t.Errorf("%s 的档位 = %s，期望 unknown", s, model.HealthLevel(h))
		}
		if h.Tests != 3 || h.Successes != 0 {
			t.Errorf("计数 = %d/%d", h.Tests, h.Successes)
		}
	}
}

// 明确的 RST 与网络不可达才是死亡证据，连续两次才把节点标 down。
func TestComputeHealthDown(t *testing.T) {
	h := ComputeHealth(oldestFirst(
		sample(true, 80, model.ServiceSoftEther, "", 3*time.Hour),
		sample(false, 0, model.ServiceRefused, "端口没在听", 2*time.Hour),
		sample(false, 0, model.ServiceRefused, "端口没在听", time.Hour),
	), 8)
	if h.Alive == nil || *h.Alive {
		t.Errorf("连续明确失败应判定不可达，实得 %v", h.Alive)
	}
	if model.HealthLevel(h) != "down" {
		t.Errorf("level = %s，期望 down", model.HealthLevel(h))
	}
	if h.FailStreak != 2 {
		t.Errorf("连续失败数 = %d，期望 2", h.FailStreak)
	}

	// 只失败了一次：结论是抖动，不是死亡。
	once := ComputeHealth(oldestFirst(
		sample(true, 80, model.ServiceSoftEther, "", 3*time.Hour),
		sample(false, 0, model.ServiceRefused, "端口没在听", time.Hour),
	), 8)
	if once.Level != "flaky" {
		t.Errorf("level = %s，期望 flaky", once.Level)
	}
}

func TestComputeHealthStableAndReachable(t *testing.T) {
	stable := ComputeHealth(oldestFirst(
		sample(true, 70, model.ServiceOpenVPN, "", 4*time.Hour),
		sample(true, 80, model.ServiceSoftEther, "", 3*time.Hour),
		sample(true, 90, model.ServiceSoftEther, "", 2*time.Hour),
		sample(true, 100, model.ServiceSoftEther, "", time.Hour),
	), 8)
	if stable.Alive == nil || !*stable.Alive {
		t.Error("持续成功应判定可达")
	}
	if stable.Level != "stable" {
		t.Errorf("level = %s，期望 stable（成功率 100%%）", stable.Level)
	}
	// EWMA 从最早一次起步、α=0.4：应当落在观测区间内，且比简单平均更靠近近期观测。
	if stable.EWMAPingMS <= 0 || stable.EWMAPingMS > 100 {
		t.Errorf("EWMA 延迟 = %d，应落在最近几次观测的区间内", stable.EWMAPingMS)
	}
	if stable.Confidence <= 0 {
		t.Error("有足够历史时可信度不该是 0")
	}

	// 成功率不到 80%：能连上但不能叫「稳定」。
	reachable := ComputeHealth(oldestFirst(
		sample(false, 0, model.ServiceRefused, "端口没在听", 4*time.Hour),
		sample(true, 80, model.ServiceSoftEther, "", 3*time.Hour),
		sample(true, 80, model.ServiceSoftEther, "", 2*time.Hour),
		sample(true, 80, model.ServiceSoftEther, "", time.Hour),
	), 8)
	if reachable.Level != "reachable" {
		t.Errorf("level = %s，期望 reachable（成功率 75%%）", reachable.Level)
	}

	if h := ComputeHealth(nil, 8); model.HealthLevel(h) != "untested" || h.Tests != 0 {
		t.Errorf("没有历史应判 untested，实得 %s", model.HealthLevel(h))
	}

	// 证据越少可信度越低，越旧也越低 —— 界面用它决定结论要不要显示成「已确认」。
	fresh := ComputeHealth(oldestFirst(sample(true, 50, model.ServiceTCPOpen, "", time.Minute)), 8)
	stale := ComputeHealth(oldestFirst(sample(true, 50, model.ServiceTCPOpen, "", 10*24*time.Hour)), 8)
	if fresh.Confidence <= stale.Confidence {
		t.Errorf("新鲜度要参与可信度：新 %.2f vs 旧 %.2f", fresh.Confidence, stale.Confidence)
	}
	if stable.Confidence <= fresh.Confidence {
		t.Errorf("证据条数要参与可信度：4 次 %.2f vs 1 次 %.2f", stable.Confidence, fresh.Confidence)
	}
}

// 历史裁剪保留的是最近的几次（尾部），不是头几次。
func TestComputeHealthKeepsMostRecent(t *testing.T) {
	var samples []model.ProbeSample
	for i := 19; i >= 0; i-- {
		samples = append(samples, sample(i%2 == 0, 50, model.ServiceSoftEther, "", time.Duration(i)*time.Hour))
	}
	h := ComputeHealth(samples, 5)
	if h.Tests != 5 {
		t.Errorf("Tests = %d，期望只统计最近 5 次", h.Tests)
	}
	if !h.LastTry.Equal(samples[len(samples)-1].At) {
		t.Errorf("LastTry = %v，期望最近一次 %v", h.LastTry, samples[len(samples)-1].At)
	}
	if h.LastOK.After(h.LastTry) {
		t.Error("LastOK 不该晚于 LastTry")
	}
}

func feedProbe(t *testing.T, s *Store, id string, ok bool, rtt int64, service string, ago time.Duration) {
	t.Helper()
	if n := s.ApplyProbeResults(map[string]*model.ProbeResult{
		id: {At: time.Now().UTC().Add(-ago), OK: ok, Host: "8.8.8.1", Port: 1194, Proto: "tcp", RTTMS: rtt, Service: service},
	}, 8); n != 1 {
		t.Fatalf("探测结果没写进去: %s", id)
	}
}

func newStoreWith(t *testing.T, nodes ...*model.Node) *Store {
	t.Helper()
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("建池失败: %v", err)
	}
	apply(t, s, nodes...)
	return s
}

func apply(t *testing.T, s *Store, nodes ...*model.Node) {
	t.Helper()
	applyEv(t, s, Eviction{KeepDays: 7}, nodes...)
}

// applyEv 跑一轮刷新并返回池子改动：淘汰规则的测试要看 Purged 这个数。
func applyEv(t *testing.T, s *Store, ev Eviction, nodes ...*model.Node) RefreshDiff {
	t.Helper()
	agg := &source.Aggregated{Nodes: map[string]*model.Node{}, Configs: map[string][]byte{}, CountsByURL: map[string]int{}}
	for _, n := range nodes {
		agg.Nodes[n.ID] = n
		if n.ConfigSHA256 != "" {
			agg.Configs[n.ConfigSHA256] = []byte("client\ndev tun\n")
		}
	}
	return s.ApplyRefresh(agg, ev)
}

func TestApplyRefreshKeepsLocalObservations(t *testing.T) {
	s := newStoreWith(t, node("v1:aaa", "vpnA", "8.8.8.1", "JP", "tcp", 1194))

	// 我们自己攒的东西：探测历史、纯净度、家宽判定、first_seen。
	feedProbe(t, s, "v1:aaa", true, 42, model.ServiceSoftEther, time.Hour)
	yes := true
	s.ApplyPurity(&model.PurityResult{IP: "8.8.8.1", CheckedAt: time.Now().UTC(), Score: 90, Level: model.PurityGood, IPType: model.TypeResidential})
	s.SetResidential("v1:aaa", yes)
	before, _ := s.Get("v1:aaa")
	firstSeen := before.FirstSeen
	if before.Health.Tests != 1 {
		t.Fatalf("探测历史没记上")
	}

	// 上游又给了一轮：指标可以刷新，但本地观测不能被抹掉。
	updated := node("v1:aaa", "vpnA", "8.8.8.1", "JP", "tcp", 1194)
	updated.UpstreamScore = 999
	updated.FirstSeen = time.Now().UTC() // 上游没有时间概念，不该覆盖我们的 first_seen
	apply(t, s, updated)

	after, _ := s.Get("v1:aaa")
	if after.Health.Tests != 1 || after.Probe == nil || !after.Probe.OK {
		t.Errorf("刷新把本地探测结论冲掉了: %+v", after.Health)
	}
	if after.Purity == nil || after.Purity.Score != 90 {
		t.Errorf("刷新把纯净度结论冲掉了: %+v", after.Purity)
	}
	if after.Residential == nil || !*after.Residential {
		t.Error("刷新把家宽判定冲掉了")
	}
	if !after.FirstSeen.Equal(firstSeen) {
		t.Errorf("first_seen 被上游改成了 %v，应保留 %v", after.FirstSeen, firstSeen)
	}
	if after.UpstreamScore != 999 {
		t.Errorf("上游分数没更新: %d", after.UpstreamScore)
	}
}

// 上游一次轮换/抓包失败不能把池子清空 —— 否则界面会变成「一个节点都没有」，
// 探测也没得测了。
func TestApplyRefreshKeepsNodesMissingFromLatest(t *testing.T) {
	s := newStoreWith(t,
		node("v1:aaa", "vpnA", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:bbb", "vpnB", "8.8.8.2", "US", "udp", 1194))
	apply(t, s, node("v1:aaa", "vpnA", "8.8.8.1", "JP", "tcp", 1194))

	if s.Count() != 2 {
		t.Fatalf("池内应有 2 个（另一个只是本轮没见到，不是消失），实得 %d", s.Count())
	}
	if n, _ := s.Get("v1:bbb"); n.InLatestSource == nil || *n.InLatestSource {
		t.Error("本轮没见到的节点应标 in_latest_source=false")
	}
	if st := s.Stats(); st.FreshNodes != 1 || st.PoolNodes != 2 {
		t.Errorf("stats = %+v，期望 fresh=1 pool=2", st)
	}
	if got := s.List(Filter{FreshOnly: true}).Total; got != 1 {
		t.Errorf("只看最新名单 = %d，期望 1", got)
	}

	// keepDays 到点了才真删 —— 而且「到期」看的是最后一次在名单里，不是本轮还在不在。
	old := node("v1:ddd", "vpnD", "8.8.8.4", "KR", "tcp", 995)
	old.LastSeen = time.Now().UTC().Add(-30 * 24 * time.Hour)
	apply(t, s, old) // 先进池：本轮它在名单里，就算时间戳很旧也不该删
	if n, _ := s.Get("v1:ddd"); n == nil {
		t.Error("本轮名单里有它就不该删（保留期按最后一次在名单里算）")
	}

	// 下一轮名单里没有它了，30 天不过期才轮到真删。
	apply(t, s, node("v1:aaa", "vpnA", "8.8.8.1", "JP", "tcp", 1194))
	if n, _ := s.Get("v1:ddd"); n != nil {
		t.Errorf("30 天没被见过的节点该被清掉")
	}
	if got := s.Count(); got != 2 {
		t.Errorf("池内 %d，期望 2", got)
	}
}

// 提前淘汰（对齐 mirror）：缺席满 AbsentFor 且连续 FailRounds 轮有效探测明确失败。
// 少一个条件都不能删：刚缺席可能只是官方轮换掉了、超时不算失败、只失败两轮可能
// 是网络抖动、UDP 节点本来就攒不出有效失败。
func TestApplyRefreshPurgesDeadTCPEarly(t *testing.T) {
	ev := Eviction{KeepDays: 7, AbsentFor: 24 * time.Hour, FailRounds: 3}
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	apply(t, s,
		node("v1:alive", "vpnAlive", "8.8.8.0", "JP", "tcp", 1194),
		node("v1:dead", "vpnDead", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:two", "vpnTwo", "8.8.8.2", "JP", "tcp", 1194),
		node("v1:back", "vpnBack", "8.8.8.6", "JP", "tcp", 1194),
		node("v1:timeout", "vpnTimeout", "8.8.8.3", "JP", "tcp", 1194),
		node("v1:udpd", "vpnUdp", "8.8.8.5", "JP", "udp", 1194))

	// 三轮探测，每轮结束后统一结算一次 —— 跟 app 层的调用方式一致：
	// 一轮只结算一次，不是每个节点结算一次。
	for i := 3; i >= 1; i-- {
		ago := time.Duration(i) * time.Hour
		feedProbe(t, s, "v1:dead", false, 0, model.ServiceRefused, ago)
		feedProbe(t, s, "v1:udpd", false, 0, model.ServiceRefused, ago)
		feedProbe(t, s, "v1:timeout", false, 0, model.ServiceTimeout, ago) // 超时：不算失败
		if i >= 2 {
			feedProbe(t, s, "v1:two", false, 0, model.ServiceRefused, ago)  // 只失败两轮
			feedProbe(t, s, "v1:back", false, 0, model.ServiceRefused, ago) // 头两轮失败
		} else {
			// 最后一轮连上了：连击必须清零，不能带着旧账被淘汰。
			feedProbe(t, s, "v1:back", true, 30, model.ServiceSoftEther, ago)
		}
		// 本轮开始时间要早于这轮的样本、又晚于上一轮的样本。
		s.UpdateFailRounds(time.Now().UTC().Add(-ago-time.Minute), true)
	}

	// 补测轮不能重复计数，否则一轮被算成两轮、删除提前一倍。
	feedProbe(t, s, "v1:two", false, 0, model.ServiceRefused, 10*time.Minute)
	s.UpdateFailRounds(time.Now().UTC().Add(-11*time.Minute), false)

	for id, want := range map[string]int{
		"v1:dead": 3, "v1:two": 2, "v1:timeout": 0, "v1:udpd": 3, "v1:alive": 0, "v1:back": 0,
	} {
		if n, _ := s.Get(id); n.DownRounds != want {
			t.Errorf("%s 连续失败轮数 = %d，期望 %d", id, n.DownRounds, want)
		}
	}

	// 第一轮缺席：缺席计时刚开始，不该动任何节点。
	live := node("v1:live", "vpnLive", "8.8.8.9", "TH", "tcp", 1194)
	if diff := applyEv(t, s, ev, live); diff.Purged != 0 || diff.Expired != 0 {
		t.Errorf("第一轮缺席就删了 %d+%d 个，缺席钟还没走完", diff.Expired, diff.Purged)
	}
	for _, id := range []string{"v1:dead", "v1:two", "v1:timeout", "v1:udpd", "v1:alive", "v1:back"} {
		n, ok := s.Get(id)
		if !ok {
			t.Errorf("%s 刚缺席就被删了", id)
			continue
		}
		if n.AbsentSince == nil {
			t.Errorf("%s 缺席时间没记上", id)
		}
		if n.InLatestSource == nil || *n.InLatestSource {
			t.Errorf("%s 没被标成不在本轮名单里", id)
		}
	}

	// 把缺席时间拨到 30 小时前（同一轮里不可能等 24 小时，测试直接拨时钟）。
	ago := time.Now().UTC().Add(-30 * time.Hour)
	s.mu.Lock()
	for _, n := range s.nodes {
		if n.AbsentSince != nil {
			t2 := ago
			n.AbsentSince = &t2
		}
	}
	s.mu.Unlock()

	diff := applyEv(t, s, ev, live)
	if diff.Purged != 1 {
		t.Errorf("提前淘汰 %d 个，期望只淘汰 v1:dead 一个", diff.Purged)
	}
	if _, ok := s.Get("v1:dead"); ok {
		t.Error("缺席满 24h 且连续 3 轮明确失败的 TCP 节点该被清掉")
	}
	for _, id := range []string{"v1:two", "v1:timeout", "v1:udpd", "v1:alive", "v1:back"} {
		if _, ok := s.Get(id); !ok {
			t.Errorf("%s 不该被删（只失败两轮 / 全是超时 / UDP / 没失败过 / 最后一轮连上了）", id)
		}
	}

	// 重新回到名单里：缺席计时必须清零，否则下一轮会被误杀。
	applyEv(t, s, ev, live, node("v1:two", "vpnTwo", "8.8.8.2", "JP", "tcp", 1194))
	if n, _ := s.Get("v1:two"); n == nil || n.AbsentSince != nil {
		t.Errorf("重新出现在名单里就该把缺席计时清零，实得 %+v", n)
	}
}

// 同一个 IP 上跑多个 VPN Gate 节点是常事（志愿者换端口），
// 纯净度是按 IP 查的，要一次写给所有共享该 IP 的节点。
func TestApplyPurityFansOutByIP(t *testing.T) {
	s := newStoreWith(t,
		node("v1:aaa", "vpnA", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:bbb", "vpnB", "8.8.8.1", "JP", "udp", 1194),
		node("v1:ccc", "vpnC", "8.8.8.9", "US", "tcp", 995))

	res := &model.PurityResult{
		IP: "8.8.8.1", CheckedAt: time.Now().UTC(), Score: 91, Level: model.PurityExcellent,
		IPType: model.TypeResidential, TypeLabel: "住宅宽带", Confidence: 100, TTLHours: 72,
		Providers: []model.ProviderVerdict{{Name: "ipquery", OK: true}},
	}
	if touched := s.ApplyPurity(res); touched != 2 {
		t.Errorf("写入了 %d 个节点，期望 2（同 IP 的两个）", touched)
	}
	for _, id := range []string{"v1:aaa", "v1:bbb"} {
		got, _ := s.Get(id)
		if got.Purity == nil || got.Purity.Score != 91 {
			t.Errorf("%s 没拿到纯净度结论", id)
		}
	}
	other, _ := s.Get("v1:ccc")
	if other.Purity != nil {
		t.Error("别的 IP 不该被连带写入")
	}
	if st := s.Stats(); st.PurityChecked != 2 {
		t.Errorf("已检测节点数 = %d，期望 2", st.PurityChecked)
	}

	// 家宽判定是 app 层算完再写回来的（purity.IsCleanResidential → SetResidential）。
	if !s.SetResidential("v1:aaa", true) {
		t.Error("SetResidential 应能写")
	}
	if got := s.List(Filter{ResidentialOnly: true}).Total; got != 1 {
		t.Errorf("只看家宽 = %d，期望 1", got)
	}
	if s.SetResidential("不存在的 ID", true) {
		t.Error("给不存在的节点写家宽应返回 false")
	}
	if got := s.ApplyPurity(nil); got != 0 {
		t.Errorf("nil 结论应直接吃掉，实得 %d", got)
	}
}

func TestListFilters(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nodes := []*model.Node{
		node("v1:jp1", "vpn-tokyo-one", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:jp2", "vpn-osaka-two", "8.8.8.2", "JP", "udp", 443),
		node("v1:us1", "vpn-us-three", "8.8.8.3", "US", "tcp", 995),
	}
	nodes[0].Operator = "NTT Com"
	nodes[1].Message = "home server, do not hammer"
	nodes[2].UpstreamScore = 500
	apply(t, s, nodes...)
	feedProbe(t, s, "v1:jp1", true, 60, model.ServiceSoftEther, time.Hour)
	feedProbe(t, s, "v1:jp2", false, 0, model.ServiceRefused, time.Hour)
	feedProbe(t, s, "v1:jp2", false, 0, model.ServiceRefused, 30*time.Minute)

	if got := s.List(Filter{}).Total; got != 3 {
		t.Fatalf("无条件应有 3 个，实得 %d", got)
	}
	if got := s.List(Filter{Countries: []string{"JP"}}).Total; got != 2 {
		t.Errorf("国家过滤 = %d", got)
	}
	if got := s.List(Filter{Countries: []string{"?"}}).Total; got != 0 {
		t.Errorf("未知国家过滤 = %d", got)
	}
	if got := s.List(Filter{Protocols: []string{"udp"}}).Total; got != 1 {
		t.Errorf("协议过滤 = %d", got)
	}
	if got := s.List(Filter{Levels: []string{"down"}}).Total; got != 1 {
		t.Errorf("状态过滤 = %d，期望 1（jp2 连拒两次）", got)
	}
	if got := s.List(Filter{Levels: []string{"untested"}}).Total; got != 1 {
		t.Errorf("未测过滤 = %d，期望 1（us1）", got)
	}
	if got := s.List(Filter{Q: "tokyo"}).Total; got != 1 {
		t.Errorf("关键词应能命中节点名，实得 %d", got)
	}
	if got := s.List(Filter{Q: "NTT"}).Total; got != 1 {
		t.Errorf("关键词应能命中运营商，实得 %d", got)
	}
	if got := s.List(Filter{Q: "hammer"}).Total; got != 1 {
		t.Errorf("关键词应能命中留言，实得 %d", got)
	}
	if got := s.List(Filter{Q: "8.8.8.3"}).Total; got != 1 {
		t.Errorf("关键词应能命中 IP，实得 %d", got)
	}
	if got := s.List(Filter{Q: "995 us"}).Total; got != 1 {
		t.Errorf("多个词要全部命中，实得 %d", got)
	}
	if got := s.List(Filter{Q: "us 不存在的词"}).Total; got != 0 {
		t.Errorf("有一个词不命中就该过滤掉，实得 %d", got)
	}
	if got := s.List(Filter{IDs: []string{"v1:jp1", "v1:us1"}}).Total; got != 2 {
		t.Errorf("按 ID 批量取 = %d", got)
	}
	if got := s.List(Filter{HasProbeLog: true}).Total; got != 2 {
		t.Errorf("只看测过的 = %d，期望 2", got)
	}

	// 纯净度过滤：没测过的一律不参与，否则筛半天筛出一堆空白。
	s.ApplyPurity(&model.PurityResult{IP: "8.8.8.3", CheckedAt: time.Now().UTC(), Score: 95, Level: model.PurityExcellent, IPType: model.TypeResidential})
	minP := 90
	if got := s.List(Filter{MinPurity: &minP}).Total; got != 1 {
		t.Errorf("纯净度≥90 = %d", got)
	}
	if got := s.List(Filter{PurityOnly: true}).Total; got != 1 {
		t.Errorf("只看已检测 = %d", got)
	}
	maxP := 50
	if got := s.List(Filter{MaxPurity: &maxP}).Total; got != 0 {
		t.Errorf("纯净度≤50 = %d，期望 0（没测过的不参与该筛选）", got)
	}

	// 延迟过滤同样跳过没有延迟数据的节点：否则「延迟≤100」会把没测过的算成快。
	maxPing := int64(100)
	if got := s.List(Filter{MaxPing: &maxPing, PingSource: "local"}).Total; got != 1 {
		t.Errorf("本地延迟≤100 = %d，期望 1", got)
	}
	if got := s.List(Filter{MaxPing: &maxPing}).Total; got != 1 {
		t.Errorf("best 口径 = %d，期望 1（另两个没有任何延迟数据）", got)
	}

	// 分页：total 始终是过滤后的总数，不是本页条数。
	page := s.List(Filter{Limit: 2, Offset: 2})
	if page.Total != 3 || len(page.Items) != 1 {
		t.Errorf("分页 = total %d / items %d", page.Total, len(page.Items))
	}
	if got := len(s.List(Filter{Offset: 5}).Items); got != 0 {
		t.Errorf("offset 越界应给空列表而不是崩，实得 %d", got)
	}
	if got := len(s.List(Filter{Limit: 2}).Items); got != 2 {
		t.Errorf("limit = %d，期望 2", got)
	}

	// 列表返回的是深拷贝：HTTP 层改字段不该污染池子。
	item := s.List(Filter{Q: "tokyo"}).Items[0]
	item.HostName = "改了"
	item.Probes[0].RTTMS = 99999
	orig, _ := s.Get("v1:jp1")
	if orig.HostName == "改了" {
		t.Error("列表结果和池内对象共享了内存")
	}
	if orig.Probes[0].RTTMS == 99999 {
		t.Error("探测历史也被共享了")
	}
}

// 有延迟数据的排前面、没测过的排最后，不分升降序 —— 否则「按延迟升序」
// 会把一堆从没测过的节点顶到最前面，看起来像它们最快。
func TestSortPutsMissingValuesLast(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fast := node("v1:fast", "vpn-fast", "8.8.8.1", "JP", "tcp", 1194)
	none := node("v1:none", "vpn-never-measured", "8.8.8.2", "JP", "tcp", 1194)
	slow := node("v1:slow", "vpn-slow", "8.8.8.3", "JP", "tcp", 1194)
	apply(t, s, fast, none, slow)
	feedProbe(t, s, "v1:fast", true, 500, model.ServiceSoftEther, time.Hour)
	feedProbe(t, s, "v1:slow", true, 800, model.ServiceSoftEther, time.Hour)

	ids := func(items []*model.Node) []string {
		out := []string{}
		for _, n := range items {
			out = append(out, n.ID)
		}
		return out
	}
	for _, desc := range []bool{false, true} {
		got := s.List(Filter{Sort: "ping", Desc: desc, PingSource: "local", Limit: 10}).Items
		if len(got) != 3 {
			t.Fatalf("应返回 3 个")
		}
		if got[len(got)-1].ID != "v1:none" {
			t.Errorf("desc=%v 时没测过的应排最后，实得顺序 %v", desc, ids(got))
		}
	}
	asc := s.List(Filter{Sort: "ping", Desc: false, PingSource: "local"}).Items
	if asc[0].ID != "v1:fast" {
		t.Errorf("延迟升序首个应是 500ms 的节点，实得 %s", asc[0].ID)
	}
	desc := s.List(Filter{Sort: "ping", Desc: true, PingSource: "local"}).Items
	if desc[0].ID != "v1:slow" {
		t.Errorf("延迟降序首个应是 800ms 的节点，实得 %s", desc[0].ID)
	}

	// 「越大越好」的列在内部先把值取负归一成「越小越好」，
	// 所以升序（desc=false）就是分数最高的在前。
	apply(t, s, func() *model.Node {
		n := node("v1:none", "vpn-never-measured", "8.8.8.2", "JP", "tcp", 1194)
		n.UpstreamScore = 1000
		return n
	}())
	withScore := s.List(Filter{Sort: "score", Desc: false})
	if withScore.Items[0].ID != "v1:none" {
		t.Errorf("按官方分升序首条应是分数最高的（1000），实得 %s", withScore.Items[0].ID)
	}
	if withScore.Items[len(withScore.Items)-1].UpstreamScore != 0 {
		t.Errorf("没分数的节点不该排在有分数的前面")
	}

	byName := s.List(Filter{Sort: "hostname"}).Items
	if byName[0].HostName != "vpn-fast" {
		t.Errorf("按名称升序首条 = %s", byName[0].HostName)
	}
	byNameDesc := s.List(Filter{Sort: "hostname", Desc: true}).Items
	if byNameDesc[0].HostName != "vpn-slow" {
		t.Errorf("按名称降序首条 = %s", byNameDesc[0].HostName)
	}

	// 未知排序键和空排序键都退回推荐分，不该把结果打乱。
	fallback := s.List(Filter{Sort: "不存在的键", Limit: 3}).Items
	recommended := s.List(Filter{Limit: 3}).Items
	if len(fallback) != 3 || len(recommended) != 3 {
		t.Error("未知排序键也该返回结果")
	}
	for i := range fallback {
		if fallback[i].ID != recommended[i].ID {
			t.Errorf("未知排序键应等价于默认排序，第 %d 位不同", i)
		}
	}
}

// best 口径不兜底官方 Ping。延迟列显示的数和 sort=ping / max_ping / 推荐分用的
// 数必须是同一个值，否则会出现「列上写着待测试，却按官方 44ms 排在前面」。
// 官方值只在显式 ping_source=upstream 时参与；统计卡片和地图的中位延迟是
// 另一套口径（store.pingOf），它们仍然兜底，这里一并钉住。
func TestBestPingSourceIgnoresUpstreamPing(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	official := node("v1:off", "vpn-official-only", "8.8.8.1", "JP", "tcp", 1194)
	official.UpstreamPingMS = 44 // 本机从没测过，只有官方给了个好看的数
	nothing := node("v1:nop", "vpn-no-ping", "8.8.8.2", "JP", "tcp", 1194)
	measured := node("v1:meas", "vpn-measured-slow", "8.8.8.3", "JP", "tcp", 1194)
	measured.UpstreamPingMS = 12
	apply(t, s, official, nothing, measured)
	feedProbe(t, s, "v1:meas", true, 900, model.ServiceSoftEther, time.Hour)

	if got := pingSource(official, "best"); got != 0 {
		t.Errorf("best 口径不该兜底官方 Ping，实得 %d", got)
	}
	if got := pingSource(official, "local"); got != 0 {
		t.Errorf("local 口径不该兜底官方 Ping，实得 %d", got)
	}
	if got := pingSource(official, "upstream"); got != 44 {
		t.Errorf("显式 upstream 口径就该给官方值，实得 %d", got)
	}

	ids := func(items []*model.Node) []string {
		out := []string{}
		for _, it := range items {
			out = append(out, it.ID)
		}
		return out
	}
	asc := s.List(Filter{Sort: "ping", Desc: false, Limit: 10}).Items
	if asc[0].ID != "v1:meas" {
		t.Errorf("按延迟升序首位应是实测过的那个（900ms），实得 %v", ids(asc))
	}
	// 只有官方 Ping 的节点与完全没数的节点一样落在「没数据」那一块（两者同分，
	// 按 ID 定序）：关键是它不能再凭官方那个 44ms 挤到实测节点前面。
	for i := 1; i < len(asc); i++ {
		if asc[i].ID == "v1:meas" {
			t.Errorf("实测过的节点不该落在后面：%v", ids(asc))
		}
	}
	max := int64(1000)
	hits := s.List(Filter{MaxPing: &max, Limit: 10}).Items
	if len(hits) != 1 || hits[0].ID != "v1:meas" {
		t.Errorf("max_ping=1000（best 口径）只该命中实测过的那个，实得 %v", ids(hits))
	}

	// 推荐分里：best 下官方 Ping 不拿延迟加分，显式 upstream 才拿。
	if a, b := RecommendScore(official, "best"), RecommendScore(nothing, "best"); a != b {
		t.Errorf("best 口径下官方 Ping 不该影响推荐分：%.1f vs %.1f", a, b)
	}
	if up := RecommendScore(official, "upstream"); up <= RecommendScore(official, "best") {
		t.Errorf("显式 upstream 口径该给延迟加分：upstream %.1f vs best %.1f", up, RecommendScore(official, "best"))
	}

	// 统计卡片的中位延迟是另一套口径：只有官方值的节点仍要算进去，
	// 否则实测覆盖这么少（实测中 74/269）的话卡片和地图基本就是空的。
	if st := s.Stats(); st.MedianPingMS <= 0 {
		t.Errorf("Stats 的中位延迟仍应兜底官方 Ping，实得 %d", st.MedianPingMS)
	}
}

// 已判定不可达的节点不能再参与「延迟」这个维度。EWMA 只由成功的探测喂出来，
// 不清空也不按时间衰减（见 ComputeHealth），所以「历史上很快、现在已挂」的
// 节点会把按延迟升序的结果顶到前面，也会被 max_ping 当成满足条件，
// 还会在推荐分里拿到一份早就作废的延迟加分。这三条都钉住。
func TestDownNodesExcludedFromPingDimension(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	deadFast := node("v1:dead-fast", "vpn-dead-fast", "8.8.8.1", "JP", "tcp", 1194)
	deadSlow := node("v1:dead-slow", "vpn-dead-slow", "8.8.8.4", "JP", "tcp", 1194)
	alive := node("v1:alive-slow", "vpn-alive-slow", "8.8.8.2", "JP", "tcp", 1194)
	apply(t, s, deadFast, deadSlow, alive)

	// 已挂的判定要连续两次明确否定，这里先给一次很久以前的成功（带延迟数），
	// 再补两次 RST：EWMA 会停在 60ms，档位是 down。
	for _, id := range []string{"v1:dead-fast", "v1:dead-slow"} {
		rtt := int64(60)
		if id == "v1:dead-slow" {
			rtt = 900
		}
		feedProbe(t, s, id, true, rtt, model.ServiceSoftEther, 6*time.Hour)
		feedProbe(t, s, id, false, 0, model.ServiceRefused, 3*time.Hour)
		feedProbe(t, s, id, false, 0, model.ServiceRefused, 1*time.Hour)
	}
	feedProbe(t, s, "v1:alive-slow", true, 800, model.ServiceSoftEther, time.Hour)

	n, ok := s.Get("v1:dead-fast")
	if !ok {
		t.Fatal("节点不在池子里")
	}
	if n.Health.Level != "down" {
		t.Fatalf("样例节点该是 down，实得 %s", n.Health.Level)
	}
	if n.Health.EWMAPingMS != 60 {
		t.Errorf("EWMA 应停在历史那个 60ms，实得 %d —— 正因为它不清空，下面那几条规则才必要", n.Health.EWMAPingMS)
	}

	// 四个延迟口径都不给已挂节点供数（包括 ping_source=upstream：
	// 官方 Ping 也是历史值，不能拿它把已挂节点塞进「快」那一端）。
	for _, src := range []string{"best", "local", "upstream", "cloudflare"} {
		if got := pingSource(n, src); got != 0 {
			t.Errorf("ping_source=%s 时已挂节点仍返回 %d，应为 0", src, got)
		}
	}

	// 延迟排序：无论升降序，已挂节点都排到末尾，而不是抢「最快」。
	ids := func(items []*model.Node) []string {
		out := []string{}
		for _, it := range items {
			out = append(out, it.ID)
		}
		return out
	}
	for _, desc := range []bool{false, true} {
		got := s.List(Filter{Sort: "ping", Desc: desc, PingSource: "best", Limit: 10}).Items
		if len(got) != 3 {
			t.Fatalf("已挂节点不该从结果里消失，应有 3 条，实得 %d", len(got))
		}
		if got[0].ID != "v1:alive-slow" {
			t.Errorf("desc=%v：延迟排序首位应是活着的 800ms，实得 %v", desc, ids(got))
		}
		if got[len(got)-1].ID == "v1:dead-fast" {
			t.Errorf("desc=%v：曾经很快的已挂节点又排回前面了：%v", desc, ids(got))
		}
	}

	// max_ping：「历史上很快」不等于「现在满足条件」。
	max := int64(1000)
	hits := s.List(Filter{MaxPing: &max, Limit: 10}).Items
	if len(hits) != 1 || hits[0].ID != "v1:alive-slow" {
		t.Errorf("max_ping=1000 只该命中活着的那个，实得 %v", ids(hits))
	}

	// 推荐分里也不给已挂节点留延迟加分：两个同样已挂、历史延迟差 15 倍的
	// 节点必须同分，否则就是那个作废的延迟数还在起作用。
	if a, b := RecommendScore(n, "best"), RecommendScore(mustGet(t, s, "v1:dead-slow"), "best"); a != b {
		t.Errorf("已挂节点的推荐分不该受历史延迟影响：%.1f vs %.1f", a, b)
	}
}

func mustGet(t *testing.T, s *Store, id string) *model.Node {
	t.Helper()
	n, ok := s.Get(id)
	if !ok {
		t.Fatalf("节点 %s 不在池子里", id)
	}
	return n
}

func TestRecommendScoreOrdering(t *testing.T) {
	reachable := node("v1:r", "vpn-r", "8.8.8.1", "JP", "tcp", 1194)
	reachable.Probes = oldestFirst(
		sample(true, 60, model.ServiceSoftEther, "", 2*time.Hour),
		sample(true, 60, model.ServiceSoftEther, "", time.Hour))
	reachable.Health = ComputeHealth(reachable.Probes, 8)
	yes := true
	reachable.Residential = &yes
	reachable.Purity = &model.PurityResult{IP: "8.8.8.1", Score: 95, Level: model.PurityExcellent, IPType: model.TypeResidential, CheckedAt: time.Now().UTC()}

	down := node("v1:d", "vpn-d", "8.8.8.2", "JP", "tcp", 1194)
	down.Probes = oldestFirst(
		sample(false, 0, model.ServiceRefused, "", 2*time.Hour),
		sample(false, 0, model.ServiceRefused, "", time.Hour))
	down.Health = ComputeHealth(down.Probes, 8)
	down.Purity = &model.PurityResult{IP: "8.8.8.2", Score: 5, Level: model.PurityBad, IPType: model.TypeHosting, CheckedAt: time.Now().UTC()}

	untested := node("v1:u", "vpn-u", "8.8.8.3", "JP", "tcp", 1194)

	// 三档之间的差距必须是「一眼能看出来」的量级，不然默认排序就是噪音。
	if !(RecommendScore(reachable, "best") > RecommendScore(untested, "best") &&
		RecommendScore(untested, "best") > RecommendScore(down, "best")) {
		t.Errorf("推荐分应满足 可达家宽 > 未测 > 不可达机房，实得 %.1f / %.1f / %.1f",
			RecommendScore(reachable, "best"), RecommendScore(untested, "best"), RecommendScore(down, "best"))
	}
	if r := RecommendScore(reachable, "best"); r > 100 || r < 0 {
		t.Errorf("推荐分应落在 0-100: %v", r)
	}
	if r := RecommendScore(down, "best"); r > 40 {
		t.Errorf("明确不可达 + 机房 IP 还有 %.1f 分，太高了", r)
	}

	// 第三方（Cloudflare Worker）观测只是佐证：可达加分、不可达减分。
	cf := node("v1:cf", "vpn-cf", "8.8.8.4", "JP", "tcp", 1194)
	ms := int64(30)
	cf.CFProbe = &model.CFProbe{Status: "reachable", CheckedAt: time.Now().UTC(), ConnectMS: &ms}
	if RecommendScore(cf, "best") <= RecommendScore(untested, "best") {
		t.Error("第三方观测到可达应该比完全没有观测的节点更占先")
	}
	cf.CFProbe.Status = "unreachable"
	if RecommendScore(cf, "best") >= RecommendScore(untested, "best") {
		t.Error("第三方观测到不可达应该扣分")
	}

	// VPN Gate 自营机房会被目标网站风控，推荐分要压一点。
	own := node("v1:own", "public-vpn-153", "219.100.37.10", "JP", "tcp", 443)
	own.Purity = &model.PurityResult{IP: "219.100.37.10", Score: 60, Level: model.PurityFair, IPType: model.TypeVpngateOwn, CheckedAt: time.Now().UTC()}
	plain := node("v1:plain", "vpn-plain", "219.100.37.11", "JP", "tcp", 443)
	plain.Purity = &model.PurityResult{IP: "219.100.37.11", Score: 60, Level: model.PurityFair, IPType: model.TypeBusiness, CheckedAt: time.Now().UTC()}
	if RecommendScore(own, "best") >= RecommendScore(plain, "best") {
		t.Errorf("自营机房该比同分的普通 IP 低，实得 %.1f vs %.1f",
			RecommendScore(own, "best"), RecommendScore(plain, "best"))
	}

	// 超过 48 小时没在官方名单里出现，要扣分（多半已经下线了）。
	stale := node("v1:stale", "vpn-stale", "8.8.8.5", "JP", "tcp", 1194)
	fresh := node("v1:fresh", "vpn-fresh", "8.8.8.6", "JP", "tcp", 1194)
	stale.LastSeen = time.Now().UTC().Add(-72 * time.Hour)
	if RecommendScore(stale, "best") >= RecommendScore(fresh, "best") {
		t.Error("长期没被官方名单见过的节点该扣分")
	}
}

func TestStatsAndCountries(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id, ip, country, code string) *model.Node {
		n := node(id, id, ip, country, "tcp", 1194)
		n.CountryCode = code
		return n
	}
	a := mk("v1:a", "8.8.8.1", "Japan", "JP")
	a.UpstreamPingMS = 90
	a.UpstreamSpeedBps = 200_000_000
	b := mk("v1:b", "8.8.8.2", "Japan", "JP")
	c := mk("v1:c", "8.8.8.3", "United States", "US")
	d := mk("v1:d", "8.8.8.4", "", "") // 没有国家码的：要归到 "?" 这一桶
	apply(t, s, a, b, c, d)
	feedProbe(t, s, "v1:a", true, 40, model.ServiceSoftEther, time.Hour)
	feedProbe(t, s, "v1:b", false, 0, model.ServiceBlocked, time.Hour)
	feedProbe(t, s, "v1:b", false, 0, model.ServiceBlocked, 30*time.Minute)

	st := s.Stats()
	if st.Nodes != 4 || st.PoolNodes != 4 || st.FreshNodes != 4 {
		t.Errorf("stats = %+v", st)
	}
	if st.Alive != 1 || st.Down != 1 || st.Untested != 2 {
		t.Errorf("档位统计 = alive %d down %d untested %d unknown %d", st.Alive, st.Down, st.Untested, st.Unknown)
	}
	if st.TCP != 4 || st.UDP != 0 {
		t.Errorf("协议统计 = %d/%d", st.TCP, st.UDP)
	}
	if st.MedianPingMS != 40 {
		t.Errorf("中位延迟 = %d，期望按实测的 40ms（实测优先于官方 Ping）", st.MedianPingMS)
	}
	// Stats 的国家数只数有国家码的，未知那一桶由 Countries() 单独给。
	if st.Countries != 2 {
		t.Errorf("国家数 = %d，期望 2", st.Countries)
	}
	if st.AvgUpstreamMbps <= 0 {
		t.Errorf("官方均速 = %v", st.AvgUpstreamMbps)
	}
	if st.ProbedAt.IsZero() {
		t.Error("最近探测时间要有，界面靠它显示「上次测试 x 分钟前」")
	}
	if st.UpdatedAt.IsZero() {
		t.Error("刷新时间要有")
	}

	buckets := s.Countries()
	if len(buckets) != 3 {
		t.Fatalf("国家桶 = %d 个: %+v", len(buckets), buckets)
	}
	byCode := map[string]model.CountryBucket{}
	for _, cb := range buckets {
		byCode[cb.Code] = cb
	}
	if byCode["JP"].Nodes != 2 || byCode["JP"].Alive != 1 {
		t.Errorf("日本桶 = %+v", byCode["JP"])
	}
	if byCode["JP"].MedPurity != 0 {
		t.Errorf("没测纯净度时中位纯净度该是 0，实得 %d", byCode["JP"].MedPurity)
	}
	if byCode["?"].Nodes != 1 {
		t.Errorf("未知桶 = %+v，期望兜住那个没有国家码的节点", byCode["?"])
	}
	if buckets[0].Nodes < buckets[len(buckets)-1].Nodes {
		t.Errorf("国家桶应按节点数降序（界面第一屏才是重点）: %+v", buckets)
	}
	if byCode["JP"].Name != "Japan" {
		t.Errorf("国家名要带出来给下拉框用，实得 %q", byCode["JP"].Name)
	}
	if byCode["JP"].Residential != 0 {
		t.Errorf("没判定过家宽时家宽数该是 0，实得 %d", byCode["JP"].Residential)
	}

	// 国家分布图按「家宽数」着色，所以每桶要带出家宽节点数。
	for _, id := range []string{"v1:a", "v1:b"} {
		if !s.SetResidential(id, true) {
			t.Fatalf("节点 %s 不在池子里，用例前提不对", id)
		}
	}
	for _, cb := range s.Countries() {
		byCode[cb.Code] = cb
	}
	if byCode["JP"].Residential != 2 {
		t.Errorf("日本桶家宽数 = %d，期望 2", byCode["JP"].Residential)
	}

	// 纯净度中位数是按节点统计的，界面上的「中位纯净度」才是那一桶的真实情况。
	s.ApplyPurity(&model.PurityResult{IP: "8.8.8.3", CheckedAt: time.Now().UTC(), Score: 90, Level: model.PurityExcellent, IPType: model.TypeResidential})
	s.ApplyPurity(&model.PurityResult{IP: "8.8.8.1", CheckedAt: time.Now().UTC(), Score: 30, Level: model.PurityPoor, IPType: model.TypeHosting})
	if got := s.Stats().MedianPurity; got != 60 {
		t.Errorf("中位纯净度 = %d，期望 60（两个已检测的平均）", got)
	}
}

func TestConfigContentAddressingAndSaveReload(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	sha := strings.Repeat("ab", 32)
	if err := s.SaveConfig(sha, []byte("client\ndev tun\n")); err != nil {
		t.Fatal(err)
	}
	// 已存在就不该重复写（VPN Gate 全站配置高度重复，去重后只占几 MB）。
	if err := s.SaveConfig(sha, []byte("client\ndev tun\n")); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Config(sha)
	if !ok || string(got) != "client\ndev tun\n" {
		t.Fatalf("读不回配置: %q %v", got, ok)
	}
	if _, ok := s.Config("deadbeef"); ok {
		t.Error("不存在的 sha 不该返回 ok")
	}
	// 存盘的文件名就是 sha，人肉也能核对。
	if _, err := os.Stat(filepath.Join(dir, "configs", sha+".ovpn")); err != nil {
		t.Errorf("配置文件位置不对: %v", err)
	}
	// 正文为空或 sha 为空都不能写：否则会造出一个空文件骗人。
	if err := s.SaveConfig("", []byte("x")); err == nil {
		t.Error("空 sha 应报错")
	}
	if err := s.SaveConfig(sha, nil); err == nil {
		t.Error("空正文应报错")
	}
	// 目录穿越：配置文件名由 sha 拼出来，不做校验的话 "../x" 也能进来。
	if _, ok := s.Config("../../etc/passwd"); ok {
		t.Error("非 hex 的 sha 不该去读盘")
	}
	if written, err := s.PutConfigs(map[string][]byte{strings.Repeat("cd", 32): []byte("x")}); err != nil || written != 1 {
		t.Errorf("批量存正文 = %d/%v", written, err)
	}

	n := node("v1:aaa", "vpnA", "8.8.8.1", "JP", "tcp", 1194)
	n.ConfigSHA256 = sha
	apply(t, s, n)
	feedProbe(t, s, "v1:aaa", true, 33, model.ServiceSoftEther, time.Hour)
	s.SetJob("probe", &model.JobState{Kind: "probe", Status: "done", Total: 1, Done: 1, OK: 1})
	if !s.Dirty() {
		t.Error("改过就该标脏，定时器靠这个决定要不要写盘")
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if s.Dirty() {
		t.Error("落盘后不该还脏")
	}
	if s.LastSave().IsZero() {
		t.Error("上次落盘时间要有，界面用它显示「数据已保存 x 前」")
	}

	restarted, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.Count() != 1 {
		t.Fatalf("重启后节点数 = %d", restarted.Count())
	}
	back, ok := restarted.Get("v1:aaa")
	if !ok {
		t.Fatal("节点读不回来")
	}
	if back.Health.Tests != 1 || back.Health.EWMAPingMS != 33 {
		t.Errorf("探测历史没能读回来: %+v", back.Health)
	}
	if back.ConfigSHA256 != sha {
		t.Errorf("配置摘要丢了")
	}
	if !back.ConfigLocal {
		t.Error("正文在磁盘上就该标 config_local")
	}
	if got, ok := restarted.Config(sha); !ok || string(got) != "client\ndev tun\n" {
		t.Errorf("正文读不回来: %q", got)
	}
	if jobs := restarted.Jobs(); jobs["probe"] == nil || jobs["probe"].OK != 1 {
		t.Errorf("任务状态没能读回来: %+v", jobs)
	}
	if restarted.Dir() != dir {
		t.Errorf("Dir = %s", restarted.Dir())
	}
	// MarkConfigLocal 是给按需拉取成功后补标记用的。
	if !restarted.MarkConfigLocal("v1:aaa") {
		t.Error("MarkConfigLocal 对存在的节点应返回 true")
	}
	if restarted.MarkConfigLocal("不存在") {
		t.Error("不存在的节点应返回 false")
	}
}

func TestSaveWritesValidJSONAndAtomicReplace(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	apply(t, s, node("v1:aaa", "vpnA", "8.8.8.1", "JP", "tcp", 1194))
	s.ApplyRefresh(&source.Aggregated{
		Nodes:       map[string]*model.Node{},
		Stats:       []model.SourceStat{{Name: "official", URL: "https://www.vpngate.net/api/iphone/", Nodes: 1, MS: 120}},
		CountsByURL: map[string]int{"https://www.vpngate.net/api/iphone/": 1},
	}, Eviction{KeepDays: 7})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "pool.json"))
	if err != nil {
		t.Fatalf("快照文件名不对: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("快照不是合法 JSON: %v", err)
	}
	if doc["schema_version"].(float64) != SchemaVersion {
		t.Errorf("schema_version = %v，期望 %d（改语义要升版本）", doc["schema_version"], SchemaVersion)
	}
	if _, left := os.Stat(filepath.Join(dir, "pool.json.tmp")); left == nil {
		t.Error("临时文件没清掉")
	}
	if meta, _ := doc["meta"].(map[string]any); meta["source_stats"] == nil {
		t.Error("各来源的抓取状态要落进快照，重启后界面才知道上一轮怎么样")
	}
	// 上一轮的各源计数要留着做「数量骤减」判断。
	if got := s.PrevCounts()["https://www.vpngate.net/api/iphone/"]; got != 1 {
		t.Errorf("PrevCounts = %v，上一轮的各源计数要留着做「数量骤减」判断", got)
	}
	if m := s.Meta(); len(m.SourceStats) != 1 || m.SourceStats[0].Name != "official" {
		t.Errorf("Meta 里的源状态 = %+v", m.SourceStats)
	}
}

// 磁盘上是个半截文件（上次写盘被断电打断）时，重启要能起来而不是崩。
func TestNewToleratesBrokenSnapshot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pool.json"), []byte(`{"nodes": [ 未完`), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(dir)
	if err != nil {
		t.Fatalf("读半截快照不该失败: %v", err)
	}
	if s.Count() != 0 {
		t.Errorf("读不懂就当空池，实得 %d", s.Count())
	}
	if _, err := os.ReadDir(dir); err != nil {
		t.Fatal(err)
	}
	// 坏文件要备份而不是直接删掉，用户还能捞回数据。
	entries, _ := os.ReadDir(dir)
	var backed bool
	for _, e := range entries {
		if strings.Contains(e.Name(), ".bad-") {
			backed = true
		}
	}
	if !backed {
		t.Error("坏的快照应备份成 .bad-<时间> 而不是丢掉")
	}
}

// schema 对不上时不能硬读：字段语义变了，读出来的健康结论会是错的。
func TestNewIgnoresIncompatibleSchema(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pool.json"), []byte(`{"schema_version": 99, "nodes": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(dir); err != nil {
		t.Fatalf("版本不认不该报错: %v", err)
	}
}

func TestNewOnMissingDirIsNotAnError(t *testing.T) {
	// 首次部署必须能起来：没有 data 目录 ≠ 出错。
	dir := filepath.Join(t.TempDir(), "nested", "data")
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if s.Count() != 0 {
		t.Error("空池")
	}
	if err := s.Save(); err != nil {
		t.Errorf("首次落盘失败: %v", err)
	}
	if got := s.List(Filter{}).Total; got != 0 {
		t.Errorf("空池查询 = %d", got)
	}
	if st := s.Stats(); st.Nodes != 0 || st.MedianPingMS != 0 {
		t.Errorf("空池统计 = %+v", st)
	}
	if len(s.Countries()) != 0 {
		t.Error("空池不该有国家桶")
	}
}

func TestParseIDAndNodesWithIP(t *testing.T) {
	if !ParseID("v1:" + strings.Repeat("0", 64)) {
		t.Error("合法 ID 应通过")
	}
	for _, bad := range []string{"", "v1:", "v1:" + strings.Repeat("0", 63), "v1:" + strings.Repeat("0", 64) + "0", "v2:" + strings.Repeat("0", 64), "zz", "v1:" + strings.Repeat("G", 64)} {
		if ParseID(bad) {
			t.Errorf("%q 不该通过", bad)
		}
	}

	s := newStoreWith(t,
		node("v1:aaa", "vpnA", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:bbb", "vpnB", "8.8.8.1", "JP", "udp", 1194),
		node("v1:ccc", "vpnC", "8.8.8.2", "US", "tcp", 995))
	if got := s.NodesWithIP("8.8.8.1"); len(got) != 2 {
		t.Errorf("同 IP 节点 = %v", got)
	}
	if got := s.NodesWithIP("9.9.9.9"); len(got) != 0 {
		t.Errorf("不存在的 IP = %v", got)
	}
	// 返回的必须是副本：调用方拿去排序/截取不该动到索引。
	got := s.NodesWithIP("8.8.8.1")
	got[0] = "改了"
	if s.NodesWithIP("8.8.8.1")[0] == "改了" {
		t.Error("NodesWithIP 返回了内部切片")
	}
	if got, ok := s.Get("不存在"); ok || got != nil {
		t.Error("取不到时要给 nil")
	}
	if s.SetJob("probe", nil); len(s.Jobs()) != 0 {
		t.Error("nil 任务状态不该写进去")
	}
	// 并发调用是常态（探测线程写、HTTP 读），这里跑一轮确保不死锁也不panic。
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			s.ApplyProbeResults(map[string]*model.ProbeResult{
				"v1:aaa": {At: time.Now(), OK: true, Host: "8.8.8.1", Port: 1194, Proto: "tcp", RTTMS: int64(i), Service: model.ServiceSoftEther},
			}, 8)
			_ = s.List(Filter{Limit: 5})
			_ = s.ApplyPurity(&model.PurityResult{IP: "8.8.8.2", Score: i, Level: model.PurityFair})
		}
	}()
	for i := 0; i < 100; i++ {
		_ = s.Stats()
		_ = s.Countries()
		_ = s.All()
	}
	<-done
}

func TestFormatMS(t *testing.T) {
	for in, want := range map[int64]string{-1: "-", 0: "-", 1: "1ms", 999: "999ms", 1000: "1.00s", 1500: "1.50s", 12345: "12.35s"} {
		if got := FormatMS(in); got != want {
			t.Errorf("FormatMS(%d) = %q，期望 %q", in, got, want)
		}
	}
}

// 自营机房节点（hostname public-vpn-* 或落在自营网段里）默认不进池：那是官方自己
// 的机房出口，跟志愿者家宽是两回事。开关要能打开，还要能「先拉进来再关掉」。
func TestApplyRefreshVpngateOwnSwitch(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("建池失败: %v", err)
	}
	round := []*model.Node{
		node("v1:ownhost", "public-vpn-232", "8.8.8.1", "JP", "tcp", 443), // 靠前缀认
		node("v1:owncidr", "vpn100", "219.100.37.170", "JP", "tcp", 443),  // 靠网段认
		node("v1:home", "vpn200", "8.8.8.2", "JP", "tcp", 443),
	}

	diff := applyEv(t, s, Eviction{KeepDays: 7}, round...)
	if got := s.Count(); got != 1 {
		t.Fatalf("默认应只留家宽节点，池内 %d 个", got)
	}
	if diff.DroppedOwn != 2 {
		t.Errorf("DroppedOwn = %d，期望 2（前缀一个 + 网段一个）", diff.DroppedOwn)
	}
	if _, ok := s.Get("v1:home"); !ok {
		t.Error("普通节点被误删了")
	}

	// 开关打开：三个都进得来。
	if diff = applyEv(t, s, Eviction{KeepDays: 7, KeepOwnNet: true}, round...); diff.DroppedOwn != 0 {
		t.Errorf("打开开关后还剔了 %d 个", diff.DroppedOwn)
	}
	if got := s.Count(); got != 3 {
		t.Errorf("打开开关后池内 %d 个，期望 3", got)
	}

	// 再关掉：已经进池的自营节点要在下一轮被清掉，不然界面上点了开关没反应。
	diff = applyEv(t, s, Eviction{KeepDays: 7}, round...)
	if got := s.Count(); got != 1 {
		t.Errorf("关掉开关后池内 %d 个，期望只剩 1", got)
	}
	if diff.DroppedOwn != 2 {
		t.Errorf("关掉开关后 DroppedOwn = %d，期望 2", diff.DroppedOwn)
	}
}

// config_local 说的只是「抓取那一轮有没有拿到正文」，而正文是按 sha 内容寻址
// 单独存盘的。重启读盘时不照磁盘实况校正，就会出现「盘上明明有正文、标记却是
// false」，界面上点一下就走一次无谓的回源（累积池导入的节点最容易踩）。
func TestLoadBackfillsConfigLocalFromDisk(t *testing.T) {
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	hasBody := strings.Repeat("f", 64) // 盘上有正文
	noBody := strings.Repeat("e", 64)  // 只有 sha，正文从没拉过
	if err := s.SaveConfig(hasBody, []byte("client\ndev tun\n")); err != nil {
		t.Fatal(err)
	}

	n1 := node("v1:pool-a", "vpn-pool-a", "203.0.113.9", "JP", "tcp", 1194)
	n1.ConfigSHA256, n1.ConfigLocal = hasBody, false
	n2 := node("v1:pool-b", "vpn-pool-b", "203.0.113.8", "JP", "tcp", 443)
	n2.ConfigSHA256, n2.ConfigLocal = noBody, false
	agg := &source.Aggregated{
		Nodes:       map[string]*model.Node{n1.ID: n1, n2.ID: n2},
		Configs:     map[string][]byte{},
		CountsByURL: map[string]int{},
	}
	if diff := s.ApplyRefresh(agg, Eviction{KeepDays: 7}); diff.Added != 2 {
		t.Fatalf("进池 %d 个", diff.Added)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	// 前提：快照里两个都是 false（回填只发生在读盘时，否则这个测试测不到东西）。
	blob, err := os.ReadFile(filepath.Join(dir, "pool.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snap struct {
		Nodes map[string]map[string]any `json:"nodes"`
	}
	if err := json.Unmarshal(blob, &snap); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{n1.ID, n2.ID} {
		if v, ok := snap.Nodes[id]["config_local"]; !ok || v != false {
			t.Fatalf("快照里 %s 的 config_local 应为 false（测试前提），实得 %#v", id, v)
		}
	}

	again, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := again.Get(n1.ID)
	if !ok {
		t.Fatal("节点读不回来")
	}
	if !got.ConfigLocal {
		t.Error("正文在盘上就该回填 config_local=true，否则界面点开要走一次回源")
	}
	if got, _ := again.Get(n2.ID); got.ConfigLocal {
		t.Error("盘上没有正文的节点不能被回填成 true，那是「按需拉取」的判据")
	}
	if !again.Dirty() {
		t.Error("回填过就该标脏，让修正写回快照（下次启动就不用再补）")
	}
}

// 容量裁剪：超出 max_nodes 时先走硬伤的，然后才轮到「活着但分低」的。
func TestTrimToCapacityHardFlawsGoFirst(t *testing.T) {
	s := newStoreWith(t,
		node("v1:good", "good", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:dead", "dead", "8.8.8.2", "JP", "tcp", 1194),
		node("v1:host", "host", "8.8.8.3", "JP", "tcp", 1194),
		node("v1:ghost", "ghost", "8.8.8.4", "US", "tcp", 1194),
		node("v1:poor", "poor", "8.8.8.5", "US", "tcp", 1194),
	)
	// good：连着两次成功，本轮也在名单里 —— 最不该被它动的。
	feedProbe(t, s, "v1:good", true, 40, model.ServiceSoftEther, 2*time.Hour)
	feedProbe(t, s, "v1:good", true, 42, model.ServiceSoftEther, time.Hour)
	// dead：连续两轮明确否定（RST），已判定不可达。
	feedProbe(t, s, "v1:dead", false, 0, model.ServiceRefused, 2*time.Hour)
	feedProbe(t, s, "v1:dead", false, 0, model.ServiceRefused, time.Hour)
	// poor：连上了但延迟很高、只测过一次：分比 good 低，可它没有硬伤。
	feedProbe(t, s, "v1:poor", true, 900, model.ServiceSoftEther, 30*time.Minute)
	// host：纯净度结论是机房出口。
	s.ApplyPurity(&model.PurityResult{IP: "8.8.8.3", CheckedAt: time.Now().UTC(),
		Score: 20, Level: model.PurityPoor, IPType: model.TypeHosting})

	// 下一轮：名单里没有 ghost 了，而它也从没被探测过，是个空壳。
	apply(t, s,
		node("v1:good", "good", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:dead", "dead", "8.8.8.2", "JP", "tcp", 1194),
		node("v1:host", "host", "8.8.8.3", "JP", "tcp", 1194),
		node("v1:poor", "poor", "8.8.8.5", "US", "tcp", 1194),
	)

	// 上限 2：得走三个，而且必须是 dead → host → ghost。
	d := s.Trim(Eviction{MaxNodes: 2})
	if d.Trimmed != 3 || d.Total != 2 {
		t.Fatalf("裁剪结果 = %+v，期望裁掉 3 剩 2", d)
	}
	for _, id := range []string{"v1:dead", "v1:host", "v1:ghost"} {
		if _, ok := s.Get(id); ok {
			t.Errorf("%s 有硬伤，该被裁掉", id)
		}
	}
	for _, id := range []string{"v1:good", "v1:poor"} {
		if _, ok := s.Get(id); !ok {
			t.Errorf("%s 没有硬伤，不该被容量裁掉", id)
		}
	}
	// IP 索引要跟着清干净，否则纯净度回写会去找已经不存在的节点。
	if got := s.NodesWithIP("8.8.8.2"); len(got) != 0 {
		t.Errorf("裁掉节点的 IP 索引没清: %v", got)
	}
}

// max_nodes 设 0（或负数）是「不限」；没超上限时也不该动一根毛。
func TestTrimNoopWhenUnderLimit(t *testing.T) {
	s := newStoreWith(t,
		node("v1:a", "a", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:b", "b", "8.8.8.2", "JP", "tcp", 1194),
	)
	feedProbe(t, s, "v1:b", false, 0, model.ServiceRefused, time.Hour)
	for _, max := range []int{0, -1, 2, 500} {
		if d := s.Trim(Eviction{MaxNodes: max}); d.Trimmed != 0 || d.Total != 2 {
			t.Errorf("max_nodes=%d 不该裁任何东西，实得 %+v", max, d)
		}
	}
	if s.Count() != 2 {
		t.Errorf("池子 = %d，期望还是 2", s.Count())
	}
}

// 同一档里先删「本轮名单里没有」的：删了不会下一轮又被抓回来，池子是真变小。
func TestTrimSameBucketPrefersAbsent(t *testing.T) {
	s := newStoreWith(t,
		node("v1:gone", "gone", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:heredead", "heredead", "8.8.8.2", "JP", "tcp", 1194),
		node("v1:ok", "ok", "8.8.8.3", "JP", "tcp", 1194),
	)
	for _, id := range []string{"v1:gone", "v1:heredead"} {
		feedProbe(t, s, id, false, 0, model.ServiceRefused, 2*time.Hour)
		feedProbe(t, s, id, false, 0, model.ServiceRefused, time.Hour)
	}
	feedProbe(t, s, "v1:ok", true, 40, model.ServiceSoftEther, time.Hour)
	// 下一轮：gone 不在名单里了；heredead 还在 —— 上游不知道它已经连不上。
	apply(t, s,
		node("v1:heredead", "heredead", "8.8.8.2", "JP", "tcp", 1194),
		node("v1:ok", "ok", "8.8.8.3", "JP", "tcp", 1194),
	)
	if d := s.Trim(Eviction{MaxNodes: 2}); d.Trimmed != 1 {
		t.Fatalf("裁掉 %d 个，期望 1 个: %+v", d.Trimmed, d)
	}
	if _, ok := s.Get("v1:gone"); ok {
		t.Error("同样已判定不可达，本轮没见到的那个该先走")
	}
	if _, ok := s.Get("v1:heredead"); !ok {
		t.Error("还在名单里的节点不该在这一刀被裁掉，白删还丢探测历史")
	}
}

// 同档、都不在名单里：缺席最久的先走。
func TestTrimAbsentOrderOldestFirst(t *testing.T) {
	s := newStoreWith(t,
		node("v1:old", "old", "8.8.8.1", "JP", "tcp", 1194),
		node("v1:fresh", "fresh", "8.8.8.2", "JP", "tcp", 1194),
		node("v1:stay", "stay", "8.8.8.3", "JP", "tcp", 1194),
	)
	for _, id := range []string{"v1:old", "v1:fresh", "v1:stay"} {
		feedProbe(t, s, id, true, 60, model.ServiceSoftEther, time.Hour)
	}
	apply(t, s, node("v1:stay", "stay", "8.8.8.3", "JP", "tcp", 1194))
	// 同一轮里等不到 20 小时，直接把 old 的缺席钟拨早。
	s.mu.Lock()
	ago := time.Now().UTC().Add(-20 * time.Hour)
	if n := s.nodes["v1:old"]; n != nil {
		n.AbsentSince = &ago
	}
	s.mu.Unlock()

	if d := s.Trim(Eviction{MaxNodes: 2}); d.Trimmed != 1 {
		t.Fatalf("裁掉 %d 个，期望 1 个: %+v", d.Trimmed, d)
	}
	if _, ok := s.Get("v1:old"); ok {
		t.Error("缺席最久的该先走")
	}
	for _, id := range []string{"v1:fresh", "v1:stay"} {
		if _, ok := s.Get(id); !ok {
			t.Errorf("%s 不该被裁掉", id)
		}
	}
}

// 自营机房节点在「保留机房」打开时不能被容量裁顺手清掉 —— 那是用户显式要的功能。
func TestTrimKeepsVpngateOwnWhenAsked(t *testing.T) {
	s := newStoreWith(t,
		node("v1:own", "vpn-own", "8.8.9.9", "JP", "tcp", 1194),
		node("v1:home", "home", "8.8.8.2", "JP", "tcp", 1194),
	)
	s.ApplyPurity(&model.PurityResult{IP: "8.8.9.9", CheckedAt: time.Now().UTC(),
		Score: 60, Level: model.PurityGood, IPType: model.TypeVpngateOwn})
	// 自营的先走：它分低（自营机房要扣分），但开关说留着。
	if d := s.Trim(Eviction{MaxNodes: 1, KeepOwnNet: true}); d.Trimmed != 1 {
		t.Fatalf("裁掉 %d 个，期望 1 个: %+v", d.Trimmed, d)
	}
	if _, ok := s.Get("v1:own"); !ok {
		t.Error("keep_vpngate_own=true 时自营机房不该被容量裁掉")
	}
	// 关掉开关时它属于「明确不是想要的出口」，得排到硬伤那一档。
	s2 := newStoreWith(t,
		node("v1:own", "vpn-own", "8.8.9.9", "JP", "tcp", 1194),
		node("v1:home", "home", "8.8.8.2", "JP", "tcp", 1194),
	)
	s2.ApplyPurity(&model.PurityResult{IP: "8.8.9.9", CheckedAt: time.Now().UTC(),
		Score: 95, Level: model.PurityExcellent, IPType: model.TypeVpngateOwn})
	if d := s2.Trim(Eviction{MaxNodes: 1}); d.Trimmed != 1 {
		t.Fatalf("裁掉 %d 个，期望 1 个: %+v", d.Trimmed, d)
	}
	if _, ok := s2.Get("v1:own"); ok {
		t.Error("默认不保留自营机房时，它该按硬伤先走，哪怕纯净度分很高")
	}
}

// 配置里的上限要能传到裁剪：漏了这一项就等于功能没接上。
func TestEvictionFromCarriesMaxNodes(t *testing.T) {
	ev := EvictionFrom(config.SourcesConfig{KeepDays: 7, PurgeAbsentHours: 24, PurgeFailRounds: 3, MaxNodes: 1500})
	if ev.MaxNodes != 1500 {
		t.Errorf("Eviction.MaxNodes = %d，期望 1500", ev.MaxNodes)
	}
}

// 升级兼容性：老快照里的第三方字段（cdn_commit / cdn_pool_commit）和
// LastSource=cdn-pool 的遗留节点，加载时不能报错，也不能被当成「本轮还在名单里」。
func TestNewLoadsLegacyPoolWithCDNFields(t *testing.T) {
	dir := t.TempDir()
	blob := `{"schema_version":1,` +
		`"cdn_commit":"` + strings.Repeat("0", 40) + `",` +
		`"cdn_pool_commit":"` + strings.Repeat("1", 40) + `",` +
		`"nodes":{"v1:old":{"id":"v1:old","hostname":"old","ip":"8.8.8.9",` +
		`"country":"JP","country_code":"JP","proto":"tcp","port":1194,"server":"8.8.8.9",` +
		`"last_source":"cdn-pool","last_seen":"2020-01-01T00:00:00Z"}}}`
	if err := os.WriteFile(filepath.Join(dir, "pool.json"), []byte(blob), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(dir)
	if err != nil {
		t.Fatalf("带第三方遗留字段的快照该照常加载: %v", err)
	}
	if s.Count() != 1 {
		t.Fatalf("池子 = %d，期望 1", s.Count())
	}
	n, ok := s.Get("v1:old")
	if !ok {
		t.Fatal("遗留节点没读进来")
	}
	// 第三方池的 last_seen 是它自己的历史观测，不能当成「本轮在名单里」，
	// 否则这个节点永远不会被过期淘汰，也不会被容量裁剪优先请走。
	if presentInCurrentList(n) {
		t.Error("LastSource=cdn-pool 的节点不该算「本轮在名单里」")
	}
	if d := s.Trim(Eviction{MaxNodes: 0}); d.Trimmed != 0 {
		t.Errorf("max_nodes=0 是不限，不该裁掉遗留节点: %+v", d)
	}
}
