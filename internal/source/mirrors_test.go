package source

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gebaolei/vpngate-agg/internal/config"
	"github.com/gebaolei/vpngate-agg/internal/model"
)

func TestParseMirrorPageFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/mirrors.html")
	if err != nil {
		t.Fatalf("读测试数据失败: %v", err)
	}
	entries, err := ParseMirrorPage(string(body))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("镜像数 = %d，期望 3：%+v", len(entries), entries)
	}
	want := []model.MirrorEntry{
		{Base: "http://150.40.105.16:33958", Location: "Croatia"},
		{Base: "http://62.133.35.246:2265", Location: "Germany"},
		{Base: "http://150.40.105.6:11803", Location: "Croatia"},
	}
	for i, w := range want {
		if entries[i] != w {
			t.Errorf("第 %d 个镜像 = %+v，期望 %+v", i, entries[i], w)
		}
	}
}

func TestParseMirrorPageRejectsUnusable(t *testing.T) {
	// 站内链接、域名镜像、私有地址都不能进来：
	// 域名要先解析再校验（还可能 DNS rebinding），私有段则等于自己打自己。
	body := `<span id="Label1"><ul>
<li><a href='/en/mirror_ssh.aspx'>list</a></li>
<li><a href='https://mirror.example.com/en/'>domain</a></li>
<li><a href='http://10.0.0.7:80/en/'>private</a></li>
<li><a href='http://127.0.0.1:8080/en/'>loopback</a></li>
<li><a href='http://[::1]:80/en/'>ipv6</a></li>
<li><a href='http://203.0.113.9:123/en/'>test-net</a></li>
<li><a href='http://203.0.113.9:99999/en/'>bad port</a></li>
</ul></span>`
	if _, err := ParseMirrorPage(body); err == nil {
		t.Fatal("一条可用镜像都没有，应报错")
	}

	body2 := `<span id="Label1"><ul><li><a href='http://150.40.105.16/en/'>no port</a></li></ul></span>`
	entries, err := ParseMirrorPage(body2)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(entries) != 1 || entries[0].Base != "http://150.40.105.16:80" {
		t.Errorf("缺省端口应回落 80，实得 %+v", entries)
	}
}

func TestParseMirrorPageFallbackScan(t *testing.T) {
	// 上游改了模板、认不出 Label1 时退回全页扫描：至少还能拿到源。
	body := `<html><body>
<ul><li><a href='http://8.8.4.4:1234/en/'>m1</a></li>
<li><a href='http://8.8.8.8:4321/en/'>m2</a></li></ul></body></html>`
	entries, err := ParseMirrorPage(body)
	if err != nil {
		t.Fatalf("兜底扫描失败: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("兜底应扫到 2 个镜像，实得 %+v", entries)
	}
	for _, e := range entries {
		if e.Location != "" {
			t.Errorf("兜底路径不该带 location，实得 %+v", e)
		}
	}
}

func TestPickMirrorSourcesDedupeAndRotation(t *testing.T) {
	// 实测官方列表页上多个克罗地亚镜像都在 150.40.105.0/24：
	// 同网段基本就是同一处机房的多个端口，重复拉只是白花带宽。
	entries := []model.MirrorEntry{
		{Base: "http://150.40.105.16:33958", Location: "Croatia"},
		{Base: "http://150.40.105.6:11803", Location: "Croatia"},
		{Base: "http://62.133.35.246:2265", Location: "Germany"},
		{Base: "http://150.40.105.99:8080", Location: "Croatia"},
		// 同一国家、不同 /24：限量时为了分带宽会被 location 去重掉，
		// 全抓时该拉 —— 它是独立缓存，节点集真的不一样。
		{Base: "http://185.132.240.7:443", Location: "Croatia"},
	}

	got := pickMirrorSources(entries, 3, 0)
	if len(got) != 2 {
		t.Fatalf("去重后应剩 2 个（同 /24 + 同 location），实得 %+v", got)
	}
	if got[0].Base != "http://150.40.105.16:33958" || got[1].Base != "http://62.133.35.246:2265" {
		t.Errorf("选出的镜像不对: %+v", got)
	}

	// 轮转：每轮换个起点，跨轮次的并集会持续变大，而每轮成本恒定。
	// rotation=1：起点是第二个条目，它自己是 150.40.105.0/24 里第一个被选中的。
	rot1 := pickMirrorSources(entries, 1, 1)
	if len(rot1) != 1 || rot1[0].Base != "http://150.40.105.6:11803" {
		t.Errorf("rotation=1 的起点不对，实得 %+v", rot1)
	}
	rot2 := pickMirrorSources(entries, 2, 2)
	if len(rot2) != 2 || rot2[0].Base != "http://62.133.35.246:2265" || rot2[1].Base != "http://150.40.105.99:8080" {
		t.Errorf("rotation=2 的选取不对: %+v", rot2)
	}

	// n=0（默认）= 本轮全抓：只按 /24 去重，同国不同机房也要拉。
	// 同 /24 那几个仍然只留一个：同一机房的多个端口给的 CSV 几乎一样。
	all := pickMirrorSources(entries, 0, 0)
	if len(all) != 3 {
		t.Fatalf("n=0 应全抓出去重后的 3 个镜像，实得 %+v", all)
	}
	for _, want := range []string{
		"http://150.40.105.16:33958", "http://62.133.35.246:2265", "http://185.132.240.7:443",
	} {
		found := false
		for _, e := range all {
			if e.Base == want {
				found = true
			}
		}
		if !found {
			t.Errorf("全抓漏了 %s：%+v", want, all)
		}
	}
	for _, e := range all {
		if e.Base == "http://150.40.105.6:11803" || e.Base == "http://150.40.105.99:8080" {
			t.Errorf("同 /24 的重复镜像不该重复拉：%+v", all)
		}
	}
	if len(pickMirrorSources(nil, 0, 0)) != 0 {
		t.Error("空列表应返回空")
	}
}

func TestValidateMirrorBase(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr string
	}{
		{"http://150.40.105.16:33958/en/", "http://150.40.105.16:33958", ""},
		{"https://8.8.8.8/en/", "https://8.8.8.8:443", ""},
		{"http://8.8.8.8/en/", "http://8.8.8.8:80", ""},
		{"ftp://8.8.8.8/en/", "", "协议"},
		{"http://mirror.example.com/en/", "", "域名"},
		{"http://127.0.0.1:8080/en/", "", "回环"},
		{"http://192.168.1.1:80/en/", "", "私有"},
		{"http://100.64.1.1:80/en/", "", "保留段"},
		{"http://198.18.0.1:80/en/", "", "保留段"},
		{"http://169.254.1.1:80/en/", "", "链路本地"},
		{"http://224.0.0.5:80/en/", "", "不被允许"},
		{"http://8.8.8.8:0/en/", "", "端口"},
		{"http://8.8.8.8:99999/en/", "", "端口"},
		{"/en/mirror.aspx", "", ""},
	}
	for _, c := range cases {
		got, _, _, err := validateMirrorBase(c.in, nil)
		switch {
		case c.wantErr != "":
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("validateMirrorBase(%q) 错误应含 %q，实得 %v", c.in, c.wantErr, err)
			}
		case c.want == "" && err == nil:
			t.Errorf("validateMirrorBase(%q) 应拒绝", c.in)
		case c.want != "" && got != c.want:
			t.Errorf("validateMirrorBase(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}

	// 本机正在监听的端口必须拒掉：真去连自己开的端口，拿到的是自己的服务。
	if _, _, _, err := validateMirrorBase("http://8.8.8.8:8443/en/", func(p int) bool { return p == 8443 }); err == nil {
		t.Error("镜像端口与本机监听端口冲突时应拒绝")
	}
}

func TestFeedURLAndSubnet(t *testing.T) {
	if got := feedURL("http://150.40.105.16:33958/"); got != "http://150.40.105.16:33958/api/iphone/" {
		t.Errorf("feedURL = %q", got)
	}
	if got := mirrorSubnet("http://150.40.105.16:33958"); got != "150.40.105.0" {
		t.Errorf("mirrorSubnet = %q", got)
	}
	if got := mirrorSubnet("http://example.com:80"); got != "" {
		t.Errorf("域名的 /24 = %q，应为空", got)
	}
	if got := cleanMirrorLocation("Croatia (LOCAL Name: Hrvatska)"); got != "Croatia" {
		t.Errorf("cleanMirrorLocation = %q", got)
	}
}

// TestMirrorStoreSources 覆盖「拉列表 → 选源 → 落盘」与「拉不动就退避」。
// 列表页必须 ≥512 字节，所以测试里把 fixture 重复到够长。
func TestMirrorStoreSources(t *testing.T) {
	fixture, err := os.ReadFile("testdata/mirrors.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(fixture) + strings.Repeat("<!-- 填充到 512 字节以上，短页面按异常处理 -->", 12)

	// 计数器用原子：handler 在别的 goroutine 里跑，-race 下不该看到竞争。
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(page))
	}))
	defer srv.Close()

	dir := t.TempDir()
	store := NewMirrorStore(dir, NewClient("test"))
	cfg := config.MirrorSource{Enabled: true, SitesPage: srv.URL, MaxMirrors: 3, ListMaxHours: 12, TimeoutSeconds: 5}

	urls := store.Sources(context.Background(), cfg, time.Now())
	if got := hits.Load(); got != 1 {
		t.Errorf("应拉一次列表页，实得 %d 次", got)
	}
	if len(urls) != 2 {
		t.Fatalf("选出的源 = %v，期望 2 个（/24 与 location 去重）", urls)
	}
	if urls[0] != "http://150.40.105.16:33958/api/iphone/" || urls[1] != "http://62.133.35.246:2265/api/iphone/" {
		t.Errorf("源地址不对: %v", urls)
	}

	// 列表没过期就不该再打列表页。
	urls2 := store.Sources(context.Background(), cfg, time.Now().Add(time.Minute))
	if got := hits.Load(); got != 1 {
		t.Errorf("列表还在缓存有效期内却又打了 %d 次", got)
	}
	// 轮转偏移已经 +1：起点换了，选出的这一批也跟着换（同 /24 依然只留一个）。
	if len(urls2) != 2 || urls2[0] != "http://62.133.35.246:2265/api/iphone/" || urls2[1] != "http://150.40.105.6:11803/api/iphone/" {
		t.Errorf("轮转后应换一批起点，实得 %v", urls2)
	}

	// 过期后重拉成功。
	if got := store.Sources(context.Background(), cfg, time.Now().Add(13*time.Hour)); len(got) == 0 {
		t.Error("过期后应重拉成功")
	}

	entries, fetched, lastErr := store.Summary()
	if len(entries) != 3 || fetched.IsZero() || lastErr != "" {
		t.Errorf("Summary 不对: %d 条 / %v / %q", len(entries), fetched, lastErr)
	}
}

func TestMirrorStoreBackoffOnFailure(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	store := NewMirrorStore(t.TempDir(), NewClient("test"))
	cfg := config.MirrorSource{Enabled: true, SitesPage: srv.URL, MaxMirrors: 3, TimeoutSeconds: 5}
	now := time.Now()

	if got := store.Sources(context.Background(), cfg, now); len(got) != 0 {
		t.Errorf("拉不到列表时本轮应没有源，实得 %v", got)
	}
	// 一轮 Sources 里 Client 自己会重试，所以只看「有没有打过」，
	// 后退避期内必须一次都不再打。
	first := hits.Load()
	if first == 0 {
		t.Fatal("第一次没有打列表页")
	}
	// 首次失败退避 15 分钟：这期间的每一轮都不该再打上游。
	for i := 0; i < 4; i++ {
		now = now.Add(3 * time.Minute) // +3 / +6 / +9 / +12 分钟
		if got := store.Sources(context.Background(), cfg, now); len(got) != 0 {
			t.Errorf("退避期内不该有源，实得 %v", got)
		}
	}
	if got := hits.Load(); got != first {
		t.Errorf("退避期内又打了 %d 次上游（基准 %d）", got-first, first)
	}
	// 退避期满就该重试，不能一次失败静默一整天。
	if store.Sources(context.Background(), cfg, now.Add(20*time.Minute)); hits.Load() == first {
		t.Error("退避期满后应重试拉列表页")
	}
	if _, _, lastErr := store.Summary(); lastErr == "" {
		t.Error("应记录最后一次失败原因给界面显示")
	}
}

func TestMirrorStoreDisabledOrNil(t *testing.T) {
	var s *MirrorStore
	if got := s.Sources(context.Background(), config.MirrorSource{Enabled: true}, time.Now()); got != nil {
		t.Errorf("nil store 应返回空，实得 %v", got)
	}
	s.NoteFailure(time.Now())
	if e, f, err := s.Summary(); e != nil || !f.IsZero() || err != "" {
		t.Errorf("nil store 的 Summary 不该炸: %v %v %q", e, f, err)
	}
	if got := (NewMirrorStore(t.TempDir(), nil)).Sources(context.Background(), config.MirrorSource{Enabled: false}, time.Now()); got != nil {
		t.Errorf("关闭时不该返回源，实得 %v", got)
	}
}
