package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 测试之间最怕环境里残留的 VPNGATE_AGG_* 把断言带跑，
// 所以每个用例开头都先清一遍自己关心的变量。
var envVars = []string{
	"VPNGATE_AGG_CONFIG", "VPNGATE_AGG_LISTEN", "VPNGATE_AGG_DATA_DIR", "VPNGATE_AGG_TITLE",
	"VPNGATE_AGG_LOG_LEVEL", "VPNGATE_AGG_USER", "VPNGATE_AGG_PASSWORD", "VPNGATE_AGG_PBKDF2",
	"VPNGATE_AGG_COOKIE_SECURE", "VPNGATE_AGG_DISABLE_AUTH", "VPNGATE_AGG_REFRESH_MINUTES",
	"VPNGATE_AGG_MAX_NODES", "VPNGATE_AGG_PROBE_INTERVAL", "VPNGATE_AGG_PROBE_CONCURRENCY", "VPNGATE_AGG_PROBE_ENABLED",
	"VPNGATE_AGG_KEEP_VPNGATE_OWN", "VPNGATE_AGG_PURITY_RPM", "VPNGATE_AGG_PURITY_ENABLED",
	"VPNGATE_AGG_API_ENABLED", "VPNGATE_AGG_API_TOKEN", "VPNGATE_AGG_API_INCLUDE_CONFIG", "VPNGATE_AGG_API_MAX_NODES", "VPNGATE_AGG_API_RATE_PER_MIN",
	"IPQUERY_KEY", "IPINFO_TOKEN", "SCAMALYTICS_KEY", "IPQUALITYSCORE_KEY", "IPREGISTRY_KEY",
	"ABUSEIPDB_KEY", "DBIP_KEY", "IP2LOCATION_KEY",
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range envVars {
		old, ok := os.LookupEnv(k)
		if err := os.Unsetenv(k); err != nil {
			t.Fatalf("清 %s 失败: %v", k, err)
		}
		if ok {
			t.Cleanup(func() { _ = os.Setenv(k, old) })
		}
	}
}

func TestDefaultsAreSane(t *testing.T) {
	clearEnv(t)
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("默认配置就该过校验: %v", err)
	}
	if c.Listen != ":8080" || c.DataDir != "data" {
		t.Errorf("listen/data = %s / %s", c.Listen, c.DataDir)
	}
	// 官方主站和官方镜像站默认开；第三方名单（vpngate-list-mirror）已整段移除，
	// 节点量只能由官方两个来源决定。
	if !c.Sources.Vpngate.Enabled || !c.Sources.Mirrors.Enabled {
		t.Error("官方主站和官方镜像站默认必须开着")
	}
	// 容量上限必须有默认值：官方主站 + 全部镜像一轮就能给到几千个，
	// 不设上限会把第一轮探测和写盘规模直接顶满。
	if c.Sources.MaxNodes != 1500 {
		t.Errorf("池子容量上限默认应为 1500，实得 %d", c.Sources.MaxNodes)
	}
	if c.Sources.Mirrors.MaxMirrors != 0 {
		t.Errorf("镜像站默认每轮全抓（0），实得 %d", c.Sources.Mirrors.MaxMirrors)
	}
	if c.Sources.PurgeAbsentHours != 24 || c.Sources.PurgeFailRounds != 3 {
		t.Errorf("提前淘汰门槛 = %dh / %d 轮，对齐 mirror 是 24 小时 + 连续 3 轮",
			c.Sources.PurgeAbsentHours, c.Sources.PurgeFailRounds)
	}
	if c.Sources.KeepDays != 7 {
		t.Errorf("节点保留天数 = %d", c.Sources.KeepDays)
	}
	if !strings.Contains(c.Sources.UserAgent, "Mozilla") {
		t.Error("默认 UA 要有，官方站在 UA 太怪时会拒")
	}
	if c.Probe.Selection != "all" || c.Purity.Selection != "unchecked" {
		t.Errorf("默认选择策略 = %s / %s", c.Probe.Selection, c.Purity.Selection)
	}
	// 探测节奏对齐 mirror：6 小时一轮，说不清的节点一小时后补测一轮。
	if got := c.Probe.Interval(); got != 6*time.Hour {
		t.Errorf("探测间隔 = %v，期望 6h（源缩到官方 + 镜像后不需要一小时把池子重测一遍）", got)
	}
	if got := c.Probe.UnknownRetry(); got != time.Hour {
		t.Errorf("unknown 补测延迟 = %v，期望 1h", got)
	}
	if got := c.Sources.PurgeAbsent(); got != 24*time.Hour {
		t.Errorf("提前淘汰的缺席门槛 = %v，期望 24h", got)
	}
	if c.Probe.Concurrency > 512 || c.Probe.Concurrency < 1 {
		t.Errorf("默认并发 = %d（再高就是自己造 SYN 风暴）", c.Probe.Concurrency)
	}
	if c.Purity.RequestsPerMinute <= 0 || c.Purity.RequestsPerMinute > 60 {
		t.Errorf("默认限速 = %d rpm，免费源会限流，别默认打太猛", c.Purity.RequestsPerMinute)
	}

	// 默认值经过一次 Validate 不该被改动（否则「默认」和「跑起来的默认」是两套数）。
	before, _ := json.Marshal(Default())
	validated := Default()
	_ = validated.Validate()
	after, _ := json.Marshal(validated)
	if string(before) != string(after) {
		t.Errorf("Validate 改了默认值:\n%s\n%s", before, after)
	}
}

func writeConfig(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// 缺字段要保留默认值，不能因为加了新字段就把老配置里的默认掏空。
// 节点生命周期相关的几个旋钮：写错要兜住，但写 0 是「显式关掉」，不能被当成写错盖掉。
func TestValidatePoolLifecycleKnobs(t *testing.T) {
	clearEnv(t)

	t.Run("负数是写错了，回到默认", func(t *testing.T) {
		c := Default()
		c.Sources.PurgeAbsentHours = -1
		c.Sources.PurgeFailRounds = 0
		c.Sources.Mirrors.MaxMirrors = -3
		c.Probe.UnknownRetryMinutes = -5
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.Sources.PurgeAbsentHours != 24 {
			t.Errorf("缺席门槛 = %d，写错应该回到 24 小时", c.Sources.PurgeAbsentHours)
		}
		if c.Sources.PurgeFailRounds != 3 {
			t.Errorf("失败轮数 = %d，写错应该回到 3 轮", c.Sources.PurgeFailRounds)
		}
		if c.Sources.Mirrors.MaxMirrors != 0 {
			t.Errorf("镜像数 = %d，负数应该当成 0（全抓）", c.Sources.Mirrors.MaxMirrors)
		}
		if c.Probe.UnknownRetryMinutes != 0 {
			t.Errorf("补测延迟 = %d，负数应该当成 0（不补测）", c.Probe.UnknownRetryMinutes)
		}
	})

	t.Run("0 是显式选择，不能被默认盖掉", func(t *testing.T) {
		c := Default()
		c.Sources.PurgeAbsentHours = 0 // 只按 keep_days 过期，不做提前淘汰
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.Sources.PurgeAbsent() != 0 {
			t.Errorf("PurgeAbsent = %v，写 0 就该不淘汰", c.Sources.PurgeAbsent())
		}
	})

	t.Run("补测轮不能顶到下一轮头上", func(t *testing.T) {
		c := Default()
		c.Probe.IntervalMinutes = 60
		c.Probe.UnknownRetryMinutes = 240
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.Probe.UnknownRetryMinutes >= c.Probe.IntervalMinutes {
			t.Errorf("补测 %d 分钟 >= 轮间隔 %d 分钟：两轮会挨着跑，连续失败轮数会被算两次",
				c.Probe.UnknownRetryMinutes, c.Probe.IntervalMinutes)
		}
	})

	t.Run("失败轮数封顶", func(t *testing.T) {
		c := Default()
		c.Sources.PurgeFailRounds = 999
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.Sources.PurgeFailRounds != 12 {
			t.Errorf("失败轮数 = %d，超出 12 就该钉住（再高永远碰不到）", c.Sources.PurgeFailRounds)
		}
	})
}

func TestLoadMergesOverDefaults(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	p := writeConfig(t, dir, `{
  "listen": ":9999",
  "sources": {"refresh_interval_minutes": 15},
  "probe": {"concurrency": 8}
}`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9999" {
		t.Errorf("listen = %s", c.Listen)
	}
	if c.Sources.RefreshIntervalMinutes != 15 {
		t.Errorf("刷新间隔 = %d", c.Sources.RefreshIntervalMinutes)
	}
	if c.Probe.Concurrency != 8 {
		t.Errorf("探测并发 = %d", c.Probe.Concurrency)
	}
	// 没写过的字段仍是默认值。
	if c.Probe.TCPTimeoutSeconds != 5 {
		t.Errorf("tcp 超时被默认值掏空了: %d", c.Probe.TCPTimeoutSeconds)
	}
	if c.Sources.MaxNodes != 1500 {
		t.Errorf("没写过的 max_nodes 该留默认值，实得 %d", c.Sources.MaxNodes)
	}
	if c.Auth.SessionHours != 168 {
		t.Errorf("会话时长 = %d", c.Auth.SessionHours)
	}
	if c.Path() != p {
		t.Errorf("Path = %q，要记下实际加载的文件（改密码时写回同一份）", c.Path())
	}
	if got := c.Sources.RefreshInterval(); got != 15*time.Minute {
		t.Errorf("RefreshInterval = %v", got)
	}
	if got := c.Probe.Interval(); got != 6*time.Hour {
		t.Errorf("Probe.Interval = %v", got)
	}
	if got := c.Purity.TTL(); got != 168*time.Hour {
		t.Errorf("Purity.TTL = %v", got)
	}
}

// 配置文件写坏了要明确报错并指出是哪个文件，不能静默用默认值跑起来
// （用户会以为自己的配置生效了）。
func TestLoadBadJSONAndMissingFile(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	p := writeConfig(t, dir, `{"listen": `)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), p) {
		t.Errorf("坏 JSON 的报错要带上文件路径，实得 %v", err)
	}

	// 文件不存在不是错误：首次部署就是没有 config.json。
	c, err := Load(filepath.Join(dir, "nope.json"))
	if err != nil {
		t.Fatalf("没有配置文件不该报错: %v", err)
	}
	if c.Path() != "" {
		t.Errorf("没加载到文件时 Path 应是空串，实得 %q", c.Path())
	}
	if c.Listen != ":8080" {
		t.Errorf("应是默认配置，实得 %s", c.Listen)
	}

	// 目录不存在同样不该报错。
	if _, err := Load(filepath.Join(dir, "nested", "deeper", "config.json")); err != nil {
		t.Errorf("路径不存在时不该报错: %v", err)
	}

	writeConfig(t, dir, `{"probe": {"selection": "随便写的"}}`)
	if _, err := Load(filepath.Join(dir, "config.json")); err == nil {
		t.Error("非法的 selection 要被拒绝，不能悄悄按默认跑")
	}
}

// 环境变量是容器里最常用的覆盖手段，优先级必须在配置文件之上。
func TestEnvOverridesFile(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	p := writeConfig(t, dir, `{
  "listen": ":1234",
  "data_dir": "from-file",
  "auth": {"username": "file-user", "cookie_secure": false},
  "sources": {"refresh_interval_minutes": 30},
  "probe": {"enabled": true, "interval_minutes": 30, "concurrency": 16},
  "purity": {"requests_per_minute": 10},
  "cdn": {"enabled": true, "use_pool": true}
}`)
	t.Setenv("VPNGATE_AGG_LISTEN", ":7000")
	t.Setenv("VPNGATE_AGG_DATA_DIR", filepath.Join(dir, "from-env"))
	t.Setenv("VPNGATE_AGG_TITLE", "我的节点池")
	t.Setenv("VPNGATE_AGG_USER", "env-user")
	t.Setenv("VPNGATE_AGG_PASSWORD", "env-password")
	t.Setenv("VPNGATE_AGG_COOKIE_SECURE", "true")
	t.Setenv("VPNGATE_AGG_DISABLE_AUTH", "1")
	t.Setenv("VPNGATE_AGG_REFRESH_MINUTES", "5")
	t.Setenv("VPNGATE_AGG_MAX_NODES", "800")
	t.Setenv("VPNGATE_AGG_PROBE_INTERVAL", "10")
	t.Setenv("VPNGATE_AGG_PROBE_CONCURRENCY", "32")
	t.Setenv("VPNGATE_AGG_PROBE_ENABLED", "false")
	t.Setenv("VPNGATE_AGG_PURITY_RPM", "3")
	t.Setenv("VPNGATE_AGG_PURITY_ENABLED", "false")

	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":7000" {
		t.Errorf("listen = %s，环境变量该盖过文件", c.Listen)
	}
	if c.DataDir != filepath.Join(dir, "from-env") {
		t.Errorf("data_dir = %s", c.DataDir)
	}
	if c.Title != "我的节点池" {
		t.Errorf("title = %q", c.Title)
	}
	if c.Auth.Username != "env-user" || c.Auth.Password != "env-password" {
		t.Errorf("auth = %+v", c.Auth)
	}
	if !c.Auth.CookieSecure || !c.Auth.DisableAuth {
		t.Errorf("布尔环境变量没生效: %+v", c.Auth)
	}
	if c.Sources.RefreshIntervalMinutes != 5 || c.Probe.IntervalMinutes != 10 || c.Probe.Concurrency != 32 {
		t.Errorf("数值覆盖没生效: %d / %d / %d", c.Sources.RefreshIntervalMinutes, c.Probe.IntervalMinutes, c.Probe.Concurrency)
	}
	if c.Sources.MaxNodes != 800 {
		t.Errorf("max_nodes = %d，环境变量该盖过默认值", c.Sources.MaxNodes)
	}
	if c.Probe.Enabled || c.Purity.Enabled {
		t.Errorf("false/off/no 这几种写法没被认出来: probe=%v purity=%v", c.Probe.Enabled, c.Purity.Enabled)
	}
	// 旧配置文件里残留的 cdn 段要安静地忽略（那个源已经移除）：不能报错拦启动，
	// 也不能把别的配置带坑里。
	if c.Sources.MaxNodes != 800 || !c.Sources.Mirrors.Enabled {
		t.Errorf("残留的 cdn 段弄坏了配置: max_nodes=%d mirrors=%v", c.Sources.MaxNodes, c.Sources.Mirrors.Enabled)
	}
	if c.Purity.RequestsPerMinute != 3 {
		t.Errorf("rpm = %d", c.Purity.RequestsPerMinute)
	}
}

// 关掉鉴权时用户名可以为空；开着就不许空 —— 否则连登录页都不知道填什么。
func TestEnvBadNumbersIgnored(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	p := writeConfig(t, dir, `{}`)
	t.Setenv("VPNGATE_AGG_REFRESH_MINUTES", "abc")
	t.Setenv("VPNGATE_AGG_PROBE_CONCURRENCY", "  ")
	t.Setenv("VPNGATE_AGG_COOKIE_SECURE", "maybe")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sources.RefreshIntervalMinutes != 60 {
		t.Errorf("写坏的数字该被忽略并留默认值，实得 %d", c.Sources.RefreshIntervalMinutes)
	}
	if c.Probe.Concurrency != 64 {
		t.Errorf("并发 = %d", c.Probe.Concurrency)
	}
	if c.Auth.CookieSecure {
		t.Error("认不出来的布尔写法不该改成 true")
	}
}

func TestEnvAPIKeys(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	p := writeConfig(t, dir, `{"purity": {"keys": {"ipregistry": "from-file"}}}`)
	t.Setenv("IPINFO_TOKEN", "ipinfo-token")
	t.Setenv("SCAMALYTICS_KEY", "scamalytics-key")
	t.Setenv("IPQUALITYSCORE_KEY", "ipqs-key")
	t.Setenv("IPREGISTRY_KEY", "ipregistry-env")
	t.Setenv("ABUSEIPDB_KEY", "abuse-key")
	t.Setenv("IPQUERY_KEY", "  ") // 空的一律当没配

	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"ipinfo": "ipinfo-token", "scamalytics": "scamalytics-key", "ipqualityscore": "ipqs-key",
		"ipregistry": "ipregistry-env", "abuseipdb": "abuse-key",
	} {
		if got := c.Purity.Keys[name]; got != want {
			t.Errorf("key %s = %q，期望 %q", name, got, want)
		}
	}
	if v, ok := c.Purity.Keys["ipquery"]; ok && strings.TrimSpace(v) != "" {
		t.Errorf("空 key 不该被当成配好了: %q", v)
	}
}

func TestValidateClampsAndRejects(t *testing.T) {
	t.Run("空用户名且开着鉴权", func(t *testing.T) {
		c := Default()
		c.Auth.Username = "   "
		if err := c.Validate(); err == nil {
			t.Error("应报错")
		}
		c.Auth.DisableAuth = true
		if err := c.Validate(); err != nil {
			t.Errorf("关掉鉴权时用户名可以为空: %v", err)
		}
	})
	t.Run("会话时长过大", func(t *testing.T) {
		c := Default()
		c.Auth.SessionHours = 24*365 + 1
		if err := c.Validate(); err == nil {
			t.Error("会话时长过大应报错")
		}
		c = Default()
		c.Auth.SessionHours = 0
		_ = c.Validate()
		if c.Auth.SessionHours != 168 {
			t.Errorf("0 应回落到默认，实得 %d", c.Auth.SessionHours)
		}
	})
	t.Run("探测并发上限", func(t *testing.T) {
		c := Default()
		c.Probe.Concurrency = 99999
		_ = c.Validate()
		if c.Probe.Concurrency != 512 {
			t.Errorf("并发没被压到上限: %d", c.Probe.Concurrency)
		}
		c = Default()
		c.Probe.HistoryKeep = 5000
		_ = c.Validate()
		if c.Probe.HistoryKeep != 64 {
			t.Errorf("history_keep 没被压到上限: %d（节点池文件会被撑大）", c.Probe.HistoryKeep)
		}
		c = Default()
		c.Probe.Retries = -3
		_ = c.Validate()
		if c.Probe.Retries != 0 {
			t.Errorf("负的重试次数没被纠正: %d", c.Probe.Retries)
		}
	})
	t.Run("非法选择策略", func(t *testing.T) {
		c := Default()
		c.Probe.Selection = "everything"
		if err := c.Validate(); err == nil {
			t.Error("probe.selection 非法值应报错")
		}
		c = Default()
		c.Purity.Selection = "everything"
		if err := c.Validate(); err == nil {
			t.Error("purity.selection 非法值应报错")
		}
	})
	t.Run("池子容量上限", func(t *testing.T) {
		c := Default()
		c.Sources.MaxNodes = -1
		if err := c.Validate(); err == nil {
			t.Error("max_nodes 为负应报错（要「不限」得写 0）")
		}
		c = Default()
		c.Sources.MaxNodes = 0
		if err := c.Validate(); err != nil {
			t.Errorf("0 = 不限，不该报错: %v", err)
		}
		c = Default()
		c.Sources.MaxNodes = 999999
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.Sources.MaxNodes != 100000 {
			t.Errorf("多打几个 0 该被压到 100000，实得 %d", c.Sources.MaxNodes)
		}
	})
	t.Run("关掉源就别校验它", func(t *testing.T) {
		c := Default()
		c.Sources.Mirrors.Enabled = false
		c.Probe.Enabled = false
		c.Probe.Selection = "非法"
		c.Purity.Enabled = false
		c.Purity.Selection = "非法"
		if err := c.Validate(); err != nil {
			t.Errorf("关掉的源不该拦启动: %v", err)
		}
		// 关掉的镜像站也不该被填上默认地址：空值是「我自己指定」的语义。
		c = Default()
		c.Sources.Mirrors.Enabled = false
		c.Sources.Mirrors.SitesPage = ""
		_ = c.Validate()
		if c.Sources.Mirrors.SitesPage != "" {
			t.Errorf("关掉时别悄悄填默认地址: %q", c.Sources.Mirrors.SitesPage)
		}
	})
	t.Run("空必填项回落默认", func(t *testing.T) {
		c := Config{Auth: AuthConfig{Username: "admin"}}
		if err := c.Validate(); err != nil {
			t.Fatalf("只是没填字段的配置不该报错: %v", err)
		}
		if c.Listen != ":8080" || c.DataDir != "data" || c.Title == "" {
			t.Errorf("零值没被兜住: %+v", c)
		}
		if c.Sources.KeepDays != 7 || c.Sources.RefreshIntervalMinutes != 60 {
			t.Errorf("源参数没被兜住: %+v", c.Sources)
		}
		if c.Auth.SessionHours != 168 {
			t.Errorf("会话时长没被兜住: %d", c.Auth.SessionHours)
		}
		if c.Sources.UserAgent == "" {
			t.Error("UA 没被兜住，官方站对空 UA 不友好")
		}
	})
	t.Run("全零配置直接被拒", func(t *testing.T) {
		// auth 段名写错（比如写成 Auth）会落到这里：与其带着空用户名跑起来，
		// 不如报错让用户发现配置根本没被读到。
		if err := (&Config{}).Validate(); err == nil {
			t.Error("全零配置该报错")
		}
	})
}

func TestSaveRoundTrip(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "config.json")
	c := Default()
	c.Listen = ":6001"
	c.Purity.Keys = map[string]string{"ipinfo": "tok"}
	c.Purity.Providers = map[string]bool{"ipquery": false}
	c.path = p
	if err := c.Save(); err != nil {
		t.Fatalf("Save 失败: %v", err)
	}
	if _, err := os.Stat(p + ".tmp"); err == nil {
		t.Error("临时文件没清掉")
	}
	if info, err := os.Stat(p); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o600 {
		t.Errorf("配置里有 API key，权限应是 0600，实得 %o", info.Mode().Perm())
	}

	back, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if back.Listen != ":6001" {
		t.Errorf("listen 没存回来: %s", back.Listen)
	}
	if back.Purity.Keys["ipinfo"] != "tok" {
		t.Errorf("keys 没存回来: %v", back.Purity.Keys)
	}
	if back.Purity.Providers["ipquery"] {
		t.Error("providers 的显式关闭没存回来")
	}
	// path 是运行时信息，不该被序列化进文件。
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), `"path"`) {
		t.Error("path 字段被写进配置了")
	}
	var pretty map[string]any
	if err := json.Unmarshal(raw, &pretty); err != nil {
		t.Fatalf("写出的不是合法 JSON: %v", err)
	}

	// 没有原路径时写到 data 目录下，用户还能找到它。
	c2 := Default()
	c2.DataDir = dir
	if err := c2.Save(); err != nil {
		t.Fatal(err)
	}
	if c2.Path() != filepath.Join(dir, "config.json") {
		t.Errorf("Path = %q", c2.Path())
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err != nil {
		t.Error("没落盘")
	}
}

func TestProviderEnabledRules(t *testing.T) {
	p := PurityConfig{}
	// 免费源默认开，要 key 的默认关。
	if !p.ProviderEnabled("ipquery", false) || !p.ProviderEnabled("builtin", false) {
		t.Error("免费来源默认该开着")
	}
	if p.ProviderEnabled("ipinfo", true) {
		t.Error("没配 key 的来源不该开：每轮都会攒一堆 401")
	}
	p.Keys = map[string]string{"ipinfo": " tok "}
	if !p.ProviderEnabled("ipinfo", true) {
		t.Error("配了 key 就该开")
	}
	// 显式开关优先于以上两条。
	p.Providers = map[string]bool{"ipquery": false, "ipinfo": true, "abuseipdb": false}
	if p.ProviderEnabled("ipquery", false) {
		t.Error("显式关掉免费源就该关掉")
	}
	if !p.ProviderEnabled("ipinfo", true) {
		t.Error("显式打开且有 key 就该开")
	}
	if p.ProviderEnabled("abuseipdb", true) {
		t.Error("显式关掉的来源即使有 key 也不该开")
	}
	// 没在 map 里出现过的来源回落到默认规则。
	if !p.ProviderEnabled("scamalytics", false) {
		t.Error("没提过的免费来源该默认开")
	}
	// key 只有空格时等于没配。
	q := PurityConfig{Keys: map[string]string{"ipinfo": "   "}}
	if q.ProviderEnabled("ipinfo", true) {
		t.Error("空白 key 等于没配")
	}
}

func TestMaskedKey(t *testing.T) {
	if got := MaskedKey(""); got != "" {
		t.Errorf("空 key = %q", got)
	}
	if got := MaskedKey("   "); got != "" {
		t.Errorf("空白 key = %q", got)
	}
	// 短的整个打星：露首尾就等于把短 key 全露出来。
	if got := MaskedKey("abc123"); got != "******" || len(got) != 6 {
		t.Errorf("短 key = %q", got)
	}
	got := MaskedKey("abcdefghij")
	if got != "abc****hij" {
		t.Errorf("长 key = %q，期望只露首尾各 3 位", got)
	}
	if len(got) != len("abcdefghij") {
		t.Errorf("脱敏后长度变了: %d vs %d（长度信息不能泄漏）", len(got), len("abcdefghij"))
	}
	// 界面上回显时不能出现原始 key 本身。
	long := "sk-live-verylongsecretvalue-9"
	if strings.Contains(MaskedKey(long), "verylongsecret") {
		t.Errorf("中间部分没遮住: %s", MaskedKey(long))
	}
}

// 自营机房节点默认不保留：public-vpn-* / 219.100.37.0/24 是 SoftEther 官方放在
// 学术网里的机房出口，要家宽的人不想要它；想要全局出口稳的人可以打开。
func TestKeepVpngateOwnDefaultsAndEnv(t *testing.T) {
	clearEnv(t)
	if Default().Sources.KeepVpngateOwn {
		t.Error("keep_vpngate_own 默认应为 false")
	}
	t.Setenv("VPNGATE_AGG_KEEP_VPNGATE_OWN", "1")
	c, err := Load("") // 没有配置文件，只吃默认值 + 环境变量
	if err != nil {
		t.Fatalf("读配置失败: %v", err)
	}
	if !c.Sources.KeepVpngateOwn {
		t.Error("VPNGATE_AGG_KEEP_VPNGATE_OWN=1 没生效")
	}
}

// 界面上改的开关要能在重启后被读回来：PatchConfig 把配置写进 <data_dir>/config.json，
// 启动时只找当前目录的 config.json 的话，改动就静默丢了 —— 比不给改更糟。
func TestLoadFindsConfigInDataDir(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	t.Setenv("VPNGATE_AGG_DATA_DIR", dir)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"data_dir":"`+dir+`","sources":{"keep_days":15}}`), 0o600); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load 失败: %v", err)
	}
	if cfg.Sources.KeepDays != 15 {
		t.Errorf("没读到数据目录里的配置：keep_days=%d（path=%q）", cfg.Sources.KeepDays, cfg.Path())
	}
	if cfg.Path() != path {
		t.Errorf("配置文件路径 = %q，期望 %q", cfg.Path(), path)
	}

	// 数据目录里没有配置文件时保持默认值，并且不要凭空造一个路径出来。
	empty := t.TempDir()
	t.Setenv("VPNGATE_AGG_DATA_DIR", empty)
	fresh, err := Load("")
	if err != nil {
		t.Fatalf("空目录 Load 失败: %v", err)
	}
	if fresh.Sources.KeepDays != 7 || fresh.Path() != "" {
		t.Errorf("空数据目录应该用默认值，实际 keep_days=%d path=%q", fresh.Sources.KeepDays, fresh.Path())
	}

	// VPNGATE_AGG_CONFIG 显式指定时优先于数据目录里的那份。
	other := filepath.Join(t.TempDir(), "special.json")
	if err := os.WriteFile(other, []byte(`{"sources":{"keep_days":41}}`), 0o600); err != nil {
		t.Fatalf("写配置失败: %v", err)
	}
	t.Setenv("VPNGATE_AGG_CONFIG", other)
	pointed, err := Load("")
	if err != nil {
		t.Fatalf("显式指定 Load 失败: %v", err)
	}
	if pointed.Sources.KeepDays != 41 {
		t.Errorf("VPNGATE_AGG_CONFIG 没生效：keep_days=%d", pointed.Sources.KeepDays)
	}
}

// 对外接口（GET /vpngate/api/iphone/）的门闩：默认关着，开着就必须带 token。
// 「enabled=true 但 token 忘了填」是最难发现的事故形态 —— 接口对整个互联网敞开，
// 而节点库里连 .ovpn 正文都有，所以这里选择拒绝启动而不是悄悄兜一个默认值。
func TestAPISection(t *testing.T) {
	clearEnv(t)

	t.Run("默认关着，且校验能过", func(t *testing.T) {
		c := Default()
		if c.API.Enabled {
			t.Error("对外接口默认就该关着")
		}
		if !c.API.IncludeConfig {
			t.Error("默认要带 OpenVPN_ConfigData_Base64：不给这一列就不算跟官方同形")
		}
		if c.API.MaxNodes != 500 || c.API.RatePerMinute != 30 {
			t.Errorf("默认 max_nodes/rate = %d / %d", c.API.MaxNodes, c.API.RatePerMinute)
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("默认配置过不了校验: %v", err)
		}
	})

	t.Run("开着但没 token 直接拒绝启动", func(t *testing.T) {
		c := Default()
		c.API.Enabled = true
		if err := c.Validate(); err == nil {
			t.Error("api.enabled=true 而 token 为空必须报错，不能把接口裸开")
		}
		c.API.Token = "  " // 只有空格也算没填
		if err := c.Validate(); err == nil {
			t.Error("空白 token 不该被当成配好了")
		}
		c.API.Enabled = false
		if err := c.Validate(); err != nil {
			t.Errorf("接口关着时不该拦启动: %v", err)
		}
	})

	t.Run("token 太短", func(t *testing.T) {
		c := Default()
		c.API.Enabled = true
		c.API.Token = "hunter2"
		if err := c.Validate(); err == nil {
			t.Error("7 个字符的 token 该被拒：这是对外接口唯一的门闩")
		}
		c.API.Token = "0123456789abcdef"
		if err := c.Validate(); err != nil {
			t.Errorf("16 字符该放行: %v", err)
		}
		if c.API.Token != "0123456789abcdef" {
			t.Errorf("token 被改了: %q", c.API.Token)
		}
	})

	t.Run("上限钉住，负数回默认", func(t *testing.T) {
		c := Default()
		c.API.Enabled = true
		c.API.Token = "0123456789abcdef0000"
		c.API.MaxNodes = 999999
		c.API.RatePerMinute = -5
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
		if c.API.MaxNodes != 500 {
			t.Errorf("max_nodes = %d，一页带正文的名单不该超过 500", c.API.MaxNodes)
		}
		if c.API.RatePerMinute != 0 {
			t.Errorf("rate_per_minute = %d，负数该当不限流", c.API.RatePerMinute)
		}
		c = Default()
		c.API.MaxNodes = 0
		_ = c.Validate()
		if c.API.MaxNodes != 500 {
			t.Errorf("0 该回落到默认 500，实得 %d", c.API.MaxNodes)
		}
	})

	t.Run("环境变量能开", func(t *testing.T) {
		t.Setenv("VPNGATE_AGG_API_ENABLED", "true")
		t.Setenv("VPNGATE_AGG_API_TOKEN", "env-token-0123456789abcd")
		t.Setenv("VPNGATE_AGG_API_INCLUDE_CONFIG", "false")
		t.Setenv("VPNGATE_AGG_API_MAX_NODES", "50")
		t.Setenv("VPNGATE_AGG_API_RATE_PER_MIN", "5")
		c := Default()
		applyEnv(&c)
		if err := c.Validate(); err != nil {
			t.Fatalf("环境变量开接口后校验失败: %v", err)
		}
		if !c.API.Enabled || c.API.Token != "env-token-0123456789abcd" {
			t.Errorf("enabled/token = %v / %q", c.API.Enabled, c.API.Token)
		}
		if c.API.IncludeConfig || c.API.MaxNodes != 50 || c.API.RatePerMinute != 5 {
			t.Errorf("include/max/rate = %v / %d / %d", c.API.IncludeConfig, c.API.MaxNodes, c.API.RatePerMinute)
		}
	})

	t.Run("老配置文件缺 api 段也照样起", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(`{"listen":":9000","auth":{"username":"u","password":"p"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil {
			t.Fatalf("Load 失败: %v", err)
		}
		if c.API.Enabled || !c.API.IncludeConfig || c.API.MaxNodes != 500 {
			t.Errorf("缺 api 段时应保留默认，实得 %+v", c.API)
		}
	})
}
