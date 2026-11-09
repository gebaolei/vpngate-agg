package web

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 口令哈希是 31 万轮 PBKDF2，一次约 0.2 秒；这个文件里的用例
// 故意不多，但每条都对着真实的登录路径打。
func TestHashAndVerifyPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "pbkdf2$sha256$310000$") {
		t.Errorf("摘要格式 = %q，期望 pbkdf2$sha256$迭代$盐$哈希", h)
	}
	if len(strings.Split(h, "$")) != 5 {
		t.Errorf("摘要段数不对: %q", h)
	}
	if !VerifyPassword("correct horse battery", h) {
		t.Error("正确口令没通过")
	}
	if VerifyPassword("Correct horse battery", h) {
		t.Error("大小写不同就该不过")
	}
	if VerifyPassword("", h) {
		t.Error("空口令不该通过")
	}

	// 同一个口令两次摘要必须不同（随机盐），否则彩虹表白准备了。
	h2, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if h == h2 {
		t.Error("两次摘要完全一样，盐没生效")
	}
	if !VerifyPassword("correct horse battery", h2) {
		t.Error("第二份摘要也该能验")
	}

	// 摘要写坏时一律算不通过，不能 panic 也不能当通过。
	bad := []string{
		"", "x", "admin/admin",
		"bcrypt$sha256$310000$00$00",
		"pbkdf2$md5$310000$00$00",
		"pbkdf2$sha256$0$00$00",
		"pbkdf2$sha256$abc$00$00",
		"pbkdf2$sha256$310000$$00",
		"pbkdf2$sha256$310000$zz$00",
		"pbkdf2$sha256$310000$00$zz",
		"pbkdf2$sha256$310000$00$00$extra",
	}
	for _, b := range bad {
		if VerifyPassword("whatever", b) {
			t.Errorf("坏摘要 %q 居然通过了", b)
		}
	}

	// 盐对不上就验不过：防止把哈希段直接当口令用。
	parts := strings.Split(h, "$")
	swapped := strings.Join([]string{parts[0], parts[1], parts[2], parts[4], parts[3]}, "$")
	if VerifyPassword("correct horse battery", swapped) {
		t.Error("盐和哈希调换了位置也该验不过")
	}
}

func newAuth(t *testing.T, cfg Config) *Auth {
	t.Helper()
	cfg.SessionHours = 1
	a, err := NewAuth(cfg, t.TempDir())
	if err != nil {
		t.Fatalf("NewAuth 失败: %v", err)
	}
	return a
}

func TestLoginWithConfiguredPassword(t *testing.T) {
	a := newAuth(t, Config{Username: "operator", Password: "a-good-password"})
	if got := a.Username(); got != "operator" {
		t.Errorf("用户名 = %q", got)
	}
	val, exp, err := a.Login("operator", "a-good-password", "10.0.0.1")
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	if val == "" {
		t.Fatal("登录成功却没给会话值")
	}
	if !exp.After(time.Now()) {
		t.Errorf("过期时间 = %v", exp)
	}
	sess, ok := a.ParseSession(val)
	if !ok || sess.User != "operator" {
		t.Errorf("会话解析 = %+v ok=%v", sess, ok)
	}

	// 用户名带空格也算对（很多人从密码管理器里复制会带上空格）。
	if _, _, err := a.Login("  operator  ", "a-good-password", "10.0.0.1"); err != nil {
		t.Errorf("用户名带空格应能登录: %v", err)
	}
	// 口令错、用户错，错误信息要一样：不能告诉攻击者哪个字段对了。
	_, _, errBadPw := a.Login("operator", "wrong-password", "10.0.0.2")
	_, _, errBadUser := a.Login("root", "a-good-password", "10.0.0.3")
	if errBadPw == nil || errBadUser == nil {
		t.Fatal("错的凭据必须失败")
	}
	if errBadPw.Error() != errBadUser.Error() {
		t.Errorf("错误信息泄露了哪个字段对: %q vs %q", errBadPw, errBadUser)
	}
	if _, _, err := a.Login("operator", "", "10.0.0.4"); err == nil {
		t.Error("空口令不该能登录")
	}
}

// 用户名默认 admin，但绝不是一个能直接登进去的默认口令。
func TestDefaultUsernameAndRandomPassword(t *testing.T) {
	a := newAuth(t, Config{})
	if got := a.Username(); got != "admin" {
		t.Errorf("默认用户名 = %q", got)
	}
	if _, _, err := a.Login("admin", "admin", "10.0.0.1"); err == nil {
		t.Error("admin/admin 这种默认口令不该能登进来")
	}
	if _, _, err := a.Login("admin", "", "10.0.0.1"); err == nil {
		t.Error("空口令不该能登进来")
	}
	// 随机口令已经落盘，运维可以从 credentials.json 旁边拿。
	if _, err := os.Stat(filepath.Join(filepath.Dir(a.path), "credentials.json")); err != nil {
		t.Errorf("凭据没落盘: %v", err)
	}
}

// 已经配了口令时，摘要不能以明文形式躺在磁盘上。
func TestCredentialsFileHasNoPlaintext(t *testing.T) {
	a := newAuth(t, Config{Username: "admin", Password: "very-secret-pw"})
	b, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "very-secret-pw") {
		t.Error("明文口令被写进凭据文件了")
	}
	var c credentials
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("凭据文件不是合法 JSON: %v", err)
	}
	if c.Username != "admin" || !strings.HasPrefix(c.PBKDF2, "pbkdf2$") {
		t.Errorf("凭据内容 = %+v", c)
	}
	if info, err := os.Stat(a.path); err == nil && info.Mode().Perm() != 0o600 {
		t.Errorf("凭据文件权限 = %o，期望 0600", info.Mode().Perm())
	}
}

// 界面上改过口令之后，重启不该被 config 里的明文覆盖回去。
func TestDiskCredentialsWinOverConfig(t *testing.T) {
	dir := t.TempDir()
	a, err := NewAuth(Config{Password: "first-password", SessionHours: 1}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Login("admin", "first-password", "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if err := a.ChangePassword("first-password", "second-password"); err != nil {
		t.Fatal(err)
	}

	// 模拟重启：config 里还写着旧口令。
	b, err := NewAuth(Config{Password: "first-password", Username: "ops", SessionHours: 1}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Login("ops", "second-password", "1.1.1.1"); err != nil {
		t.Errorf("改过的口令重启后失效了: %v", err)
	}
	if _, _, err := b.Login("ops", "first-password", "1.1.1.1"); err == nil {
		t.Error("config 里的旧口令把改过的口令盖掉了")
	}
	// 用户名跟着 config 走（口令不动）。
	if b.Username() != "ops" {
		t.Errorf("用户名 = %q，期望跟着 config 改成 ops", b.Username())
	}
}

// 预生成的摘要（vpngate-agg passwd 的输出）要能直接写进 config 用。
func TestPrecomputedPBKDF2FromConfig(t *testing.T) {
	hash, err := HashPassword("hashed-login-pw")
	if err != nil {
		t.Fatal(err)
	}
	a := newAuth(t, Config{PBKDF2: hash})
	if _, _, err := a.Login("admin", "hashed-login-pw", "2.2.2.2"); err != nil {
		t.Errorf("用预生成摘要登录失败: %v", err)
	}
	if _, _, err := a.Login("admin", "hashed-login-p", "2.2.2.2"); err == nil {
		t.Error("少一个字符也该验不过")
	}
	// 摘要不合法时不能被当成口令接受。
	broken := newAuth(t, Config{PBKDF2: "not-a-hash"})
	if _, _, err := broken.Login("admin", "not-a-hash", "2.2.2.3"); err == nil {
		t.Error("坏摘要不该让任何人登进来")
	}
}

func TestChangePassword(t *testing.T) {
	a := newAuth(t, Config{Password: "original-pass"})
	for _, short := range []string{"", "short", "1234567"} {
		if err := a.ChangePassword("original-pass", short); err == nil {
			t.Errorf("%q 太短了却没报错", short)
		}
	}
	if err := a.ChangePassword("wrong-old-pass", "a-brand-new-pass"); err == nil {
		t.Error("旧口令不对却改了")
	}
	if _, _, err := a.Login("admin", "original-pass", "3.3.3.3"); err != nil {
		t.Errorf("改失败后旧口令还能用: %v", err)
	}
	if err := a.ChangePassword("original-pass", "a-brand-new-pass"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Login("admin", "original-pass", "3.3.3.3"); err == nil {
		t.Error("旧口令还能登")
	}
	if _, _, err := a.Login("admin", "a-brand-new-pass", "3.3.3.3"); err != nil {
		t.Errorf("新口令登不进: %v", err)
	}
}

// 登录限速：字典攻击不该能无限试。
func TestLoginRateLimit(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	restore := now
	defer func() { now = restore }()
	now = func() time.Time { return base }

	a := newAuth(t, Config{Password: "rate-limit-pass"})
	// 4 次失败还不该锁（正常用户偶尔打错两次很正常）。
	for i := 0; i < 4; i++ {
		if _, _, err := a.Login("admin", "nope", "9.9.9.9"); err == nil ||
			strings.Contains(err.Error(), "失败次数过多") {
			t.Fatalf("第 %d 次失败不该锁定: %v", i+1, err)
		}
	}
	// 第 5 次开始进入退避。
	if _, _, err := a.Login("admin", "nope", "9.9.9.9"); err == nil {
		t.Fatal("该失败了")
	}
	_, _, err := a.Login("admin", "rate-limit-pass", "9.9.9.9")
	if err == nil || !strings.Contains(err.Error(), "失败次数过多") {
		t.Errorf("锁定后连正确口令都要挡: %v", err)
	}
	// 别的 IP 不该被牵连（办公室共用一个出口时别一起锁）。
	if _, _, err := a.Login("admin", "rate-limit-pass", "9.9.9.8"); err != nil {
		t.Errorf("别的 IP 被牵连了: %v", err)
	}
	// 退避到点自动解锁。
	now = func() time.Time { return base.Add(31 * time.Minute) }
	if _, _, err := a.Login("admin", "rate-limit-pass", "9.9.9.9"); err != nil {
		t.Errorf("退避过了还锁着: %v", err)
	}
}

// 成功登录要清掉失败计数：不然白天误操作几次，晚上就进不去了。
func TestSuccessfulLoginClearsAttempts(t *testing.T) {
	base := time.Now()
	restore := now
	defer func() { now = restore }()
	now = func() time.Time { return base }

	a := newAuth(t, Config{Password: "clear-attempts"})
	for i := 0; i < 4; i++ {
		a.Login("admin", "nope", "7.7.7.7")
	}
	if _, _, err := a.Login("admin", "clear-attempts", "7.7.7.7"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, _, err := a.Login("admin", "nope", "7.7.7.7"); err != nil && strings.Contains(err.Error(), "失败次数过多") {
			t.Errorf("登录成功过却又被锁: %v", err)
		}
	}
}

func TestSessionSignatureAndExpiry(t *testing.T) {
	dir := t.TempDir()
	a, err := NewAuth(Config{Password: "session-pass", SessionHours: 1}, dir)
	if err != nil {
		t.Fatal(err)
	}
	val, _, err := a.Login("admin", "session-pass", "4.4.4.4")
	if err != nil {
		t.Fatal(err)
	}
	sess, ok := a.ParseSession(val)
	if !ok {
		t.Fatal("刚签出来的会话该有效")
	}
	if sess.User != "admin" || sess.Nonce == "" {
		t.Errorf("会话内容 = %+v", sess)
	}
	// 每次登录的 nonce 不同：同一个口令登两次不该得到同一个值，
	// 否则「退出登录」就没法让旧 cookie 失效。
	other, _, _ := a.Login("admin", "session-pass", "4.4.4.4")
	if other == val {
		t.Error("两次登录发了同一个会话值")
	}

	// 改载荷不改签名 → 无效（否则用户可以自己把用户名改成 admin）。
	i := strings.LastIndexByte(val, '.')
	enc, sig := val[:i], val[i+1:]
	blob, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(blob, &payload); err != nil {
		t.Fatal(err)
	}
	payload["u"] = "root"
	rewritten, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	tampered := base64.RawURLEncoding.EncodeToString(rewritten) + "." + sig
	if got, ok := a.ParseSession(tampered); ok {
		t.Errorf("把用户改成 %s 还验得过，签名没起作用", got.User)
	}
	// 签名本身被改一个字符也要无效。
	flip := []byte(sig)
	if flip[0] == '0' {
		flip[0] = '1'
	} else {
		flip[0] = '0'
	}
	if _, ok := a.ParseSession(enc + "." + string(flip)); ok {
		t.Error("签名被改了一个字符还验得过")
	}
	// 换一份密钥（重启前拷走 key 之外的数据）也要无效。
	other3, err := NewAuth(Config{Password: "session-pass", SessionHours: 1}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := other3.ParseSession(val); ok {
		t.Error("别的实例的密钥不该认这个会话")
	}
	for _, garbage := range []string{"", ".", "abc", "abc.", ".abc", "abc.xyz", "abc." + strings.Repeat("0", 64)} {
		if _, ok := a.ParseSession(garbage); ok {
			t.Errorf("垃圾会话值 %q 居然有效", garbage)
		}
	}
}

// 会话过期后必须失效：签了名的 cookie 不会自己过期，只靠载荷里的 Exp。
func TestSessionExpiry(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	restore := now
	defer func() { now = restore }()
	now = func() time.Time { return base }

	a := newAuth(t, Config{Password: "ttl-pass"})
	val, exp, err := a.Login("admin", "ttl-pass", "5.5.5.5")
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(base.Add(time.Hour)) {
		t.Errorf("过期时间 = %v，期望按 SessionHours=1", exp)
	}
	if _, ok := a.ParseSession(val); !ok {
		t.Error("刚签发时该有效")
	}
	now = func() time.Time { return base.Add(59 * time.Minute) }
	if _, ok := a.ParseSession(val); !ok {
		t.Error("还在有效期内却判无效")
	}
	now = func() time.Time { return base.Add(61 * time.Minute) }
	if _, ok := a.ParseSession(val); ok {
		t.Error("过期后还判有效")
	}
}

// 会话密钥落盘：重启不该把已登录的浏览器踢出去。
func TestSessionKeyPersists(t *testing.T) {
	dir := t.TempDir()
	a, err := NewAuth(Config{Password: "persist-pass", SessionHours: 1}, dir)
	if err != nil {
		t.Fatal(err)
	}
	val, _, err := a.Login("admin", "persist-pass", "6.6.6.6")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewAuth(Config{Password: "persist-pass", SessionHours: 1}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.ParseSession(val); !ok {
		t.Error("重启后已登录的会话失效了")
	}
	keyPath := filepath.Join(dir, "session.key")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("会话密钥权限 = %o，期望 0600（拿到它就能伪造会话）", info.Mode().Perm())
	}
	raw, _ := os.ReadFile(keyPath)
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		t.Errorf("会话密钥内容不对: %q", raw)
	}

	// 密钥文件被写坏时不能崩，也不能沿用坏值。
	corrupt := filepath.Join(t.TempDir(), "session.key")
	if err := os.WriteFile(corrupt, []byte("not-hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c2, err := NewAuth(Config{Password: "x", SessionHours: 1}, filepath.Dir(corrupt))
	if err != nil {
		t.Fatalf("坏密钥文件不该让启动失败: %v", err)
	}
	if len(c2.secret) != 32 {
		t.Errorf("坏密钥没被重新生成: %d 字节", len(c2.secret))
	}
}

func TestCSRFToken(t *testing.T) {
	a := newAuth(t, Config{Password: "csrf-pass"})
	v1, _, err := a.Login("admin", "csrf-pass", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	v2, _, _ := a.Login("admin", "csrf-pass", "1.1.1.1")
	t1, t2 := a.CSRF(v1), a.CSRF(v2)
	if len(t1) != 64 {
		t.Errorf("token 长度 = %d，期望 64 位 hex", len(t1))
	}
	if _, err := hex.DecodeString(t1); err != nil {
		t.Errorf("token 不是 hex: %v", err)
	}
	if t1 == t2 {
		t.Error("两个不同会话的 token 一样，跨站脚本可以照抄")
	}
	if a.CSRF(v1) != t1 {
		t.Error("同一会话的 token 必须稳定，否则前端每次都要重新取")
	}
	b := newAuth(t, Config{Password: "csrf-pass"})
	if b.CSRF(v1) == t1 {
		t.Error("别的实例（别的密钥）算不出同一个 token")
	}
	// token 要从会话值里推导，不能等于会话值本身。
	if t1 == v1 {
		t.Error("token 和会话值相同")
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	a := newAuth(t, Config{Password: "cookie-pass"})
	w := httptest.NewRecorder()
	a.SetSessionCookie(w, "session-value", time.Now().Add(time.Hour))
	var c *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == CookieName {
			c = ck
		}
	}
	if c == nil {
		t.Fatal("没写会话 cookie")
	}
	if c.Value != "session-value" || c.Path != "/" {
		t.Errorf("cookie = %+v", c)
	}
	if !c.HttpOnly {
		t.Error("必须 HttpOnly：跨站脚本读不到会话值就算不出 CSRF token")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v，期望 Lax（跨站 POST 不带 cookie）", c.SameSite)
	}
	if c.Secure {
		t.Error("默认本地 http 访问，不该标 Secure 否则存不住")
	}

	secure := newAuth(t, Config{Password: "cookie-pass"})
	secure.secure = true
	w2 := httptest.NewRecorder()
	secure.SetSessionCookie(w2, "v", time.Now().Add(time.Hour))
	for _, ck := range w2.Result().Cookies() {
		if ck.Name == CookieName && !ck.Secure {
			t.Error("配了 HTTPS 就该标 Secure")
		}
	}

	w3 := httptest.NewRecorder()
	a.ClearSessionCookie(w3)
	for _, ck := range w3.Result().Cookies() {
		if ck.Name == CookieName {
			if ck.Value != "" || ck.MaxAge >= 0 {
				t.Errorf("清 cookie 没清干净: %+v", ck)
			}
		}
	}
}

func TestRealIP(t *testing.T) {
	mk := func(remote string, headers map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}
	cases := []struct {
		remote  string
		headers map[string]string
		want    string
		why     string
	}{
		{"127.0.0.1:5555", map[string]string{"X-Forwarded-For": "203.0.113.9, 10.0.0.1"}, "203.0.113.9", "本机反代后面要信 XFF 的第一段"},
		{"192.168.1.2:5555", map[string]string{"X-Real-IP": "198.51.100.7"}, "198.51.100.7", "可信来源才信 X-Real-IP"},
		{"203.0.113.50:5555", map[string]string{"X-Forwarded-For": "1.2.3.4"}, "203.0.113.50", "公网直连时 XFF 是客户端自己编的，不能信"},
		{"203.0.113.50:5555", nil, "203.0.113.50", "没有头就用连接地址"},
		{"127.0.0.1:5555", map[string]string{"X-Forwarded-For": "not-an-ip"}, "127.0.0.1", "XFF 不是 IP 就退回连接地址"},
		{"127.0.0.1:5555", map[string]string{"X-Forwarded-For": "  2001:db8::1  , x"}, "2001:db8::1", "IPv6 也要能取出来"},
		{"no-port-remote-addr", nil, "no-port-remote-addr", "畸形地址不该崩"},
	}
	for _, c := range cases {
		if got := realIP(mk(c.remote, c.headers)); got != c.want {
			t.Errorf("%s: realIP(%s, %v) = %q，期望 %q", c.why, c.remote, c.headers, got, c.want)
		}
	}
}

func TestRandomPasswordAlphabet(t *testing.T) {
	// 生成的口令要从日志里能整段双击复制：不含 o0l1I 之类易混字符，
	// 也不含需要转义的符号。
	for round := 0; round < 20; round++ {
		pw, err := randomPassword(16)
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != 16 {
			t.Fatalf("长度 = %d", len(pw))
		}
		for _, r := range pw {
			if strings.ContainsRune("oO0l1I", r) {
				t.Errorf("口令 %q 含易混字符 %c", pw, r)
			}
			if !strings.ContainsRune("abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789", r) {
				t.Errorf("口令 %q 含字母表外的字符 %c", pw, r)
			}
		}
	}
	if a, _ := randomPassword(16); func() bool {
		for i := 0; i < 20; i++ {
			if b, _ := randomPassword(16); a == b {
				return true
			}
		}
		return false
	}() {
		t.Error("随机口令重复了")
	}
}

func TestNonceAndDisabledFlag(t *testing.T) {
	if n := nonceHex(); len(n) != 16 {
		t.Errorf("nonce 长度 = %d", len(n))
	}
	if a, b := nonceHex(), nonceHex(); a == b {
		t.Error("nonce 重复")
	}
	on := newAuth(t, Config{DisableAuth: true})
	if !on.Disabled() {
		t.Error("DisableAuth 没生效")
	}
	off := newAuth(t, Config{})
	if off.Disabled() {
		t.Error("默认该开着登录")
	}
	// 关掉登录时用户名仍然要有（界面右上角要显示当前身份）。
	if on.Username() != "admin" {
		t.Errorf("用户名 = %q", on.Username())
	}
}

// 会话时长没配时要有个合理默认，不能签一个立刻过期的 cookie。
func TestDefaultSessionTTL(t *testing.T) {
	a, err := NewAuth(Config{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if a.ttl != 168*time.Hour {
		t.Errorf("默认会话时长 = %v，期望 7 天", a.ttl)
	}
	bad, err := NewAuth(Config{SessionHours: -5}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if bad.ttl != 168*time.Hour {
		t.Errorf("负数会话时长没被纠正: %v", bad.ttl)
	}
}
