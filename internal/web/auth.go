package web

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// 口令哈希用 PBKDF2-HMAC-SHA256，Go 1.24+ 已在标准库里（crypto/pbkdf2），
// 所以不必为 bcrypt 引第三方包。
//
// 迭代数取 31 万：本机实测约 0.2 秒一次，登录是低频操作，
// 这个代价换来的是离线爆破要付 30 万倍的成本。
const (
	pbkdf2Iter   = 310_000
	pbkdf2KeyLen = 32
)

// credentials 是落盘的登录凭据。
type credentials struct {
	Username string    `json:"username"`
	PBKDF2   string    `json:"pbkdf2"` // pbkdf2$sha256$迭代$盐hex$哈希hex
	Updated  time.Time `json:"updated"`
}

// Auth 管口令、会话 cookie 和登录限速。
type Auth struct {
	path string

	mu    sync.Mutex
	creds credentials
	// secret 用来签会话 cookie。落盘是为了重启后已登录的浏览器不被踢出。
	secret []byte

	disabled bool
	secure   bool
	ttl      time.Duration

	// 登录限速：失败计数按来源 IP 存，防着公网上的字典攻击。
	attempts map[string]*attempt
}

type attempt struct {
	fails   int
	blocked time.Time
}

// NewAuth 装配认证。dataDir 下会生成 credentials.json 与 session.key。
func NewAuth(cfg Config, dataDir string) (*Auth, error) {
	a := &Auth{
		path:     filepath.Join(dataDir, "credentials.json"),
		secure:   cfg.CookieSecure,
		ttl:      time.Duration(cfg.SessionHours) * time.Hour,
		disabled: cfg.DisableAuth,
		attempts: map[string]*attempt{},
	}
	if a.ttl <= 0 {
		a.ttl = 168 * time.Hour
	}
	if err := a.loadSecret(dataDir); err != nil {
		return nil, err
	}
	if err := a.loadCreds(cfg); err != nil {
		return nil, err
	}
	return a, nil
}

// Config 是 NewAuth 需要的最小配置切片（避免 web 依赖整个 config 包，
// 也让测试可以直接构造）。
type Config struct {
	Username     string
	Password     string
	PBKDF2       string
	SessionHours int
	CookieSecure bool
	DisableAuth  bool
}

func (a *Auth) loadSecret(dataDir string) error {
	p := filepath.Join(dataDir, "session.key")
	b, err := os.ReadFile(p)
	if err == nil {
		key, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err == nil && len(key) >= 32 {
			a.secret = key
			return nil
		}
	}
	if !os.IsNotExist(err) && err != nil {
		return fmt.Errorf("读取 %s 失败: %w", p, err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("生成会话密钥失败: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	a.secret = key
	return nil
}

func (a *Auth) loadCreds(cfg Config) error {
	// 磁盘上的凭据优先：界面上改过密码之后，重启不该被 config 里的明文覆盖。
	if b, err := os.ReadFile(a.path); err == nil {
		var c credentials
		if err := json.Unmarshal(b, &c); err == nil && strings.HasPrefix(c.PBKDF2, "pbkdf2$") {
			a.creds = c
			if cfg.Username != "" && c.Username != cfg.Username {
				// 用户名改了（配置里换了）就跟着改，口令保持不动。
				a.creds.Username = cfg.Username
				_ = a.save()
			}
			return nil
		}
	}
	user := cfg.Username
	if user == "" {
		user = "admin"
	}
	switch {
	case strings.HasPrefix(cfg.PBKDF2, "pbkdf2$"):
		a.creds = credentials{Username: user, PBKDF2: cfg.PBKDF2, Updated: time.Now().UTC()}
		return a.save()
	case cfg.Password != "":
		hash, err := HashPassword(cfg.Password)
		if err != nil {
			return err
		}
		a.creds = credentials{Username: user, PBKDF2: hash, Updated: time.Now().UTC()}
		return a.save()
	default:
		// 什么都没配：生成一个随机口令，打到日志里。
		// 比默认的 admin/admin 好，也比「空密码直接进」安全。
		pw, err := randomPassword(16)
		if err != nil {
			return err
		}
		hash, err := HashPassword(pw)
		if err != nil {
			return err
		}
		a.creds = credentials{Username: user, PBKDF2: hash, Updated: time.Now().UTC()}
		if err := a.save(); err != nil {
			return err
		}
		// 只有这一条会把明文口令写进日志，且文件权限是 0600。
		fmt.Printf("[web] 未配置登录口令，已生成随机口令：用户名 %s / 口令 %s（改 config 里的 auth.password 或登录后再改）\n", user, pw)
		return nil
	}
}

func (a *Auth) save() error {
	b, err := json.MarshalIndent(a.creds, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o755); err != nil {
		return err
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path)
}

// HashPassword 生成 pbkdf2$sha256$迭代$盐$哈希 格式的口令摘要。
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, pbkdf2KeyLen)
	if err != nil {
		return "", fmt.Errorf("PBKDF2 失败: %w", err)
	}
	return fmt.Sprintf("pbkdf2$sha256$%d$%s$%s", pbkdf2Iter, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

// VerifyPassword 校验口令。解析失败一律返回 false（配置写错时不 panic）。
func VerifyPassword(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "pbkdf2" || parts[1] != "sha256" {
		return false
	}
	var iter int
	if _, err := fmt.Sscanf(parts[2], "%d", &iter); err != nil || iter <= 0 {
		return false
	}
	salt, err := hex.DecodeString(parts[3])
	if err != nil || len(salt) == 0 {
		return false
	}
	want, err := hex.DecodeString(parts[4])
	if err != nil || len(want) == 0 {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(dk, want) == 1
}

// Username 返回当前用户名。
func (a *Auth) Username() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.creds.Username
}

// Disabled 表示是否关掉了登录。
func (a *Auth) Disabled() bool { return a.disabled }

// Login 校验凭据并返回会话 cookie 值。
func (a *Auth) Login(user, pw, ip string) (string, time.Time, error) {
	a.mu.Lock()
	at := a.attempts[ip]
	if at != nil && now().Before(at.blocked) {
		wait := at.blocked.Sub(now()).Round(time.Second)
		a.mu.Unlock()
		return "", time.Time{}, fmt.Errorf("失败次数过多，请 %s 后再试", wait)
	}
	wantUser, wantHash := a.creds.Username, a.creds.PBKDF2
	a.mu.Unlock()

	ok := subtle.ConstantTimeCompare([]byte(strings.TrimSpace(user)), []byte(wantUser)) == 1 &&
		VerifyPassword(pw, wantHash)
	a.mu.Lock()
	if !ok {
		if at == nil {
			at = &attempt{}
			a.attempts[ip] = at
		}
		at.fails++
		if at.fails >= 5 {
			// 指数退避但封顶 30 分钟，免得一次误操作把自己锁一下午。
			backoff := time.Duration(1<<min(at.fails-5, 9)) * time.Minute
			if backoff > 30*time.Minute {
				backoff = 30 * time.Minute
			}
			at.blocked = now().Add(backoff)
		}
		a.mu.Unlock()
		return "", time.Time{}, errors.New("用户名或口令错误")
	}
	delete(a.attempts, ip)
	a.mu.Unlock()

	exp := now().Add(a.ttl)
	val, err := a.sign(sessionPayload{User: strings.TrimSpace(user), Exp: exp.Unix(), Nonce: nonceHex()})
	if err != nil {
		return "", time.Time{}, err
	}
	return val, exp, nil
}

// ChangePassword 改口令（需要旧口令）。
func (a *Auth) ChangePassword(oldPw, newPw string) error {
	if len(strings.TrimSpace(newPw)) < 8 {
		return errors.New("新口令至少 8 位")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !VerifyPassword(oldPw, a.creds.PBKDF2) {
		return errors.New("当前口令不正确")
	}
	h, err := HashPassword(newPw)
	if err != nil {
		return err
	}
	a.creds.PBKDF2 = h
	a.creds.Updated = now().UTC()
	return a.save()
}

// ---------- 会话 cookie ----------

type sessionPayload struct {
	User  string `json:"u"`
	Exp   int64  `json:"e"`
	Nonce string `json:"n"`
}

func (a *Auth) sign(p sessionPayload) (string, error) {
	blob, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding.EncodeToString(blob)
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(enc))
	return enc + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

// ParseSession 校验 cookie 值，返回会话。签名不对、过期都算无效。
func (a *Auth) ParseSession(value string) (sessionPayload, bool) {
	var p sessionPayload
	i := strings.LastIndexByte(value, '.')
	if i <= 0 {
		return p, false
	}
	enc, sig := value[:i], value[i+1:]
	want, err := hex.DecodeString(sig)
	if err != nil {
		return p, false
	}
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(enc))
	if !hmac.Equal(mac.Sum(nil), want) {
		return p, false
	}
	blob, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return p, false
	}
	if err := json.Unmarshal(blob, &p); err != nil {
		return p, false
	}
	if p.User == "" || p.Exp <= 0 || now().Unix() > p.Exp {
		return p, false
	}
	return p, true
}

// CSRF 从会话值导出一个必须由前端显式回传的 token。
//
// 跨站请求能自动带上 cookie（SameSite 之外还有历史浏览器问题），
// 但读不到 cookie 内容也就算不出这个 token；而浏览器要发带自定义头的
// 跨域请求必须过 preflight，我们不给 CORS 头就会被拦。
// 这两条合起来足够挡住 CSRF，不需要额外的 double-submit cookie。
func (a *Auth) CSRF(sessionValue string) string {
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte("csrf|" + sessionValue))
	return hex.EncodeToString(mac.Sum(nil))
}

// CookieName 是会话 cookie 名。
const CookieName = "vpa_session"

// SetSessionCookie 写 cookie。SameSite 用 Lax：本服务没有跨站发起的 GET 需求，
// Lax 既能让正常跳转后的页面可用，又不会把 cookie 附到跨站 POST 上。
func (a *Auth) SetSessionCookie(w http.ResponseWriter, value string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie 清 cookie（把过期时间推到过去）。
func (a *Auth) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   a.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ---------- 杂项 ----------

// realIP 取来源 IP。反代后面优先看 X-Forwarded-For 的第一段
// （那是最初的客户端），但只在确实来自可信网段时才信这个头。
func realIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote := net.ParseIP(host)
	trusted := remote != nil && (remote.IsLoopback() || remote.IsPrivate())
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" && trusted {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			if parsed := net.ParseIP(ip); parsed != nil {
				return parsed.String()
			}
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" && trusted {
		if parsed := net.ParseIP(xri); parsed != nil {
			return parsed.String()
		}
	}
	if remote != nil {
		return remote.String()
	}
	return host
}

func nonceHex() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// randomPassword 生成只含 URL 安全字符的随机口令，避免用户从日志里
// 复制时踩到需要转义的符号。
func randomPassword(n int) (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, n)
	for i := range out {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[idx.Int64()]
	}
	return string(out), nil
}

// now 是可替换的时间源，单测里要能推进它。
var now = time.Now
