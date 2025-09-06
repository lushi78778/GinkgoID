package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// CSRFCookieName 为 CSRF Token 的默认 Cookie 名称。
const CSRFCookieName = "csrf_token"

// CSRFConfig 用于配置 CSRF 中间件的策略。
type CSRFConfig struct {
	// CookieName 存储 Token 的 Cookie 名称。
	CookieName string
	// HeaderNames 允许用于传递 Token 的请求头名，按顺序匹配。
	HeaderNames []string
	// FormFieldNames 允许从表单读取的字段名（仅对表单 Content-Type 生效）。
	FormFieldNames []string
	// ExemptPaths 免校验的路径（支持精确匹配或以 * 作为前缀通配，如 /webhook/*）。
	ExemptPaths []string
	// CheckOrigin 是否对非安全方法校验 Origin/Referer 与请求同源。
	CheckOrigin bool
}

// DefaultCSRFConfig 返回默认配置。
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		CookieName:     CSRFCookieName,
		HeaderNames:    []string{"X-CSRF-Token", "X-XSRF-TOKEN"},
		FormFieldNames: []string{"_csrf", "csrf", "csrf_token", "xsrf", "_xsrf"},
		ExemptPaths:    nil,
		CheckOrigin:    false,
	}
}

// CSRF 保护非 GET 请求：要求请求头 X-CSRF-Token 与名为 csrf_token 的 Cookie 一致
// （双提交 Cookie 模式）。用于管理 API 的基本 CSRF 防护。
// CSRF 返回使用默认配置的中间件。
func CSRF() gin.HandlerFunc { return CSRFWithConfig(DefaultCSRFConfig()) }

// CSRFWithConfig 返回使用自定义配置的中间件。
func CSRFWithConfig(cfg CSRFConfig) gin.HandlerFunc {
	// 兜底默认值
	if cfg.CookieName == "" {
		cfg.CookieName = CSRFCookieName
	}
	if len(cfg.HeaderNames) == 0 {
		cfg.HeaderNames = []string{"X-CSRF-Token"}
	}
	if len(cfg.FormFieldNames) == 0 {
		cfg.FormFieldNames = []string{"_csrf", "csrf", "csrf_token", "xsrf", "_xsrf"}
	}
	return func(c *gin.Context) {
		// 路径白名单放行
		if isExemptPath(cfg.ExemptPaths, c.Request.URL.Path) {
			c.Next()
			return
		}

		// 安全方法：若缺失则自动下发 Token（双提交 Cookie 模式）
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
			if token, err := c.Cookie(cfg.CookieName); err != nil || token == "" {
				// 生成并设置 CSRF Cookie：SameSite=Lax，Secure(HTTPS 时)，Path=/，HttpOnly=false
				if t, genErr := generateCSRFToken(); genErr == nil {
					c.SetSameSite(http.SameSiteLaxMode)
					c.SetCookie(cfg.CookieName, t, 0, "/", "", isRequestSecure(c.Request), false)
				} else {
					// 生成失败则直接返回 500，避免下游继续
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "csrf_token_generation_failed"})
					return
				}
			}
			c.Next()
			return
		}

		// 非安全方法：如启用，校验 Origin/Referer 同源
		if cfg.CheckOrigin {
			if !checkSameOrigin(c.Request) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "invalid_origin"})
				return
			}
		}

		// 从 Cookie 读取 CSRF Token
		cookie, err := c.Cookie(cfg.CookieName)
		if err != nil || cookie == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "missing_csrf_cookie"})
			return
		}
		// 从请求中提取 Token（Header 优先，表单兜底）
		token := tokenFromRequest(c, cfg)
		if token == "" || !secureEqual(token, cookie) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "invalid_csrf_token"})
			return
		}
		c.Next()
	}
}

func secureEqual(a, b string) bool {
	// 常量时间比较并确保非空
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// generateCSRFToken 生成高熵随机 Token，使用 URL-safe Base64 编码。
func generateCSRFToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// isRequestSecure 判断请求是否处于 HTTPS（直连或经反向代理）。
func isRequestSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); strings.EqualFold(proto, "https") {
		return true
	}
	if ssl := r.Header.Get("X-Forwarded-Ssl"); strings.EqualFold(ssl, "on") {
		return true
	}
	return false
}

// tokenFromRequest 从请求头或表单字段中提取 CSRF Token。
// 优先从 HeaderNames 读取；若未命中且为表单提交，则尝试从 FormFieldNames 读取。
func tokenFromRequest(c *gin.Context, cfg CSRFConfig) string {
	// Header 优先
	for _, name := range cfg.HeaderNames {
		if v := c.GetHeader(name); v != "" {
			return v
		}
	}
	// 表单字段（仅处理常见表单类型）
	ct := c.GetHeader("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "multipart/form-data") {
		for _, name := range cfg.FormFieldNames {
			if v := c.PostForm(name); v != "" {
				return v
			}
		}
	}
	return ""
}

// isExemptPath 判断当前路径是否在白名单中。
func isExemptPath(patterns []string, path string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, p := range patterns {
		if p == path {
			return true
		}
		if strings.HasSuffix(p, "*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	}
	return false
}

// checkSameOrigin 校验请求的 Origin/Referer 是否与有效请求源一致。
// 要求至少存在 Origin 或 Referer 且与 effective scheme+host 匹配。
func checkSameOrigin(r *http.Request) bool {
	scheme, host := effectiveSchemeAndHost(r)
	// 优先使用 Origin
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Scheme, scheme) && equalHost(u.Host, host)
	}
	// 退回 Referer
	if ref := r.Header.Get("Referer"); ref != "" {
		u, err := url.Parse(ref)
		if err != nil {
			return false
		}
		return strings.EqualFold(u.Scheme, scheme) && equalHost(u.Host, host)
	}
	// 未提供任何头则视为不通过（严格模式）
	return false
}

// effectiveSchemeAndHost 根据反向代理头推导外部可见的 scheme 与 host。
func effectiveSchemeAndHost(r *http.Request) (string, string) {
	scheme := "http"
	if isRequestSecure(r) {
		scheme = "https"
	}
	host := r.Host
	if xfhost := r.Header.Get("X-Forwarded-Host"); xfhost != "" {
		// 只取第一个值
		parts := strings.Split(xfhost, ",")
		host = strings.TrimSpace(parts[0])
	}
	return scheme, host
}

// equalHost 比较主机名（含端口），忽略大小写。
func equalHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}
