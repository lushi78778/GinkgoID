package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	"ginkgoid/internal/infra/errx"
	"ginkgoid/internal/infra/logx"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// 注意：与 CORS 的装配顺序
// - 推荐先挂载 CORS 中间件处理预检与跨域响应头，再挂载 CSRF。
// - 例：
//   r := gin.New()
//   r.Use(cors.Default())          // 来自 github.com/gin-contrib/cors
//   r.Use(middleware.CSRF())       // 或 CSRFWithConfig(...)
// - 理由：预检请求（OPTIONS）与跨域响应头应由 CORS 决定，CSRF 仅拦截业务请求；本中间件已放行 OPTIONS。

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

// CSRF 保护非 GET 请求：要求请求头 X-CSRF-Token（或配置的 Header）与 Cookie 中的 Token 一致
// （双提交 Cookie 模式）。用于管理 API 的基本 CSRF 防护。
// 中间件顺序建议：应在 CORS 中间件之后挂载。
// CSRF 返回使用默认配置的中间件。
func CSRF() gin.HandlerFunc { return CSRFWithConfig(DefaultCSRFConfig()) }

// CSRFWithConfig 返回使用自定义配置的中间件。
// 顺序建议：确保先挂载 CORS，再挂载 CSRF。
// 示例：
//
//	r.Use(cors.Default())
//	r.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{ CheckOrigin: true }))
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
		// 通过上下文标记跳过（需在本中间件之前设置）
		if isCSRFSkipped(c) {
			c.Next()
			return
		}
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
					logx.L().Error("csrf reject: token generation failed",
						logx.String("path", c.Request.URL.Path),
						logx.String("method", c.Request.Method),
						logx.String("client_ip", c.ClientIP()),
						zap.Bool("https", isRequestSecure(c.Request)),
					)
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": int(errx.CSRFTokenGenFailed), "message": errx.Msg(errx.CSRFTokenGenFailed)})
					return
				}
			}
			c.Next()
			return
		}

		// 非安全方法：如启用，校验 Origin/Referer 同源
		if cfg.CheckOrigin {
			if !checkSameOrigin(c.Request) {
				scheme, host := effectiveSchemeAndHost(c.Request)
				logx.L().Warn("csrf reject: invalid origin",
					logx.String("path", c.Request.URL.Path),
					logx.String("method", c.Request.Method),
					logx.String("client_ip", c.ClientIP()),
					logx.String("origin", c.GetHeader("Origin")),
					logx.String("referer", c.GetHeader("Referer")),
					logx.String("expected_scheme", scheme),
					logx.String("expected_host", host),
					logx.String("xf_proto", c.GetHeader("X-Forwarded-Proto")),
					logx.String("xf_host", c.GetHeader("X-Forwarded-Host")),
				)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": int(errx.CSRFOriginInvalid), "message": errx.Msg(errx.CSRFOriginInvalid)})
				return
			}
		}

		// 从 Cookie 读取 CSRF Token
		cookie, err := c.Cookie(cfg.CookieName)
		if err != nil || cookie == "" {
			logx.L().Warn("csrf reject: missing cookie",
				logx.String("path", c.Request.URL.Path),
				logx.String("method", c.Request.Method),
				logx.String("client_ip", c.ClientIP()),
				logx.String("cookie_name", cfg.CookieName),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": int(errx.CSRFTokenMissing), "message": errx.Msg(errx.CSRFTokenMissing)})
			return
		}
		// 从请求中提取 Token（Header 优先，表单兜底）
		token, source := tokenFromRequest(c, cfg)
		if token == "" || !secureEqual(token, cookie) {
			logx.L().Warn("csrf reject: invalid token",
				logx.String("path", c.Request.URL.Path),
				logx.String("method", c.Request.Method),
				logx.String("client_ip", c.ClientIP()),
				logx.String("cookie_name", cfg.CookieName),
				logx.String("token_source", source),
				zap.Bool("has_token", token != ""),
			)
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": int(errx.CSRFTokenInvalid), "message": errx.Msg(errx.CSRFTokenInvalid)})
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

// CSRFSkipKey 为在 gin.Context 中标记跳过 CSRF 的键名。
const CSRFSkipKey = "csrf_skip"

// SkipCSRFMiddleware 返回一个将当前请求标记为跳过 CSRF 校验的中间件。
// 可用于路由分组：group.Use(middleware.SkipCSRFMiddleware())
func SkipCSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(CSRFSkipKey, true)
		c.Next()
	}
}

// SkipCSRF 便捷方法：在当前 Context 上设置跳过标记。
// 注意：只有当调用发生在 CSRF 中间件之前（例如前置中间件）才有效。
func SkipCSRF(c *gin.Context) { c.Set(CSRFSkipKey, true) }

// isCSRFSkipped 判断 Context 是否已标记跳过。
func isCSRFSkipped(c *gin.Context) bool {
	if v, ok := c.Get(CSRFSkipKey); ok {
		if b, _ := v.(bool); b {
			return true
		}
	}
	return false
}

// tokenFromRequest 从请求头或表单字段中提取 CSRF Token。
// 优先从 HeaderNames 读取；若未命中且为表单提交，则尝试从 FormFieldNames 读取。
func tokenFromRequest(c *gin.Context, cfg CSRFConfig) (string, string) {
	// Header 优先
	for _, name := range cfg.HeaderNames {
		if v := c.GetHeader(name); v != "" {
			return v, "header:" + name
		}
	}
	// 表单字段（仅处理常见表单类型）
	ct := c.GetHeader("Content-Type")
	if strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "multipart/form-data") {
		for _, name := range cfg.FormFieldNames {
			if v := c.PostForm(name); v != "" {
				return v, "form:" + name
			}
		}
	}
	return "", ""
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
