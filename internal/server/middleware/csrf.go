package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// CSRFCookieName 为 CSRF Token 的 Cookie 名称。
const CSRFCookieName = "csrf_token"

// CSRF 保护非 GET 请求：要求请求头 X-CSRF-Token 与名为 csrf_token 的 Cookie 一致
// （双提交 Cookie 模式）。用于管理 API 的基本 CSRF 防护。
func CSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 对安全方法：若缺失则自动下发 Token（双提交 Cookie 模式）
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
			if token, err := c.Cookie(CSRFCookieName); err != nil || token == "" {
				// 生成并设置 CSRF Cookie：SameSite=Lax，Secure(HTTPS 时)，Path=/，HttpOnly=false
				if t, genErr := generateCSRFToken(); genErr == nil {
					c.SetSameSite(http.SameSiteLaxMode)
					c.SetCookie(CSRFCookieName, t, 0, "/", "", isRequestSecure(c.Request), false)
				} else {
					// 生成失败则直接返回 500，避免下游继续
					c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"code": 500, "message": "csrf_token_generation_failed"})
					return
				}
			}
			c.Next()
			return
		}
		// 从 Cookie 读取 CSRF Token
		cookie, err := c.Cookie(CSRFCookieName)
		if err != nil || cookie == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "missing_csrf_cookie"})
			return
		}
		// 前端需在请求头携带同名 Token
		header := c.GetHeader("X-CSRF-Token")
		if header == "" || !secureEqual(header, cookie) {
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
