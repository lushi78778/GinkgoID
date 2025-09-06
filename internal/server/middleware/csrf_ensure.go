package middleware

import (
	"net/http"
	"time"

	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/utility/randx"
	"github.com/gin-gonic/gin"
)

// EnsureCSRFCookie 确保浏览器中存在 csrf_token Cookie；若不存在则签发一个随机值。
func EnsureCSRFCookie() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 已存在则无需重复设置
		if v, err := c.Cookie(CSRFCookieName); err == nil && v != "" {
			c.Next()
			return
		}
		_ = RotateCSRFCookie(c, 24*time.Hour)
		c.Next()
	}
}

// RotateCSRFCookie 重新签发 CSRF Cookie（用于登录成功、权限变更等时机）。
// ttl 为 Cookie 存活时间；推荐与会话同生命周期。
func RotateCSRFCookie(c *gin.Context, ttl time.Duration) error {
	tok, err := randx.ID(24)
	if err != nil {
		return err
	}
	cfg := config.C()
	// 设置 SameSite=Lax，避免跨站导航自动携带；非 HttpOnly 便于前端读取
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(CSRFCookieName, tok, int(ttl.Seconds()), "/", cfg.Server.CookieDomain, cfg.Server.SecureCookies, false)
	return nil
}

// ClearCSRFCookie 清除 CSRF Cookie。
func ClearCSRFCookie(c *gin.Context) {
	cfg := config.C()
	c.SetCookie(CSRFCookieName, "", -1, "/", cfg.Server.CookieDomain, cfg.Server.SecureCookies, false)
}
