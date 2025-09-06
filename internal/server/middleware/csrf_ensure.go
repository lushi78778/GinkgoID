package middleware

import (
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
		tok, err := randx.ID(24)
		if err == nil {
			cfg := config.C()
			// 不是 HttpOnly，便于前端 JS 读取并写入 X-CSRF-Token 头
			c.SetCookie(CSRFCookieName, tok, int((24 * time.Hour).Seconds()), "/", cfg.Server.CookieDomain, cfg.Server.SecureCookies, false)
		}
		c.Next()
	}
}
