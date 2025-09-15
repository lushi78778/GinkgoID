package middlewares

import (
	"fmt"

	"ginkgoid/internal/config"
	"github.com/gin-gonic/gin"
)

// SecurityHeaders 设置通用的安全相关响应头（受配置控制）。
func SecurityHeaders(cfg config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "no-referrer")
		// 若请求经由 HTTPS（直连或反代）并且配置开启 HSTS，则设置 Strict-Transport-Security。
		if (c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https") && cfg.Security.HSTS.Enabled {
			v := fmt.Sprintf("max-age=%d", cfg.Security.HSTS.MaxAgeSeconds)
			if cfg.Security.HSTS.IncludeSubdomains {
				v += "; includeSubDomains"
			}
			c.Header("Strict-Transport-Security", v)
		}
		c.Next()
	}
}
