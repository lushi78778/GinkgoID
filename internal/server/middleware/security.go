package middleware

import (
	"ginkgoid/internal/infra/config"

	"github.com/gin-gonic/gin"
)

// HSTS 根据配置开启 HSTS 响应头（建议仅在 HTTPS 与反代层正确配置时启用）。
func HSTS() gin.HandlerFunc {
	return func(c *gin.Context) {
		if config.C().Security.HSTS {
			c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		c.Next()
	}
}

// RequireTLS 占位：生产环境应保证所有流量均经 TLS（或由反向代理注入 X-Forwarded-Proto=https）。
func RequireTLS() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 本项目不强制中断，以便本地开发；生产应在网关层强制。
		c.Next()
	}
}

// JSONError 返回统一 JSON 错误格式并终止后续处理。
func JSONError(c *gin.Context, code int, msg string) {
	c.AbortWithStatusJSON(code, gin.H{"error": msg})
}
