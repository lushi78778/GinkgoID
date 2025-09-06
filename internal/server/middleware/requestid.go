package middleware

import (
	"strings"

	"ginkgoid/internal/utility/randx"
	"github.com/gin-gonic/gin"
)

// reqIDKey 是在 gin.Context 中保存请求 ID 的键。
const reqIDKey = "request_id"

// RequestID 中间件：为每个请求注入一个短请求 ID，并通过响应头传递。
// - Header: X-Request-ID
// - Context: key "request_id"
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader("X-Request-ID")
		rid = strings.TrimSpace(rid)
		if rid == "" {
			// 生成 12 字节随机 ID（Base64URL ≈ 16 chars）
			if v, err := randx.ID(12); err == nil {
				rid = v
			} else {
				rid = "unknown"
			}
		}
		c.Set(reqIDKey, rid)
		c.Header("X-Request-ID", rid)
		c.Next()
	}
}

// GetRequestID 从 gin.Context 读取请求 ID，不存在则返回空串。
func GetRequestID(c *gin.Context) string {
	if v, ok := c.Get(reqIDKey); ok {
		if s, _ := v.(string); s != "" {
			return s
		}
	}
	return ""
}
