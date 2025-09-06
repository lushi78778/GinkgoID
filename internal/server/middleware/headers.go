package middleware

import "github.com/gin-gonic/gin"

// SecurityHeaders 为所有响应设置通用安全相关的响应头：
// - X-Content-Type-Options: nosniff
// - X-Frame-Options: DENY
// - Referrer-Policy: strict-origin-when-cross-origin
// - Content-Security-Policy: 仅允许同源脚本/样式/字体等（保留 'unsafe-eval' 兼容 Layui 模板）
func SecurityHeaders() gin.HandlerFunc {
	// 说明：Layui 的 laytpl 使用 Function 构造（等价于 eval），因此需允许 'unsafe-eval'。
	const csp = "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'self'"
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Content-Security-Policy", csp)
		c.Next()
	}
}
