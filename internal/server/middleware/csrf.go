package middleware

import (
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
		// 仅对可能改变状态的方法执行校验；GET/HEAD/OPTIONS 放行
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
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
	// 常量时间比较，避免时序侧信道；长度不一致直接失败
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	// 附加检查：非空（防止空值通过）
	return v == 0 && !strings.EqualFold(a, "")
}
