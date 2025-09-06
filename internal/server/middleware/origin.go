package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// CheckOriginRefererStrict 在非 GET 请求时，强制校验 Origin/Referer 是否与允许的来源匹配；
// 若头缺失或不匹配则拒绝请求。建议用于敏感 API（如管理后台）。
func CheckOriginRefererStrict(allowed []string) gin.HandlerFunc {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		if a != "" {
			allowedSet[a] = struct{}{}
		}
	}
	return func(c *gin.Context) {
		// 只拦截可能改变状态的方法
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		// 严格模式：若同时缺失 Origin 与 Referer，则拒绝
		if c.Request.Header.Get("Origin") == "" && c.Request.Header.Get("Referer") == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "origin_referer_forbidden"})
			return
		}
		if matchAllowed(c, allowedSet) {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "origin_referer_forbidden"})
	}
}

// CheckOriginRefererSoft 仅在请求头存在时进行校验，缺失时放行。适合登录/令牌等需要兼容多环境的端点。
func CheckOriginRefererSoft(allowed []string) gin.HandlerFunc {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		if a != "" {
			allowedSet[a] = struct{}{}
		}
	}
	return func(c *gin.Context) {
		// GET/HEAD/OPTIONS 放行
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		// 软模式：如果两者都缺失则放行（兼容非浏览器/某些代理场景）
		if c.Request.Header.Get("Origin") == "" && c.Request.Header.Get("Referer") == "" {
			c.Next()
			return
		}
		if matchAllowed(c, allowedSet) {
			c.Next()
			return
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "origin_referer_forbidden"})
	}
}

// matchAllowed 判断请求的 Origin/Referer 是否与允许列表匹配。
// 优先使用 Origin；缺失时回退使用 Referer 的来源；
// 同源（根据 Host 与协议推断）也视作允许。
func matchAllowed(c *gin.Context, allowed map[string]struct{}) bool {
	// 推断请求的外层协议（反向代理应设置 X-Forwarded-Proto）
	scheme := "http"
	if c.Request.TLS != nil || strings.EqualFold(c.Request.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	reqOrigin := strings.ToLower(scheme + "://" + c.Request.Host)
	// 优先校验 Origin
	if o := c.Request.Header.Get("Origin"); o != "" {
		lo := strings.ToLower(o)
		if lo == reqOrigin {
			return true
		}
		if _, ok := allowed[lo]; ok {
			return true
		}
	}
	// 回退参照 Referer 的来源
	if r := c.Request.Header.Get("Referer"); r != "" {
		if u, err := url.Parse(r); err == nil {
			origin := strings.ToLower(u.Scheme + "://" + u.Host)
			if origin == reqOrigin {
				return true
			}
			if _, ok := allowed[origin]; ok {
				return true
			}
		}
	}
	return false
}
