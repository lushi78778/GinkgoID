package middleware

import (
	"context"
	"net/http"

	"ginkgoid/internal/service/session"
	"ginkgoid/internal/service/user"
	"github.com/gin-gonic/gin"
)

// AdminRequired 校验请求来自有效管理员会话（角色为 admin）。不满足时返回 401/403。
func AdminRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 读取会话 Cookie
		sid, err := c.Cookie(session.CookieName)
		if err != nil || sid == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "unauthorized"})
			return
		}
		// 校验会话是否有效（未撤销且未过期）
		ss, err := session.Get(context.Background(), sid)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"code": 401, "message": "unauthorized"})
			return
		}
		// 必须为管理员角色
		u, err := user.GetByID(context.Background(), ss.UserID)
		if err != nil || u.Role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "forbidden"})
			return
		}
		c.Next()
	}
}

// AdminPageRequired 类似 AdminRequired，但在未登录时重定向到 /login，适用于页面路由。
func AdminPageRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 页面场景：未登录跳转到 /login
		sid, err := c.Cookie(session.CookieName)
		if err != nil || sid == "" {
			c.Redirect(http.StatusFound, "/login?continue="+c.Request.URL.RequestURI())
			c.Abort()
			return
		}
		ss, err := session.Get(context.Background(), sid)
		if err != nil {
			c.Redirect(http.StatusFound, "/login?continue="+c.Request.URL.RequestURI())
			c.Abort()
			return
		}
		u, err := user.GetByID(context.Background(), ss.UserID)
		if err != nil || u.Role != "admin" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}
