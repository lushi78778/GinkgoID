// Package admin 实现管理后台页面渲染与静态资源分发。
//
// 页面说明：
// - /admin/            首页（Iframe 跳转子页）
// - /admin/ui/*.html   子页（Clients/Users/Consents/JWKS）
// - /assets/...        本地内嵌的 JS/CSS/Font 资源（在路由层注册）
package admin

import (
	"context"
	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/service/session"
	res "ginkgoid/resource"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

// IndexPage 管理后台首页，渲染顶栏与左侧菜单，并通过 Iframe 加载具体子页。
func IndexPage(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"privacy_url": config.C().Admin.PrivacyURL,
		"terms_url":   config.C().Admin.TermsURL,
	})
}

// 各子页入口，统一 302 到内嵌静态页面。
func ClientsPage(c *gin.Context)  { c.Redirect(http.StatusFound, "/admin/ui/clients.html") }
func UsersPage(c *gin.Context)    { c.Redirect(http.StatusFound, "/admin/ui/users.html") }
func ConsentsPage(c *gin.Context) { c.Redirect(http.StatusFound, "/admin/ui/consents.html") }
func JWKSPage(c *gin.Context)     { c.Redirect(http.StatusFound, "/admin/ui/jwks.html") }

// UIHandler 返回内嵌的后台 HTML 页面。
// 为避免路径穿越，拒绝包含 ".." 的路径。
func UIHandler(c *gin.Context) {
	path := c.Param("filepath")
	if path == "" || path == "/" {
		path = "/index.html"
	}
	if strings.Contains(path, "..") {
		c.String(http.StatusBadRequest, "invalid path")
		return
	}
	full := "templates/admin" + path
	b, err := res.AdminFS.ReadFile(full)
	if err != nil {
		c.String(http.StatusNotFound, "not found")
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", b)
}

// AssetsJSHandler 返回内嵌的 JS 资源。
func AssetsJSHandler(c *gin.Context) {
	path := c.Param("filepath")
	if path == "" || path == "/" {
		c.Status(http.StatusNotFound)
		return
	}
	if strings.Contains(path, "..") {
		c.String(http.StatusBadRequest, "invalid path")
		return
	}
	full := "static/admin/js" + path
	b, err := res.AdminFS.ReadFile(full)
	if err != nil {
		c.String(http.StatusNotFound, "not found")
		return
	}
	c.Data(http.StatusOK, "application/javascript; charset=utf-8", b)
}

// AssetsCSSHandler 返回内嵌的 CSS 资源。
func AssetsCSSHandler(c *gin.Context) {
	path := c.Param("filepath")
	if path == "" || path == "/" {
		c.Status(http.StatusNotFound)
		return
	}
	if strings.Contains(path, "..") {
		c.String(http.StatusBadRequest, "invalid path")
		return
	}
	full := "static/admin/css" + path
	b, err := res.AdminFS.ReadFile(full)
	if err != nil {
		c.String(http.StatusNotFound, "not found")
		return
	}
	c.Data(http.StatusOK, "text/css; charset=utf-8", b)
}

// Logout 注销管理员会话并跳转回登录页。
func Logout(c *gin.Context) {
	if sid, err := c.Cookie(session.CookieName); err == nil && sid != "" {
		_ = session.Revoke(context.Background(), sid)
		session.ClearCookie(c)
	}
	c.Redirect(http.StatusFound, "/login")
}

// AssetsFontHandler 返回内嵌的字体资源，并按扩展名设置正确的 Content-Type。
func AssetsFontHandler(c *gin.Context) {
	path := c.Param("filepath")
	if path == "" || path == "/" {
		c.Status(http.StatusNotFound)
		return
	}
	if strings.Contains(path, "..") {
		c.String(http.StatusBadRequest, "invalid path")
		return
	}
	full := "static/admin/font" + path
	b, err := res.AdminFS.ReadFile(full)
	if err != nil {
		c.String(http.StatusNotFound, "not found")
		return
	}
	// naive content type by extension
	ct := "application/octet-stream"
	if strings.HasSuffix(strings.ToLower(path), ".woff2") {
		ct = "font/woff2"
	}
	if strings.HasSuffix(strings.ToLower(path), ".woff") {
		ct = "font/woff"
	}
	if strings.HasSuffix(strings.ToLower(path), ".ttf") {
		ct = "font/ttf"
	}
	if strings.HasSuffix(strings.ToLower(path), ".otf") {
		ct = "font/otf"
	}
	if strings.HasSuffix(strings.ToLower(path), ".eot") {
		ct = "application/vnd.ms-fontobject"
	}
	c.Data(http.StatusOK, ct, b)
}
