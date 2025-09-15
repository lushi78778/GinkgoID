package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"ginkgoid/internal/storage"
	"github.com/gin-gonic/gin"
)

// baseURL 根据请求与反向代理头推导基础地址（issuer 等动态值需要）。
func (h *Handler) baseURL(c *gin.Context) string {
	proto := c.GetHeader("X-Forwarded-Proto")
	host := c.GetHeader("X-Forwarded-Host")
	if proto == "" {
		proto = c.Request.URL.Scheme
	}
	if proto == "" {
		proto = "http"
	}
	if host == "" {
		host = c.Request.Host
	}
	return proto + "://" + host
}

// setNoCache 为敏感响应添加禁止缓存的标准响应头。
func setNoCache(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
}

// splitScope 将 scope 规范为单空格分隔，返回字符串与切片。
func splitScope(scope string) (string, []string) {
	parts := strings.Fields(scope)
	return strings.Join(parts, " "), parts
}

// redirectError 辅助：若可用，带错误码重定向到 redirect_uri。
func (h *Handler) redirectError(c *gin.Context, redirectURI, code, state string) {
	if redirectURI == "" {
		c.JSON(400, gin.H{"error": code})
		return
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	loc := redirectURI + sep + "error=" + urlQueryEscape(code)
	if state != "" {
		loc += "&state=" + urlQueryEscape(state)
	}
	c.Redirect(302, loc)
}

func redirectURIMatches(c *storage.Client, redirectURI string) bool {
	var list []string
	_ = json.Unmarshal([]byte(c.RedirectURIs), &list)
	for _, v := range list {
		if v == redirectURI {
			return true
		}
	}
	return false
}

// readSessionCookie 读取指定名称的会话 Cookie。
func readSessionCookie(c *gin.Context, name string) string {
	if ck, err := c.Request.Cookie(name); err == nil {
		return ck.Value
	}
	return ""
}

// urlQueryEscape 使用 QueryEscape 进行最小化转义。
func urlQueryEscape(s string) string { return url.QueryEscape(s) }

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// --- CSRF helpers (double-submit cookie for demo forms) ---
const csrfCookie = "csrf_token"

func genCSRFToken(n int) string {
	if n <= 0 {
		n = 32
	}
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *Handler) issueCSRF(c *gin.Context) string {
	tok := genCSRFToken(32)
	ck := &http.Cookie{Name: csrfCookie, Value: tok, Path: "/", HttpOnly: false, Secure: h.cfg.Session.CookieSecure}
	// SameSite 与会话保持一致
	switch strings.ToLower(h.cfg.Session.CookieSameSite) {
	case "strict":
		ck.SameSite = http.SameSiteStrictMode
	case "none":
		ck.SameSite = http.SameSiteNoneMode
	default:
		ck.SameSite = http.SameSiteLaxMode
	}
	if h.cfg.Session.CookieDomain != "" {
		ck.Domain = h.cfg.Session.CookieDomain
	}
	http.SetCookie(c.Writer, ck)
	return tok
}

func validateCSRF(c *gin.Context) bool {
	f := c.PostForm("csrf_token")
	ck, _ := c.Request.Cookie(csrfCookie)
	if ck == nil || ck.Value == "" || f == "" {
		return false
	}
	return ck.Value == f
}
