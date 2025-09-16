package handlers

import (
	"net/http"
	"net/url"

	"strings"

	"ginkgoid/internal/services"

	"github.com/gin-gonic/gin"
)

// @Summary      会话探测 Iframe（简化）
// @Description  用于 RP 轮询检查 OP 登录状态的 iframe
// @Tags         session-management
// @Produce      html
// @Success      200 {string} string "HTML"
// @Router       /check_session [get]
func (h *Handler) checkSessionIframe(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	cookieName := h.cfg.Session.CookieName
	html := `<!DOCTYPE html><html><head><meta charset="utf-8"><title>check_session</title></head><body><script>
    (function(){
      function hasSession(){ return document.cookie.indexOf('` + cookieName + `=') >= 0; }
      window.addEventListener('message', function(e){
        try {
          var state = hasSession() ? 'unchanged' : 'changed';
          e.source && e.source.postMessage(state, e.origin);
        } catch(err){}
      }, false);
    })();
    </script></body></html>`
	c.String(200, html)
}

// @Summary      登录页
// @Description  显示用户名密码登录表单
// @Tags         ui
// @Produce      html
// @Success      200 {string} string "HTML"
// @Router       /login [get]
func (h *Handler) loginPage(c *gin.Context) {
	csrf := h.issueCSRF(c)
	c.HTML(http.StatusOK, "login.html", gin.H{"params": c.Request.URL.Query(), "csrf": csrf})
}

// @Summary      提交登录
// @Description  处理用户名密码登录请求
// @Tags         ui
// @Accept       x-www-form-urlencoded
// @Produce      html
// @Param        username  formData string true  "用户名"
// @Param        password  formData string true  "密码"
// @Success      302 {string} string "重定向至 /authorize"
// @Failure      401 {string} string "HTML 登录页（含错误）"
// @Router       /login [post]
func (h *Handler) loginSubmit(c *gin.Context) {
	if !validateCSRF(c) {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "CSRF 校验失败", "params": c.Request.PostForm, "csrf": h.issueCSRF(c)})
		return
	}
	username := c.PostForm("username")
	password := c.PostForm("password")
	if err := c.Request.ParseForm(); err != nil {
		c.String(400, "bad_request")
		return
	}
	orig := url.Values{}
	for k, v := range c.Request.PostForm {
		if k == "username" || k == "password" || k == "csrf_token" {
			continue
		}
		for _, iv := range v {
			orig.Add(k, iv)
		}
	}
	u, err := h.userSvc.FindByUsername(c, username)
	if err != nil || !h.userSvc.CheckPassword(u, password) {
		ip := c.ClientIP()
		rid := c.GetString("request_id")
		ua := c.Request.UserAgent()
		h.logSvc.Write(c, "WARN", "USER_LOGIN_FAILED", nil, nil, "bad credentials", ip, services.LogWriteOpts{
			RequestID: rid,
			SessionID: readSessionCookie(c, h.cfg.Session.CookieName),
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			Status:    http.StatusUnauthorized,
			UserAgent: ua,
			Outcome:   "failure",
			ErrorCode: "bad_credentials",
			Extra:     map[string]any{"username": username},
		})
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "用户名或密码错误", "params": c.Request.PostForm, "csrf": h.issueCSRF(c)})
		return
	}
	sess, err := h.sessionSvc.New(c, u.ID, "urn:op:auth:pwd", []string{"pwd"})
	if err != nil {
		c.String(500, "session error")
		return
	}
	cookie := &http.Cookie{Name: h.cfg.Session.CookieName, Value: sess.SID, Path: "/", HttpOnly: true, Secure: h.cfg.Session.CookieSecure}
	switch strings.ToLower(h.cfg.Session.CookieSameSite) {
	case "strict":
		cookie.SameSite = http.SameSiteStrictMode
	case "none":
		cookie.SameSite = http.SameSiteNoneMode
	default:
		cookie.SameSite = http.SameSiteLaxMode
	}
	if h.cfg.Session.CookieDomain != "" {
		cookie.Domain = h.cfg.Session.CookieDomain
	}
	http.SetCookie(c.Writer, cookie)
	ip := c.ClientIP()
	rid := c.GetString("request_id")
	ua := c.Request.UserAgent()
	h.logSvc.Write(c, "INFO", "USER_LOGIN", h.userSvc.IDPtr(u.ID), nil, "login success", ip, services.LogWriteOpts{
		RequestID: rid,
		SessionID: sess.SID,
		Method:    c.Request.Method,
		Path:      c.Request.URL.Path,
		Status:    http.StatusFound,
		UserAgent: ua,
		Outcome:   "success",
		Extra:     map[string]any{"username": u.Username},
	})
	hasClient := orig.Get("client_id") != "" && orig.Get("redirect_uri") != ""
	if hasClient {
		c.Redirect(http.StatusFound, "/authorize?"+orig.Encode())
		return
	}
	next := orig.Get("next")
	if next != "" && !strings.Contains(next, "://") && strings.HasPrefix(next, "/") {
		c.Redirect(http.StatusFound, next)
		return
	}
	if h.isAdmin(u) {
		c.Redirect(http.StatusFound, "/app/admin/users")
	} else {
		c.Redirect(http.StatusFound, "/app/profile")
	}
}

// @Summary      授权同意页
// @Description  显示授权范围供用户确认
// @Tags         ui
// @Produce      html
// @Param        client_id  query string true  "客户端 ID"
// @Param        scope      query string true  "请求的 scope（空格分隔）"
// @Success      200 {string} string "HTML"
// @Router       /consent [get]
func (h *Handler) consentPage(c *gin.Context) {
	clientID := c.Query("client_id")
	scope := c.Query("scope")
	cl, err := h.clientSvc.FindByID(c, clientID)
	if err != nil {
		c.String(400, "invalid client")
		return
	}
	_, scopes := splitScope(scope)
	csrf := h.issueCSRF(c)
	c.HTML(http.StatusOK, "consent.html", gin.H{"client_name": cl.Name, "scopes": scopes, "params": c.Request.URL.Query(), "csrf": csrf})
}

// @Summary      提交授权同意
// @Description  处理用户对授权的同意或拒绝
// @Tags         ui
// @Accept       x-www-form-urlencoded
// @Produce      html
// @Param        decision   formData string true  "approve 或 deny"
// @Success      302 {string} string "重定向至 /authorize"
// @Router       /consent [post]
func (h *Handler) consentSubmit(c *gin.Context) {
	if !validateCSRF(c) {
		c.JSON(401, gin.H{"error": "csrf_failed"})
		return
	}
	decision := c.PostForm("decision")
	if decision != "approve" {
		c.JSON(400, gin.H{"error": "access_denied"})
		return
	}
	if err := c.Request.ParseForm(); err != nil {
		c.String(400, "bad_request")
		return
	}
	qv := url.Values{}
	for k, v := range c.Request.PostForm {
		if k == "decision" || k == "csrf_token" {
			continue
		}
		for _, iv := range v {
			qv.Add(k, iv)
		}
	}
	sid := readSessionCookie(c, h.cfg.Session.CookieName)
	if sid != "" {
		if sess, err := h.sessionSvc.Get(c, sid); err == nil {
			clientID := qv.Get("client_id")
			scope := qv.Get("scope")
			_ = h.consentSvc.Save(c, sess.UserID, clientID, scope)
		}
	}
	qv.Set("consent", "approve")
	c.Redirect(http.StatusFound, "/authorize?"+qv.Encode())
}

// 开发辅助（仅非 prod）
// @Summary      开发辅助 - 创建用户
// @Description  （仅限非生产环境）快速创建用户
// @Tags         dev
// @Accept       json
// @Produce      json
// @Param        body body object true "{username,password}"
// @Success      201 {object} map[string]interface{}
// @Failure      400 {object} map[string]string
// @Router       /dev/users [post]
func (h *Handler) devCreateUser(c *gin.Context) {
	type req struct{ Username, Password, Email, Name string }
	var r req
	if err := c.ShouldBindJSON(&r); err != nil {
		c.JSON(400, gin.H{"error": "bad_json"})
		return
	}
	u, err := h.userSvc.Create(c, r.Username, r.Password, r.Email, r.Name)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, gin.H{"id": u.ID, "username": u.Username})
}

// @Summary      开发辅助 - 用户列表
// @Description  （仅限非生产环境）列出所有用户
// @Tags         dev
// @Produce      json
// @Success      200 {array} storage.User
// @Router       /dev/users [get]
func (h *Handler) devListUsers(c *gin.Context) {
	users, err := h.userSvc.List(c, 100)
	if err != nil {
		c.JSON(500, gin.H{"error": "db"})
		return
	}
	out := make([]gin.H, 0, len(users))
	for _, u := range users {
		out = append(out, gin.H{"id": u.ID, "username": u.Username, "email": u.Email, "name": u.Name})
	}
	c.JSON(200, out)
}

// @Summary      开发辅助 - 轮换密钥
// @Description  （仅限非生产环境）触发一次新的 JWK 生成
// @Tags         dev
// @Produce      json
// @Success      200 {object} map[string]string
// @Failure      500 {object} map[string]string
// @Router       /dev/keys/rotate [post]
func (h *Handler) devRotateKeys(c *gin.Context) {
	if err := h.keySvc.Rotate(c); err != nil {
		c.JSON(500, gin.H{"error": "rotate_failed"})
		return
	}
	c.Status(204)
}
