package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"ginkgoid/internal/services"
	"ginkgoid/internal/storage"
)

// @Summary      管理员 - 待审批客户端列表
// @Tags         admin-api
// @Produce      json
// @Success      200 {array} map[string]interface{}
// @Failure      500 {object} map[string]string
// @Router       /api/admin/clients/pending [get]
func (h *Handler) apiAdminListPendingClients(c *gin.Context) {
	list, err := h.clientSvc.ListPending(c, 200)
	if err != nil {
		c.JSON(500, gin.H{"error": "db"})
		return
	}
	out := make([]gin.H, 0, len(list))
	for _, cl := range list {
		out = append(out, gin.H{
			"client_id":     cl.ClientID,
			"client_name":   cl.Name,
			"owner_user_id": cl.OwnerUserID,
			"created_at":    cl.CreatedAt.Unix(),
		})
	}
	c.JSON(200, out)
}

// @Summary      管理员 - 审批通过客户端
// @Tags         admin-api
// @Produce      json
// @Param        client_id path string true "客户端ID"
// @Success      204 {string} string "No Content"
// @Failure      400 {object} map[string]string
// @Failure      404 {object} map[string]string
// @Router       /api/admin/clients/{client_id}/approve [post]
func (h *Handler) apiAdminApproveClient(c *gin.Context) {
	clientID := c.Param("client_id")
	if clientID == "" {
		c.JSON(400, gin.H{"error": "bad_client"})
		return
	}
	uidp, err := h.currentUser(c)
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	if err := h.clientSvc.ApproveClient(c, clientID, *uidp); err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	// 审计日志
	ip := c.ClientIP()
	_ = h.logSvc.Write(c, "INFO", "ADMIN_CLIENT_APPROVED", uidp, &clientID, "client approved", ip)
	c.Status(204)
}

// @Summary      管理员 - 审批拒绝客户端
// @Tags         admin-api
// @Produce      json
// @Param        client_id path string true "客户端ID"
// @Param        body body object true "{reason}"
// @Success      204 {string} string "No Content"
// @Failure      400 {object} map[string]string
// @Failure      404 {object} map[string]string
// @Router       /api/admin/clients/{client_id}/reject [post]
func (h *Handler) apiAdminRejectClient(c *gin.Context) {
	clientID := c.Param("client_id")
	if clientID == "" {
		c.JSON(400, gin.H{"error": "bad_client"})
		return
	}
	var req struct{ Reason string }
	if err := c.ShouldBindJSON(&req); err != nil || req.Reason == "" {
		c.JSON(400, gin.H{"error": "reason_required"})
		return
	}
	uidp, err := h.currentUser(c)
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	if err := h.clientSvc.RejectClient(c, clientID, *uidp, req.Reason); err != nil {
		c.JSON(404, gin.H{"error": err.Error()})
		return
	}
	// 审计日志
	ip := c.ClientIP()
	_ = h.logSvc.Write(c, "INFO", "ADMIN_CLIENT_REJECTED", uidp, &clientID, "client rejected", ip)
	c.Status(204)
}

// registerAPIRoutes adds JSON APIs for user self-service and admin user management.
func (h *Handler) registerAPIRoutes(r *gin.Engine) {
	api := r.Group("/api")
	// 客户端审批流相关API（管理员）
	api.GET("/admin/clients/pending", h.adminOnly(h.apiAdminListPendingClients))
	api.POST("/admin/clients/:client_id/approve", h.adminOnly(h.apiAdminApproveClient))
	api.POST("/admin/clients/:client_id/reject", h.adminOnly(h.apiAdminRejectClient))
	api.GET("/me", h.apiMe)
	api.PUT("/me", h.apiUpdateMe)
	api.POST("/me/password", h.apiChangePassword)
	api.POST("/me/email/verify", h.apiMeVerifyEmail)
	api.PUT("/me/preferences", h.apiMeUpdatePreferences)
	api.GET("/self/logs", h.apiSelfLogs)

	security := api.Group("/security")
	security.GET("/mfa", h.apiSecurityGetMFA)
	security.POST("/mfa/setup", h.apiSecuritySetupMFA)
	security.POST("/mfa/activate", h.apiSecurityActivateMFA)
	security.DELETE("/mfa", h.apiSecurityDisableMFA)
	security.GET("/sessions", h.apiSecurityListSessions)
	security.DELETE("/sessions", h.apiSecurityDeleteSessions)
	security.DELETE("/sessions/:id", h.apiSecurityDeleteSession)

	privacy := api.Group("/privacy")
	privacy.POST("/export", h.apiPrivacyExport)
	privacy.POST("/delete", h.apiPrivacyDelete)
	api.GET("/privacy/export/:token", h.apiPrivacyDownload)
	// 我的应用（客户端）
	api.GET("/my/clients", h.apiMyClients)
	api.PUT("/my/clients/:client_id/disable", h.apiMyDisableClient)
	api.PUT("/my/clients/:client_id/enable", h.apiMyEnableClient)
	api.DELETE("/my/clients/:client_id", h.apiMyDeleteClient)
	api.GET("/my/clients/:client_id/logs", h.devOnly(h.apiMyClientLogs))
	api.GET("/my/clients/:client_id/users", h.devOnly(h.apiMyClientUsers))
	api.DELETE("/my/clients/:client_id/users/:user_id", h.devOnly(h.apiMyClientUserDelete))
	api.GET("/my/clients/:client_id/analytics", h.devOnly(h.apiMyClientAnalytics))
	// 授权应用（同意）
	api.GET("/consents", h.apiListConsents)
	api.DELETE("/consents/:client_id", h.apiRevokeConsent)
	// Admin endpoints
	api.GET("/users", h.adminOnly(h.apiAdminListUsers))
	api.POST("/users", h.adminOnly(h.apiAdminCreateUser))
	api.PUT("/users/:id", h.adminOnly(h.apiAdminUpdateUser))
	api.GET("/logs", h.adminOnly(h.apiAdminListLogs))
	api.GET("/admin/metrics", h.adminOnly(h.apiAdminMetrics))
	api.GET("/admin/settings", h.adminOnly(h.apiAdminSettings))
	api.PUT("/admin/scopes", h.adminOnly(h.apiAdminUpdateScopes))
	api.PUT("/admin/roles", h.adminOnly(h.apiAdminUpdateRoles))
	api.PUT("/admin/policies", h.adminOnly(h.apiAdminUpdatePolicies))
	api.GET("/admin/branding", h.adminOnly(h.apiAdminBranding))
	api.PUT("/admin/branding", h.adminOnly(h.apiAdminUpdateBranding))
}

func (h *Handler) currentUser(c *gin.Context) (*uint64, error) {
	sid := readSessionCookie(c, h.cfg.Session.CookieName)
	if sid == "" {
		return nil, gin.Error{Err: http.ErrNoCookie}
	}
	sess, err := h.sessionSvc.Get(c, sid)
	if err != nil {
		return nil, err
	}
	return &sess.UserID, nil
}

// @Summary      当前用户信息
// @Description  读取当前登录用户的基础资料
// @Tags         user-api
// @Produce      json
// @Success      200 {object} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Router       /api/me [get]
func (h *Handler) apiMe(c *gin.Context) {
	uidp, err := h.currentUser(c)
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	u, err := h.userSvc.FindByID(c, *uidp)
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	msg := ""
	if !u.EmailVerified {
		msg = "邮箱尚未验证。如需启用邮件验证，请联系管理员配置邮件服务"
	}
	if u.PendingEmail != "" {
		msg = "新邮箱待验证，请查收验证邮件"
	}
	resp := gin.H{
		"id":                   u.ID,
		"username":             u.Username,
		"email":                u.Email,
		"name":                 u.Name,
		"is_admin":             h.isAdmin(u),
		"is_dev":               u.IsDev,
		"marketing_opt_in":     u.MarketingOptIn,
		"email_verified":       u.EmailVerified,
		"pending_email":        u.PendingEmail,
		"mfa_enabled":          u.MFAEnabled,
		"email_status_message": msg,
	}
	if u.MFAEnrolledAt != nil {
		resp["mfa_enrolled_at"] = u.MFAEnrolledAt.Unix()
	}
	if u.MFALastUsedAt != nil {
		resp["mfa_last_used_at"] = u.MFALastUsedAt.Unix()
	}
	c.JSON(200, resp)
}

// @Summary      更新我的资料
// @Description  更新当前登录用户的姓名/邮箱
// @Tags         user-api
// @Accept       json
// @Produce      json
// @Param        body body object true "{name,email}"
// @Success      200 {object} map[string]interface{}
// @Failure      400 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Router       /api/me [put]
func (h *Handler) apiUpdateMe(c *gin.Context) {
	uidp, err := h.currentUser(c)
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	var req struct{ Name, Email string }
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "bad_json"})
		return
	}
	u, err := h.userSvc.FindByID(c, *uidp)
	if err != nil {
		c.JSON(404, gin.H{"error": "not_found"})
		return
	}
	originalEmail := strings.TrimSpace(u.Email)
	name := strings.TrimSpace(req.Name)
	email := strings.TrimSpace(req.Email)
	if name != "" {
		u.Name = name
	}
	if email != "" && email != originalEmail {
		u.Email = email
		u.EmailVerified = false
		u.PendingEmail = ""
	}
	if err := h.userSvc.Save(c, u); err != nil {
		c.JSON(500, gin.H{"error": "db"})
		return
	}
	c.JSON(200, gin.H{"id": u.ID, "username": u.Username, "email": u.Email, "name": u.Name, "email_verified": u.EmailVerified})
}

// @Summary      修改我的口令
// @Description  需要提供旧口令与新口令
// @Tags         user-api
// @Accept       json
// @Produce      json
// @Param        body body object true "{oldPassword,newPassword}"
// @Success      204 {string} string "No Content"
// @Failure      400 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Router       /api/me/password [post]
func (h *Handler) apiChangePassword(c *gin.Context) {
	uidp, err := h.currentUser(c)
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	var req struct{ OldPassword, NewPassword string }
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "bad_json"})
		return
	}
	if err := h.userSvc.ChangePassword(c, *uidp, req.OldPassword, req.NewPassword); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	c.Status(204)
}

// 启用我拥有的客户端（Approved=true）
// @Summary      启用我的客户端
// @Description  将指定客户端置为启用状态（enabled=true）
// @Tags         client-api
// @Produce      json
// @Param        client_id path string true "客户端 ID"
// @Success      204 {string} string "No Content"
// @Failure      401 {object} map[string]string
// @Failure      403 {object} map[string]string
// @Router       /api/my/clients/{client_id}/enable [put]
func (h *Handler) apiMyEnableClient(c *gin.Context) {
	uidp, err := h.currentUser(c)
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	cid := c.Param("client_id")
	if cid == "" {
		c.JSON(400, gin.H{"error": "bad_client"})
		return
	}
	cl, err := h.clientSvc.FindAnyByID(c, cid)
	if err != nil {
		c.JSON(404, gin.H{"error": "not_found"})
		return
	}
	me, _ := h.userSvc.FindByID(c, *uidp)
	if cl.OwnerUserID != *uidp && !h.isAdmin(me) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	cl.Enabled = true
	if err := h.clientSvc.Save(c, cl); err != nil {
		c.JSON(500, gin.H{"error": "db"})
		return
	}
	c.Status(204)
}

func (h *Handler) adminOnly(fn gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		uidp, err := h.currentUser(c)
		if err != nil {
			c.JSON(401, gin.H{"error": "unauthorized"})
			return
		}
		u, err := h.userSvc.FindByID(c, *uidp)
		if err != nil {
			c.JSON(401, gin.H{"error": "unauthorized"})
			return
		}
		if !h.isAdmin(u) {
			c.JSON(403, gin.H{"error": "forbidden"})
			return
		}
		fn(c)
	}
}

func (h *Handler) devOnly(fn gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		uidp, err := h.currentUser(c)
		if err != nil {
			c.JSON(401, gin.H{"error": "unauthorized"})
			return
		}
		u, err := h.userSvc.FindByID(c, *uidp)
		if err != nil {
			c.JSON(401, gin.H{"error": "unauthorized"})
			return
		}
		if !h.isDev(u) {
			c.JSON(403, gin.H{"error": "forbidden"})
			return
		}
		fn(c)
	}
}

func (h *Handler) isAdmin(u *storage.User) bool {
	if u == nil {
		return false
	}
	if u.IsAdmin {
		return true
	}
	if u.ID == 1 {
		return true
	} // 简单兜底：第一个用户视为管理员
	if u.Username == "admin" {
		return true
	}
	return false
}

func (h *Handler) isDev(u *storage.User) bool {
	if u == nil {
		return false
	}
	if u.IsDev {
		return true
	}
	return h.isAdmin(u)
}

// @Summary      管理员 - 审计日志查询
// @Tags         admin-api
// @Produce      json
// @Param        from  query string false "开始时间(Unix秒)"
// @Param        to    query string false "结束时间(Unix秒)"
// @Param        level query string false "级别"
// @Param        event query string false "事件"
// @Param        user  query uint64 false "用户ID"
// @Param        client query string false "客户端ID"
// @Param        limit query int false "数量(<=1000)"
// @Success      200 {array} map[string]interface{}
// @Router       /api/logs [get]
func (h *Handler) apiAdminListLogs(c *gin.Context) {
	var (
		fromPtr *time.Time
		toPtr   *time.Time
	)
	if v := c.Query("from"); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			t := time.Unix(sec, 0)
			fromPtr = &t
		}
	}
	if v := c.Query("to"); v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			t := time.Unix(sec, 0)
			toPtr = &t
		}
	}
	level := c.Query("level")
	event := c.Query("event")
	var userPtr *uint64
	if v := c.Query("user"); v != "" {
		if u, err := strconv.ParseUint(v, 10, 64); err == nil {
			userPtr = &u
		}
	}
	var clientPtr *string
	if v := c.Query("client"); v != "" {
		clientPtr = &v
	}
	limit := 200
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	// 新增筛选
	rid := c.Query("request_id")
	outcome := c.Query("outcome")
	errorCode := c.Query("error_code")
	method := c.Query("method")
	path := c.Query("path")
	ua := c.Query("ua")
	var statusPtr *int
	if v := c.Query("status"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			statusPtr = &n
		}
	}
	list, err := h.logSvc.Query2(c, services.LogQuery{
		From: fromPtr, To: toPtr,
		Level: level, Event: event,
		UserID: userPtr, ClientID: clientPtr,
		Limit:     limit,
		RequestID: rid, Outcome: outcome, ErrorCode: errorCode,
		Method: method, Path: path, UserAgent: ua, Status: statusPtr,
	})
	if err != nil {
		c.JSON(500, gin.H{"error": "db"})
		return
	}
	out := make([]gin.H, 0, len(list))
	for _, it := range list {
		out = append(out, gin.H{
			"ts":         it.Timestamp.Unix(),
			"level":      it.Level,
			"event":      it.Event,
			"user_id":    it.UserID,
			"client_id":  it.ClientID,
			"desc":       it.Description,
			"ip":         it.IPAddress,
			"request_id": it.RequestID,
			"session_id": it.SessionID,
			"method":     it.Method,
			"path":       it.Path,
			"status":     it.Status,
			"ua":         it.UserAgent,
			"outcome":    it.Outcome,
			"error_code": it.ErrorCode,
			"extra":      it.ExtraJSON,
		})
	}
	c.JSON(200, out)
}

// --- Consents ---
// @Summary      授权记录列表
// @Description  列出当前用户对各客户端已授予的 scope
// @Tags         consent-api
// @Produce      json
// @Success      200 {array} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Router       /api/consents [get]
func (h *Handler) apiListConsents(c *gin.Context) {
	uidp, err := h.currentUser(c)
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	list, err := h.consentSvc.ListByUser(c, *uidp)
	if err != nil {
		c.JSON(500, gin.H{"error": "db"})
		return
	}
	out := make([]gin.H, 0, len(list))
	for _, cs := range list {
		name := ""
		if cl, err := h.clientSvc.FindByID(c, cs.ClientID); err == nil {
			name = cl.Name
		}
		out = append(out, gin.H{"client_id": cs.ClientID, "client_name": name, "scope": cs.Scope, "created_at": cs.CreatedAt.Unix()})
	}
	c.JSON(200, out)
}

// @Summary      撤销授权
// @Description  撤销当前用户对指定 client 的授权，并尝试吊销关联的刷新令牌
// @Tags         consent-api
// @Produce      json
// @Param        client_id path string true "客户端 ID"
// @Success      204 {string} string "No Content"
// @Failure      401 {object} map[string]string
// @Router       /api/consents/{client_id} [delete]
func (h *Handler) apiRevokeConsent(c *gin.Context) {
	uidp, err := h.currentUser(c)
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	cid := c.Param("client_id")
	if cid == "" {
		c.JSON(400, gin.H{"error": "bad_client"})
		return
	}
	if err := h.consentSvc.Revoke(c, *uidp, cid); err != nil {
		c.JSON(500, gin.H{"error": "db"})
		return
	}
	// 尝试删除相关刷新令牌（最佳努力）
	if h.refreshSvc != nil {
		_, _ = h.refreshSvc.DeleteByUserClient(c, *uidp, cid)
	}
	c.Status(204)
}

// --- Admin endpoints ---
// @Summary      管理员 - 用户列表
// @Tags         admin-api
// @Produce      json
// @Success      200 {array} map[string]interface{}
// @Failure      500 {object} map[string]string
// @Router       /api/users [get]
func (h *Handler) apiAdminListUsers(c *gin.Context) {
	users, err := h.userSvc.List(c, 1000)
	if err != nil {
		c.JSON(500, gin.H{"error": "db"})
		return
	}
	out := make([]gin.H, 0, len(users))
	for _, u := range users {
		out = append(out, gin.H{
			"id":       u.ID,
			"username": u.Username,
			"email":    u.Email,
			"name":     u.Name,
			"is_admin": u.IsAdmin,
			"is_dev":   u.IsDev,
		})
	}
	c.JSON(200, out)
}

// @Summary      管理员 - 创建用户
// @Tags         admin-api
// @Accept       json
// @Produce      json
// @Param        body body object true "{username,password,email,name,is_admin,is_dev}"
// @Success      201 {object} map[string]interface{}
// @Failure      400 {object} map[string]string
// @Router       /api/users [post]
func (h *Handler) apiAdminCreateUser(c *gin.Context) {
	var req struct {
		Username, Password, Email, Name string
		IsAdmin                         bool `json:"is_admin"`
		IsDev                           bool `json:"is_dev"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "bad_json"})
		return
	}
	u, err := h.userSvc.Create(c, req.Username, req.Password, req.Email, req.Name)
	if err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if req.IsAdmin {
		u.IsAdmin = true
		_ = h.userSvc.Save(c, u)
	}
	if req.IsDev {
		u.IsDev = true
		_ = h.userSvc.Save(c, u)
	}
	c.JSON(201, gin.H{"id": u.ID, "username": u.Username, "is_admin": u.IsAdmin, "is_dev": u.IsDev})
}

// --- Clients for current user (owner) ---
// @Summary      我的应用列表
// @Description  返回我拥有的已注册客户端（应用）
// @Tags         client-api
// @Produce      json
// @Success      200 {array} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Router       /api/my/clients [get]
func (h *Handler) apiMyClients(c *gin.Context) {
	uidp, err := h.currentUser(c)
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	list, err := h.clientSvc.ListByOwner(c, *uidp)
	if err != nil {
		c.JSON(500, gin.H{"error": "db"})
		return
	}
	out := make([]gin.H, 0, len(list))
	for _, cl := range list {
		out = append(out, gin.H{
			"client_id":                  cl.ClientID,
			"client_name":                cl.Name,
			"subject_type":               cl.SubjectType,
			"token_endpoint_auth_method": cl.TokenEndpointAuthMethod,
			"approved":                   cl.Approved,
			"enabled":                    cl.Enabled,
			"created_at":                 cl.CreatedAt.Unix(),
		})
	}
	c.JSON(200, out)
}

// 禁用我拥有的客户端
// @Summary      禁用我的客户端
// @Description  将指定客户端置为禁用状态（enabled=false）
// @Tags         client-api
// @Produce      json
// @Param        client_id path string true "客户端 ID"
// @Success      204 {string} string "No Content"
// @Failure      401 {object} map[string]string
// @Failure      403 {object} map[string]string
// @Router       /api/my/clients/{client_id}/disable [put]
func (h *Handler) apiMyDisableClient(c *gin.Context) {
	uidp, err := h.currentUser(c)
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	cid := c.Param("client_id")
	if cid == "" {
		c.JSON(400, gin.H{"error": "bad_client"})
		return
	}
	cl, err := h.clientSvc.FindAnyByID(c, cid)
	if err != nil {
		c.JSON(404, gin.H{"error": "not_found"})
		return
	}
	me, _ := h.userSvc.FindByID(c, *uidp)
	if cl.OwnerUserID != *uidp && !h.isAdmin(me) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	cl.Enabled = false
	if err := h.clientSvc.Save(c, cl); err != nil {
		c.JSON(500, gin.H{"error": "db"})
		return
	}
	c.Status(204)
}

// 物理删除我拥有的客户端
// @Summary      删除我的客户端
// @Description  物理删除我拥有的客户端
// @Tags         client-api
// @Produce      json
// @Param        client_id path string true "客户端 ID"
// @Success      204 {string} string "No Content"
// @Failure      401 {object} map[string]string
// @Failure      403 {object} map[string]string
// @Router       /api/my/clients/{client_id} [delete]
func (h *Handler) apiMyDeleteClient(c *gin.Context) {
	uidp, err := h.currentUser(c)
	if err != nil {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	cid := c.Param("client_id")
	if cid == "" {
		c.JSON(400, gin.H{"error": "bad_client"})
		return
	}
	cl, err := h.clientSvc.FindAnyByID(c, cid)
	if err != nil {
		c.JSON(404, gin.H{"error": "not_found"})
		return
	}
	me, _ := h.userSvc.FindByID(c, *uidp)
	if cl.OwnerUserID != *uidp && !h.isAdmin(me) {
		c.JSON(403, gin.H{"error": "forbidden"})
		return
	}
	if err := h.clientSvc.DeleteByID(c, cid); err != nil {
		c.JSON(500, gin.H{"error": "db"})
		return
	}
	c.Status(204)
}

// @Summary      管理员 - 更新用户
// @Tags         admin-api
// @Accept       json
// @Produce      json
// @Param        id path int true "用户ID"
// @Param        body body object true "{email,name,is_admin,is_dev,password}"
// @Success      204 {string} string "No Content"
// @Failure      400 {object} map[string]string
// @Failure      404 {object} map[string]string
// @Router       /api/users/{id} [put]
func (h *Handler) apiAdminUpdateUser(c *gin.Context) {
	idStr := c.Param("id")
	idU64, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(400, gin.H{"error": "bad_id"})
		return
	}
	u, err := h.userSvc.FindByID(c, idU64)
	if err != nil {
		c.JSON(404, gin.H{"error": "not_found"})
		return
	}
	var req struct {
		Email    *string `json:"email"`
		Name     *string `json:"name"`
		IsAdmin  *bool   `json:"is_admin"`
		IsDev    *bool   `json:"is_dev"`
		Password *string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "bad_json"})
		return
	}
	if req.Email != nil {
		u.Email = *req.Email
	}
	if req.Name != nil {
		u.Name = *req.Name
	}
	if req.IsAdmin != nil {
		u.IsAdmin = *req.IsAdmin
	}
	if req.IsDev != nil {
		u.IsDev = *req.IsDev
	}
	if req.Password != nil && *req.Password != "" {
		_ = h.userSvc.SetPassword(c, u.ID, *req.Password)
	}
	if err := h.userSvc.Save(c, u); err != nil {
		c.JSON(500, gin.H{"error": "db"})
		return
	}
	c.Status(204)
}
