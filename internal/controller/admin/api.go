// Package admin 提供管理后台 API。所有接口需管理员会话与 CSRF 校验，
// 并在路由层启用严格的 Origin/Referer 校验。统一返回结构：
//
//	成功： {"code":0,"message":"ok","data":...}
//	失败： {"code":<非0>,"message":"错误信息"}
package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"fmt"
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/model/entity"
	"ginkgoid/internal/server/middleware"
	"ginkgoid/internal/service/jwk"
	"ginkgoid/internal/service/revocation"
	"ginkgoid/internal/service/session"
	"ginkgoid/internal/utility/passhash"
	"github.com/gin-gonic/gin"
)

func ok(c *gin.Context, data any) {
	rid := middleware.GetRequestID(c)
	c.Header("X-Error", "0")
	c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "ok", "request_id": rid, "data": data})
}
func fail(c *gin.Context, code int, msg string) {
	rid := middleware.GetRequestID(c)
	c.Header("X-Error", "1")
	c.Header("X-Error-Code", fmt.Sprintf("%d", code))
	c.Header("X-Error-Message", msg)
	c.JSON(http.StatusOK, gin.H{"code": code, "msg": msg, "request_id": rid})
}

// tableFail 用于 Layui 表格错误响应，包含 request_id 与错误头。
func tableFail(c *gin.Context, err error) {
	rid := middleware.GetRequestID(c)
	msg := "error"
	if err != nil {
		msg = err.Error()
	}
	c.Header("X-Error", "1")
	c.Header("X-Error-Code", "1")
	c.Header("X-Error-Message", msg)
	c.JSON(http.StatusOK, gin.H{"code": 1, "msg": msg, "request_id": rid, "count": 0, "data": []any{}})
}

// tableOK 用于 Layui 表格成功响应，包含 request_id。
func tableOK(c *gin.Context, count int64, rows any) {
	rid := middleware.GetRequestID(c)
	c.Header("X-Error", "0")
	c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "ok", "request_id": rid, "count": count, "data": rows})
}

// Clients
// ListClients 列出客户端（最多 1000 条，调试/导出用途）。
// GET /admin/api/clients
// ListClients 列出客户端
// @Summary      列出客户端
// @Description  返回最多 1000 条客户端列表
// @Tags         Admin
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Success      200 {object} admin.ClientsResponse
// @Router       /admin/api/clients [get]
func ListClients(c *gin.Context) {
	var list []entity.Client
	db.G().WithContext(c.Request.Context()).Limit(1000).Find(&list)
	out := make([]ClientItem, 0, len(list))
	for _, v := range list {
		out = append(out, ClientItem{
			ClientID:       v.ClientID,
			Name:           v.Name,
			Status:         v.Status,
			RedirectURIs:   v.RedirectURIs,
			PostLogoutURIs: v.PostLogoutURIs,
			Scopes:         v.Scopes,
		})
	}
	ok(c, out)
}

// ListClientsTable returns data for Layui table with pagination
// ListClientsTable 以 Layui 表格所需格式返回客户端分页数据。
// GET /admin/api/clients/table?page=&limit=&q=
// @Summary      客户端表格
// @Description  以 Layui 表格格式返回分页数据
// @Tags         Admin
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        page  query int false "页码"
// @Param        limit query int false "每页大小(<=200)"
// @Param        q     query string false "搜索关键词"
// @Success      200 {object} admin.TableClientsResponse
// @Router       /admin/api/clients/table [get]
func ListClientsTable(c *gin.Context) {
	// query params: page, limit, q
	page := atoiDefault(c.DefaultQuery("page", "1"), 1)
	limit := atoiDefault(c.DefaultQuery("limit", "10"), 10)
	if limit <= 0 || limit > 200 {
		limit = 10
	}
	offset := (page - 1) * limit
	q := c.Query("q")
	dbx := db.G().WithContext(c.Request.Context())
	if q != "" {
		like := "%" + q + "%"
		dbx = dbx.Where("client_id LIKE ? OR name LIKE ?", like, like)
	}
	var total int64
	if err := dbx.Model(&entity.Client{}).Count(&total).Error; err != nil {
		tableFail(c, err)
		return
	}
	var list []entity.Client
	if err := dbx.Offset(offset).Limit(limit).Find(&list).Error; err != nil {
		tableFail(c, err)
		return
	}
	rows := make([]ClientRow, 0, len(list))
	for _, v := range list {
		rows = append(rows, ClientRow{ClientID: v.ClientID, Name: v.Name, Status: v.Status})
	}
	tableOK(c, total, rows)
}

func atoiDefault(s string, def int) int {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return def
	}
	if n <= 0 {
		return def
	}
	return n
}

type UpsertClientReq struct {
	ClientID       string   `json:"client_id"`
	Name           string   `json:"name"`
	Secret         *string  `json:"secret"`
	RedirectURIs   []string `json:"redirect_uris"`
	PostLogoutURIs []string `json:"post_logout_uris"`
	Scopes         []string `json:"scopes"`
	Status         *int8    `json:"status"`
}

// CreateClient 创建客户端。
// POST /admin/api/clients
// body: {client_id,name,secret?,redirect_uris[],post_logout_uris[],scopes[],status?}
// @Summary      创建客户端
// @Description  创建新的 OAuth 客户端
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        body body   admin.UpsertClientReq true "客户端信息"
// @Success      200  {object} map[string]any
// @Failure      400  {object} map[string]any
// @Failure      500  {object} map[string]any
// @Router       /admin/api/clients [post]
func CreateClient(c *gin.Context) {
	var req UpsertClientReq
	if err := c.BindJSON(&req); err != nil {
		fail(c, 400, "bad_request")
		return
	}
	ru, _ := json.Marshal(req.RedirectURIs)
	plu, _ := json.Marshal(req.PostLogoutURIs)
	sc, _ := json.Marshal(req.Scopes)
	var sh *string
	if req.Secret != nil && *req.Secret != "" {
		h, _ := passhash.Hash(*req.Secret)
		sh = &h
	}
	cli := entity.Client{ClientID: req.ClientID, Name: req.Name, SecretHash: sh, RedirectURIs: string(ru), PostLogoutURIs: string(plu), Scopes: string(sc)}
	if req.Status != nil {
		cli.Status = *req.Status
	}
	if err := db.G().WithContext(c.Request.Context()).Create(&cli).Error; err != nil {
		fail(c, 500, err.Error())
		return
	}
	ok(c, gin.H{"client_id": cli.ClientID, "name": cli.Name, "status": cli.Status})
}

// UpdateClient 更新客户端（不提供的字段不变）。
// PUT /admin/api/clients/:id
// @Summary      更新客户端
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        id   path   string          true  "client_id"
// @Param        body body   admin.UpsertClientReq true  "更新信息（未提供的字段不变）"
// @Success      200  {object} map[string]any
// @Failure      400  {object} map[string]any
// @Failure      500  {object} map[string]any
// @Router       /admin/api/clients/{id} [put]
func UpdateClient(c *gin.Context) {
	id := c.Param("id")
	var req UpsertClientReq
	if err := c.BindJSON(&req); err != nil {
		fail(c, 400, "bad_request")
		return
	}
	updates := map[string]any{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Secret != nil {
		if *req.Secret == "" {
			updates["secret_hash"] = nil
		} else {
			h, _ := passhash.Hash(*req.Secret)
			updates["secret_hash"] = h
		}
	}
	if req.RedirectURIs != nil {
		b, _ := json.Marshal(req.RedirectURIs)
		updates["redirect_uris"] = string(b)
	}
	if req.PostLogoutURIs != nil {
		b, _ := json.Marshal(req.PostLogoutURIs)
		updates["post_logout_uris"] = string(b)
	}
	if req.Scopes != nil {
		b, _ := json.Marshal(req.Scopes)
		updates["scopes"] = string(b)
	}
	if req.Status != nil {
		updates["status"] = *req.Status
	}
	if err := db.G().WithContext(c.Request.Context()).Model(&entity.Client{}).Where("client_id = ?", id).Updates(updates).Error; err != nil {
		fail(c, 500, err.Error())
		return
	}
	ok(c, gin.H{"client_id": id})
}

// PatchClientStatus 启停客户端。
// PATCH /admin/api/clients/:id/status  body: {status}
// @Summary      启停客户端
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        id   path   string true "client_id"
// @Param        body body   admin.ClientStatusPatchReq true "状态"
// @Success      200  {object} map[string]any
// @Failure      400  {object} map[string]any
// @Failure      500  {object} map[string]any
// @Router       /admin/api/clients/{id}/status [patch]
func PatchClientStatus(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Status int8 `json:"status"`
	}
	if err := c.BindJSON(&body); err != nil {
		fail(c, 400, "bad_request")
		return
	}
	if err := db.G().WithContext(c.Request.Context()).Model(&entity.Client{}).Where("client_id = ?", id).Update("status", body.Status).Error; err != nil {
		fail(c, 500, err.Error())
		return
	}
	ok(c, gin.H{"client_id": id, "status": body.Status})
}

// Users
// ListUsers 列出用户（最多 1000 条）。
// GET /admin/api/users
// @Summary      列出用户
// @Tags         Admin
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Success      200 {object} admin.UsersResponse
// @Router       /admin/api/users [get]
func ListUsers(c *gin.Context) {
	var list []entity.User
	db.G().WithContext(c.Request.Context()).Limit(1000).Find(&list)
	out := make([]UserRow, 0, len(list))
	for _, v := range list {
		email := ""
		if v.Email != nil {
			email = *v.Email
		}
		out = append(out, UserRow{ID: v.ID, Username: v.Username, Email: email, EmailVerified: v.EmailVerified, Role: v.Role})
	}
	ok(c, out)
}

// Layui table for users
// ListUsersTable 以 Layui 表格格式返回用户分页数据。
// GET /admin/api/users/table?page=&limit=&q=
// @Summary      用户表格
// @Description  以 Layui 表格格式返回分页数据
// @Tags         Admin
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        page  query int false "页码"
// @Param        limit query int false "每页大小(<=200)"
// @Param        q     query string false "搜索关键词"
// @Success      200 {object} admin.TableUsersResponse
// @Router       /admin/api/users/table [get]
func ListUsersTable(c *gin.Context) {
	page := atoiDefault(c.DefaultQuery("page", "1"), 1)
	limit := atoiDefault(c.DefaultQuery("limit", "10"), 10)
	if limit <= 0 || limit > 200 {
		limit = 10
	}
	offset := (page - 1) * limit
	q := c.Query("q")
	dbx := db.G().WithContext(c.Request.Context()).Model(&entity.User{})
	if q != "" {
		like := "%" + q + "%"
		dbx = dbx.Where("username LIKE ? OR email LIKE ?", like, like)
	}
	var total int64
	if err := dbx.Count(&total).Error; err != nil {
		tableFail(c, err)
		return
	}
	var list []entity.User
	if err := dbx.Offset(offset).Limit(limit).Find(&list).Error; err != nil {
		tableFail(c, err)
		return
	}
	rows := make([]UserRow, 0, len(list))
	for _, v := range list {
		email := ""
		if v.Email != nil {
			email = *v.Email
		}
		rows = append(rows, UserRow{ID: v.ID, Username: v.Username, Email: email, EmailVerified: v.EmailVerified, Status: v.Status, Role: v.Role})
	}
	tableOK(c, total, rows)
}

// CreateUser 创建用户。
// POST /admin/api/users  body: {username,password,email?,email_verified?,role?}
// @Summary      创建用户
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        body body   admin.CreateUserReq true "用户信息"
// @Success      200  {object} map[string]any
// @Failure      400  {object} map[string]any
// @Failure      500  {object} map[string]any
// @Router       /admin/api/users [post]
func CreateUser(c *gin.Context) {
	var body struct {
		Username, Password, Email, Role string
		EmailVerified                   *bool `json:"email_verified"`
	}
	if err := c.BindJSON(&body); err != nil {
		fail(c, 400, "bad_request")
		return
	}
	ph, _ := passhash.Hash(body.Password)
	u := entity.User{Username: body.Username, PasswordHash: ph, Status: 1}
	if body.Email != "" {
		u.Email = &body.Email
	}
	if body.EmailVerified != nil {
		u.EmailVerified = *body.EmailVerified
	}
	if body.Role != "" {
		u.Role = body.Role
	}
	if err := db.G().WithContext(c.Request.Context()).Create(&u).Error; err != nil {
		fail(c, 500, err.Error())
		return
	}
	ok(c, u)
}

// PatchUserPassword 重置用户口令。
// PATCH /admin/api/users/:id/password  body: {password}
// @Summary      重置用户口令
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        id   path   string true "用户ID"
// @Param        body body   admin.PatchUserPasswordReq true "新密码"
// @Success      200  {object} map[string]any
// @Failure      400  {object} map[string]any
// @Failure      500  {object} map[string]any
// @Router       /admin/api/users/{id}/password [patch]
func PatchUserPassword(c *gin.Context) {
	id := c.Param("id")
	var body struct{ Password string }
	if err := c.BindJSON(&body); err != nil {
		fail(c, 400, "bad_request")
		return
	}
	ph, _ := passhash.Hash(body.Password)
	if err := db.G().WithContext(c.Request.Context()).Model(&entity.User{}).Where("id = ?", id).Update("password_hash", ph).Error; err != nil {
		fail(c, 500, err.Error())
		return
	}
	ok(c, gin.H{"id": id})
}

// Revoke all active sessions of a user (admin action)
// RevokeUserSessions 注销某用户的全部会话。
// POST /admin/api/users/:id/sessions/revoke_all
// @Summary      撤销用户所有会话
// @Tags         Admin
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        id   path   string true "用户ID"
// @Success      200  {object} map[string]any
// @Failure      400  {object} map[string]any
// @Failure      500  {object} map[string]any
// @Router       /admin/api/users/{id}/sessions/revoke_all [post]
func RevokeUserSessions(c *gin.Context) {
	id := c.Param("id")
	var uid uint64
	_, err := fmt.Sscanf(id, "%d", &uid)
	if err != nil || uid == 0 {
		fail(c, 400, "bad_request")
		return
	}
	if err := session.RevokeAllForUser(context.Background(), uid); err != nil {
		fail(c, 500, err.Error())
		return
	}
	ok(c, gin.H{"id": uid, "revoked": true})
}

// Update user's email and verification status
// PatchUserEmail 设置用户邮箱与验证状态。
// PATCH /admin/api/users/:id/email  body: {email,email_verified?}
// @Summary      设置用户邮箱
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        id   path   string true "用户ID"
// @Param        body body   admin.PatchUserEmailReq true "邮箱信息"
// @Success      200  {object} map[string]any
// @Failure      400  {object} map[string]any
// @Failure      500  {object} map[string]any
// @Router       /admin/api/users/{id}/email [patch]
func PatchUserEmail(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := c.BindJSON(&body); err != nil {
		fail(c, 400, "bad_request")
		return
	}
	updates := map[string]any{}
	if body.Email != "" {
		updates["email"] = body.Email
	} else {
		updates["email"] = nil
	}
	if body.EmailVerified != nil {
		updates["email_verified"] = *body.EmailVerified
	}
	if err := db.G().WithContext(c.Request.Context()).Model(&entity.User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		fail(c, 500, err.Error())
		return
	}
	ok(c, gin.H{"id": id})
}

// Update user's role
// PatchUserRole 设置用户角色（admin/operator/auditor/user）。
// PATCH /admin/api/users/:id/role  body: {role}
// @Summary      设置用户角色
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        id   path   string true "用户ID"
// @Param        body body   admin.PatchUserRoleReq true "角色"
// @Success      200  {object} map[string]any
// @Failure      400  {object} map[string]any
// @Failure      500  {object} map[string]any
// @Router       /admin/api/users/{id}/role [patch]
func PatchUserRole(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Role string `json:"role"`
	}
	if err := c.BindJSON(&body); err != nil || body.Role == "" {
		fail(c, 400, "bad_request")
		return
	}
	if err := db.G().WithContext(c.Request.Context()).Model(&entity.User{}).Where("id = ?", id).Update("role", body.Role).Error; err != nil {
		fail(c, 500, err.Error())
		return
	}
	// 角色变更后，旋转当前操作者的 CSRF Token（防御口令/权限变更后的重用窗口）
	_ = middleware.RotateCSRFCookie(c, 24*time.Hour)
	ok(c, gin.H{"id": id, "role": body.Role})
}

// Consents
// ListConsents 列出同意记录。
// GET /admin/api/consents?user_id=&client_id=
// @Summary      列出同意记录
// @Tags         Admin
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        user_id  query string false "用户ID"
// @Param        client_id query string false "客户端ID"
// @Success      200 {object} admin.ConsentsResponse
// @Router       /admin/api/consents [get]
func ListConsents(c *gin.Context) {
	var list []entity.Consent
	q := db.G().WithContext(c.Request.Context())
	if uid := c.Query("user_id"); uid != "" {
		q = q.Where("user_id = ?", uid)
	}
	if cid := c.Query("client_id"); cid != "" {
		q = q.Where("client_id = ?", cid)
	}
	q.Limit(1000).Find(&list)
	out := make([]ConsentRow, 0, len(list))
	for _, v := range list {
		out = append(out, ConsentRow{ID: v.ID, UserID: v.UserID, ClientID: v.ClientID, Scopes: v.Scopes})
	}
	ok(c, out)
}

// Layui table for consents
// ListConsentsTable 以 Layui 表格格式返回同意记录分页数据。
// GET /admin/api/consents/table?page=&limit=&user_id=&client_id=
// @Summary      同意记录表格
// @Description  以 Layui 表格格式返回分页数据
// @Tags         Admin
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        page  query int false "页码"
// @Param        limit query int false "每页大小(<=200)"
// @Param        user_id  query string false "用户ID"
// @Param        client_id query string false "客户端ID"
// @Success      200 {object} admin.TableConsentsResponse
// @Router       /admin/api/consents/table [get]
func ListConsentsTable(c *gin.Context) {
	page := atoiDefault(c.DefaultQuery("page", "1"), 1)
	limit := atoiDefault(c.DefaultQuery("limit", "10"), 10)
	if limit <= 0 || limit > 200 {
		limit = 10
	}
	offset := (page - 1) * limit
	dbx := db.G().WithContext(c.Request.Context()).Model(&entity.Consent{})
	if uid := c.Query("user_id"); uid != "" {
		dbx = dbx.Where("user_id = ?", uid)
	}
	if cid := c.Query("client_id"); cid != "" {
		dbx = dbx.Where("client_id = ?", cid)
	}
	var total int64
	if err := dbx.Count(&total).Error; err != nil {
		tableFail(c, err)
		return
	}
	var list []entity.Consent
	if err := dbx.Offset(offset).Limit(limit).Find(&list).Error; err != nil {
		tableFail(c, err)
		return
	}
	rows := make([]ConsentRow, 0, len(list))
	for _, v := range list {
		rows = append(rows, ConsentRow{ID: v.ID, UserID: v.UserID, ClientID: v.ClientID, Scopes: v.Scopes})
	}
	tableOK(c, total, rows)
}

// DeleteConsent 删除同意记录。
// DELETE /admin/api/consents/:id
// @Summary      删除同意记录
// @Tags         Admin
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        id   path   string true "同意记录ID"
// @Success      200  {object} map[string]any
// @Failure      500  {object} map[string]any
// @Router       /admin/api/consents/{id} [delete]
func DeleteConsent(c *gin.Context) {
	id := c.Param("id")
	if err := db.G().WithContext(c.Request.Context()).Delete(&entity.Consent{}, id).Error; err != nil {
		fail(c, 500, err.Error())
		return
	}
	ok(c, gin.H{"id": id})
}

// JWKS
// ListJWKS 列出 JWK（kid/alg/status）。
// GET /admin/api/jwks
// @Summary      列出 JWK
// @Tags         Admin
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Success      200 {object} map[string]any
// @Router       /admin/api/jwks [get]
func ListJWKS(c *gin.Context) {
	var list []entity.JWKKey
	db.G().WithContext(c.Request.Context()).Order("status DESC, not_before DESC").Find(&list)
	out := make([]gin.H, 0, len(list))
	for _, v := range list {
		out = append(out, gin.H{"kid": v.KID, "alg": v.Alg, "status": v.Status})
	}
	ok(c, out)
}

// RotateJWK 轮换 JWK。
// POST /admin/api/jwks/rotate?alg=ALL|RS256|ES256
// @Summary      轮换 JWK
// @Tags         Admin
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        alg query string false "算法：ALL|RS256|ES256"
// @Success      200 {object} map[string]any
// @Failure      500 {object} map[string]any
// @Router       /admin/api/jwks/rotate [post]
func RotateJWK(c *gin.Context) {
	alg := c.Query("alg")
	ctx := context.Background()
	if alg == "" || alg == "ALL" {
		if err := jwk.Rotate(ctx, "RS256", 7); err != nil {
			fail(c, 500, err.Error())
			return
		}
		if err := jwk.Rotate(ctx, "ES256", 7); err != nil {
			fail(c, 500, err.Error())
			return
		}
		ok(c, gin.H{"rotated": []string{"RS256", "ES256"}, "grace_days": 7})
		return
	}
	if err := jwk.Rotate(ctx, alg, 7); err != nil {
		fail(c, 500, err.Error())
		return
	}
	ok(c, gin.H{"rotated": []string{alg}, "grace_days": 7})
}

// Health/admin ping
// Ping 健康探测。
// GET /admin/api/ping
// @Summary      管理端 ping
// @Tags         Admin
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Success      200 {object} map[string]any
// @Router       /admin/api/ping [get]
func Ping(c *gin.Context) { ok(c, gin.H{"time": time.Now().UTC().Format(time.RFC3339)}) }

// Token Revocation APIs
// POST /admin/api/tokens/revoke_access {access_token}
// RevokeAccess 撤销 Access Token（解析 jti 并写入黑名单）。
// POST /admin/api/tokens/revoke_access  body: {access_token}
// @Summary      撤销 Access Token
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        body body   admin.RevokeAccessReq true "Access Token"
// @Success      200  {object} map[string]any
// @Failure      400  {object} map[string]any
// @Failure      500  {object} map[string]any
// @Router       /admin/api/tokens/revoke_access [post]
func RevokeAccess(c *gin.Context) {
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := c.BindJSON(&body); err != nil || body.AccessToken == "" {
		fail(c, 400, "bad_request")
		return
	}
	jti, err := revocation.RevokeAccessToken(context.Background(), body.AccessToken)
	if err != nil {
		fail(c, 500, err.Error())
		return
	}
	ok(c, gin.H{"jti": jti, "revoked": true})
}

// POST /admin/api/tokens/revoke_jti {jti, ttl_seconds}
// RevokeJTI 按 jti 撤销。
// POST /admin/api/tokens/revoke_jti  body: {jti, ttl_seconds}
// @Summary      按 jti 撤销
// @Tags         Admin
// @Accept       json
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        body body   admin.RevokeJTIReq true "撤销参数"
// @Success      200  {object} map[string]any
// @Failure      400  {object} map[string]any
// @Failure      500  {object} map[string]any
// @Router       /admin/api/tokens/revoke_jti [post]
func RevokeJTI(c *gin.Context) {
	var body struct {
		JTI string `json:"jti"`
		TTL int    `json:"ttl_seconds"`
	}
	if err := c.BindJSON(&body); err != nil || body.JTI == "" {
		fail(c, 400, "bad_request")
		return
	}
	ttl := time.Duration(body.TTL) * time.Second
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	if err := revocation.RevokeJTI(context.Background(), body.JTI, ttl); err != nil {
		fail(c, 500, err.Error())
		return
	}
	ok(c, gin.H{"jti": body.JTI, "revoked": true, "ttl_seconds": int(ttl.Seconds())})
}

// GET /admin/api/tokens/status?jti=
// TokenStatus 查询 jti 撤销状态。
// GET /admin/api/tokens/status?jti=
// @Summary      查询 jti 撤销状态
// @Tags         Admin
// @Produce      json
// @Security     Session
// @Security     CSRF
// @Param        jti query string true "JWT ID"
// @Success      200 {object} map[string]any
// @Failure      400 {object} map[string]any
// @Router       /admin/api/tokens/status [get]
func TokenStatus(c *gin.Context) {
	jti := c.Query("jti")
	if jti == "" {
		fail(c, 400, "bad_request")
		return
	}
	rev, _ := revocation.IsRevoked(context.Background(), jti)
	ok(c, gin.H{"jti": jti, "revoked": rev})
}
