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
	"ginkgoid/internal/service/jwk"
	"ginkgoid/internal/service/revocation"
	"ginkgoid/internal/service/session"
	"ginkgoid/internal/utility/passhash"
	"github.com/gin-gonic/gin"
)

func ok(c *gin.Context, data any) {
	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "ok", "data": data})
}
func fail(c *gin.Context, code int, msg string) {
	c.JSON(http.StatusOK, gin.H{"code": code, "message": msg})
}

// Clients
// ListClients 列出客户端（最多 1000 条，调试/导出用途）。
// GET /admin/api/clients
func ListClients(c *gin.Context) {
	var list []entity.Client
	db.G().WithContext(c.Request.Context()).Limit(1000).Find(&list)
	out := make([]gin.H, 0, len(list))
	for _, v := range list {
		out = append(out, gin.H{
			"client_id":        v.ClientID,
			"name":             v.Name,
			"status":           v.Status,
			"redirect_uris":    v.RedirectURIs,
			"post_logout_uris": v.PostLogoutURIs,
			"scopes":           v.Scopes,
		})
	}
	ok(c, out)
}

// ListClientsTable returns data for Layui table with pagination
// ListClientsTable 以 Layui 表格所需格式返回客户端分页数据。
// GET /admin/api/clients/table?page=&limit=&q=
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
		c.JSON(http.StatusOK, gin.H{"code": 1, "msg": err.Error(), "count": 0, "data": []any{}})
		return
	}
	var list []entity.Client
	if err := dbx.Offset(offset).Limit(limit).Find(&list).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{"code": 1, "msg": err.Error(), "count": 0, "data": []any{}})
		return
	}
	rows := make([]gin.H, 0, len(list))
	for _, v := range list {
		rows = append(rows, gin.H{"client_id": v.ClientID, "name": v.Name, "status": v.Status})
	}
	c.JSON(http.StatusOK, gin.H{"code": 0, "msg": "ok", "count": total, "data": rows})
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
func ListUsers(c *gin.Context) {
	var list []entity.User
	db.G().WithContext(c.Request.Context()).Limit(1000).Find(&list)
	out := make([]gin.H, 0, len(list))
	for _, v := range list {
		email := ""
		if v.Email != nil {
			email = *v.Email
		}
		out = append(out, gin.H{"id": v.ID, "username": v.Username, "email": email, "email_verified": v.EmailVerified, "role": v.Role})
	}
	ok(c, out)
}

// Layui table for users
// ListUsersTable 以 Layui 表格格式返回用户分页数据。
// GET /admin/api/users/table?page=&limit=&q=
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
		c.JSON(200, gin.H{"code": 1, "msg": err.Error(), "count": 0, "data": []any{}})
		return
	}
	var list []entity.User
	if err := dbx.Offset(offset).Limit(limit).Find(&list).Error; err != nil {
		c.JSON(200, gin.H{"code": 1, "msg": err.Error(), "count": 0, "data": []any{}})
		return
	}
	rows := make([]gin.H, 0, len(list))
	for _, v := range list {
		email := ""
		if v.Email != nil {
			email = *v.Email
		}
		rows = append(rows, gin.H{"id": v.ID, "username": v.Username, "email": email, "email_verified": v.EmailVerified, "status": v.Status, "role": v.Role})
	}
	c.JSON(200, gin.H{"code": 0, "msg": "ok", "count": total, "data": rows})
}

// CreateUser 创建用户。
// POST /admin/api/users  body: {username,password,email?,email_verified?,role?}
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
	ok(c, gin.H{"id": id, "role": body.Role})
}

// Consents
// ListConsents 列出同意记录。
// GET /admin/api/consents?user_id=&client_id=
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
	out := make([]gin.H, 0, len(list))
	for _, v := range list {
		out = append(out, gin.H{"id": v.ID, "user_id": v.UserID, "client_id": v.ClientID, "scopes": v.Scopes})
	}
	ok(c, out)
}

// Layui table for consents
// ListConsentsTable 以 Layui 表格格式返回同意记录分页数据。
// GET /admin/api/consents/table?page=&limit=&user_id=&client_id=
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
		c.JSON(200, gin.H{"code": 1, "msg": err.Error(), "count": 0, "data": []any{}})
		return
	}
	var list []entity.Consent
	if err := dbx.Offset(offset).Limit(limit).Find(&list).Error; err != nil {
		c.JSON(200, gin.H{"code": 1, "msg": err.Error(), "count": 0, "data": []any{}})
		return
	}
	rows := make([]gin.H, 0, len(list))
	for _, v := range list {
		rows = append(rows, gin.H{"id": v.ID, "user_id": v.UserID, "client_id": v.ClientID, "scopes": v.Scopes})
	}
	c.JSON(200, gin.H{"code": 0, "msg": "ok", "count": total, "data": rows})
}

// DeleteConsent 删除同意记录。
// DELETE /admin/api/consents/:id
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
func Ping(c *gin.Context) { ok(c, gin.H{"time": time.Now().UTC().Format(time.RFC3339)}) }

// Token Revocation APIs
// POST /admin/api/tokens/revoke_access {access_token}
// RevokeAccess 撤销 Access Token（解析 jti 并写入黑名单）。
// POST /admin/api/tokens/revoke_access  body: {access_token}
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
func TokenStatus(c *gin.Context) {
	jti := c.Query("jti")
	if jti == "" {
		fail(c, 400, "bad_request")
		return
	}
	rev, _ := revocation.IsRevoked(context.Background(), jti)
	ok(c, gin.H{"jti": jti, "revoked": rev})
}
