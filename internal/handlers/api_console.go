package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"ginkgoid/internal/services"
	"ginkgoid/internal/storage"
)

const (
	settingKeyScopes    = "console.scopes"
	settingKeyRoles     = "console.roles"
	settingKeyPolicies  = "console.policies"
	settingKeyBranding  = "console.branding"
	privacyExportPrefix = "privacy-export:"
)

// --- Helpers -----------------------------------------------------------------

func (h *Handler) currentUserRecord(c *gin.Context) (*storage.User, error) {
	uidp, err := h.currentUser(c)
	if err != nil {
		return nil, err
	}
	return h.userSvc.FindByID(c, *uidp)
}

func stringListFromCSV(in string) []string {
	parts := strings.Split(in, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func generateRecoveryCodes(n int) ([]string, error) {
	codes := make([]string, 0, n)
	buf := make([]byte, 8)
	for len(codes) < n {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		code := fmt.Sprintf("%s-%s", strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf[:4])), strings.ToUpper(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf[4:])))
		if len(code) > 10 {
			code = code[:10]
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// --- Me ----------------------------------------------------------------------

// @Summary      请求发送邮箱验证
// @Description  当前未配置邮件发送服务时会返回 501
// @Tags         user-api
// @Produce      json
// @Failure      401 {object} map[string]string
// @Failure      501 {object} map[string]string
// @Router       /api/me/email/verify [post]
func (h *Handler) apiMeVerifyEmail(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":   "email_verification_disabled",
		"message": "系统未配置邮箱发送服务，请联系管理员手动完成验证",
	})
}

type mePreferenceReq struct {
	MarketingOptIn *bool `json:"marketing_opt_in"`
}

// @Summary      更新用户偏好
// @Description  修改当前登录用户的营销订阅等偏好设置
// @Tags         user-api
// @Accept       json
// @Produce      json
// @Param        body  body      mePreferenceReq  true  "偏好设置"
// @Success      200 {object} map[string]interface{}
// @Failure      400 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Router       /api/me/preferences [put]
func (h *Handler) apiMeUpdatePreferences(c *gin.Context) {
	u, err := h.currentUserRecord(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req mePreferenceReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad_json"})
		return
	}
	if req.MarketingOptIn != nil {
		u.MarketingOptIn = *req.MarketingOptIn
	}
	if err := h.userSvc.Save(c, u); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"marketing_opt_in": u.MarketingOptIn})
}

// --- Logs --------------------------------------------------------------------

// @Summary      用户安全日志
// @Description  查询当前登录用户的安全事件日志，可按级别、关键词和时间范围过滤
// @Tags         user-api
// @Produce      json
// @Param        level query string false "日志级别"
// @Param        search query string false "关键字过滤"
// @Param        from  query string false "起始时间(YYYY-MM-DD 或 Unix 秒)"
// @Param        to    query string false "结束时间(YYYY-MM-DD 或 Unix 秒)"
// @Param        limit query int    false "返回数量上限"
// @Success      200 {array} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Router       /api/self/logs [get]
func (h *Handler) apiSelfLogs(c *gin.Context) {
	u, err := h.currentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	level := strings.ToUpper(strings.TrimSpace(c.Query("level")))
	search := strings.TrimSpace(c.Query("search"))
	var fromPtr, toPtr *time.Time
	if v := c.Query("from"); v != "" {
		if t, err := parseDateOrUnix(v); err == nil {
			fromPtr = &t
		}
	}
	if v := c.Query("to"); v != "" {
		if t, err := parseDateOrUnix(v); err == nil {
			toPtr = &t
		}
	}
	limit := 200
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	list, err := h.logSvc.Query2(c.Request.Context(), services.LogQuery{From: fromPtr, To: toPtr, Level: level, UserID: u, Limit: limit})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	q := strings.ToLower(search)
	resp := make([]gin.H, 0, len(list))
	for _, item := range list {
		if q != "" {
			blob := strings.ToLower(strings.Join([]string{item.Event, item.Description, item.IPAddress, item.UserAgent, item.Outcome, item.ErrorCode}, " "))
			if !strings.Contains(blob, q) {
				continue
			}
		}
		resp = append(resp, gin.H{
			"ts":         item.Timestamp.Unix(),
			"event":      item.Event,
			"level":      item.Level,
			"desc":       item.Description,
			"ip":         item.IPAddress,
			"client_id":  item.ClientID,
			"request_id": item.RequestID,
			"session_id": item.SessionID,
			"user_agent": item.UserAgent,
			"outcome":    item.Outcome,
			"error_code": item.ErrorCode,
		})
	}
	c.JSON(http.StatusOK, resp)
}

// parseDateOrUnix 支持日期字符串(YYYY-MM-DD)或 Unix 秒。
func parseDateOrUnix(v string) (time.Time, error) {
	if len(v) == 10 && strings.Count(v, "-") == 2 {
		return time.ParseInLocation("2006-01-02", v, time.Local)
	}
	if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(sec, 0), nil
	}
	return time.Time{}, errors.New("invalid time")
}

// --- MFA ---------------------------------------------------------------------

type mfaStateResponse struct {
	Enabled       bool     `json:"enabled"`
	Secret        string   `json:"secret,omitempty"`
	OtpauthURL    string   `json:"otpauth_url,omitempty"`
	OtpauthQR     string   `json:"otpauth_qr,omitempty"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
	LastUsedAt    *int64   `json:"last_used_at,omitempty"`
	EnrolledAt    *int64   `json:"enrolled_at,omitempty"`
}

// @Summary      获取 MFA 状态
// @Description  读取当前用户的多因素认证配置，包括密钥、恢复码等
// @Tags         user-security
// @Produce      json
// @Success      200 {object} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Router       /api/security/mfa [get]
func (h *Handler) apiSecurityGetMFA(c *gin.Context) {
	u, err := h.currentUserRecord(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	resp := mfaStateResponse{Enabled: u.MFAEnabled}
	if !u.MFAEnabled && u.MFAPendingSecret != "" {
		resp.Secret = u.MFAPendingSecret
		resp.OtpauthURL = h.buildOtpauthURL(u, u.MFAPendingSecret)
		resp.RecoveryCodes = stringListFromCSV(u.MFAPendingRecoveryCodes)
		if qr := h.buildOTPQRCode(resp.OtpauthURL); qr != "" {
			resp.OtpauthQR = qr
		}
	}
	if u.MFAEnabled {
		resp.RecoveryCodes = stringListFromCSV(u.MFARecoveryCodes)
	}
	if u.MFALastUsedAt != nil {
		v := u.MFALastUsedAt.Unix()
		resp.LastUsedAt = &v
	}
	if u.MFAEnrolledAt != nil {
		v := u.MFAEnrolledAt.Unix()
		resp.EnrolledAt = &v
	}
	c.JSON(http.StatusOK, resp)
}

// @Summary      生成 MFA 绑定信息
// @Description  为当前用户生成新的 TOTP 秘钥和恢复码用于绑定 MFA
// @Tags         user-security
// @Produce      json
// @Success      200 {object} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Router       /api/security/mfa/setup [post]
func (h *Handler) apiSecuritySetupMFA(c *gin.Context) {
	u, err := h.currentUserRecord(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	secret := u.MFAPendingSecret
	codes := stringListFromCSV(u.MFAPendingRecoveryCodes)
	if secret == "" {
		issuer := h.cfg.Issuer
		account := u.Email
		if account == "" {
			account = u.Username
		}
		key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: account})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "mfa_generate_failed"})
			return
		}
		secret = key.Secret()
		codes, err = generateRecoveryCodes(5)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "mfa_generate_failed"})
			return
		}
		u.MFAPendingSecret = secret
		u.MFAPendingRecoveryCodes = strings.Join(codes, ",")
		if err := h.userSvc.Save(c, u); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
			return
		}
	}
	otpauth := h.buildOtpauthURL(u, secret)
	resp := gin.H{
		"secret":         secret,
		"otpauth_url":    otpauth,
		"recovery_codes": codes,
	}
	if qr := h.buildOTPQRCode(otpauth); qr != "" {
		resp["otpauth_qr"] = qr
	}
	c.JSON(http.StatusOK, resp)
}

type activateMFAReq struct {
	Code string `json:"code"`
}

// @Summary      激活 MFA
// @Description  校验一次性验证码并启用当前用户的 MFA
// @Tags         user-security
// @Accept       json
// @Produce      json
// @Param        body body map[string]string true "验证码参数"
// @Success      204 {string} string "No Content"
// @Failure      400 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Router       /api/security/mfa/activate [post]
func (h *Handler) apiSecurityActivateMFA(c *gin.Context) {
	u, err := h.currentUserRecord(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	if u.MFAPendingSecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no_pending_secret"})
		return
	}
	var req activateMFAReq
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Code) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code_required"})
		return
	}
	if !totp.Validate(strings.TrimSpace(req.Code), u.MFAPendingSecret) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_code"})
		return
	}
	now := time.Now()
	u.MFASecret = u.MFAPendingSecret
	u.MFARecoveryCodes = u.MFAPendingRecoveryCodes
	u.MFAEnabled = true
	u.MFAEnrolledAt = &now
	u.MFALastUsedAt = &now
	u.MFAPendingSecret = ""
	u.MFAPendingRecoveryCodes = ""
	if err := h.userSvc.Save(c, u); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	c.Status(http.StatusNoContent)
}

// @Summary      关闭 MFA
// @Description  禁用当前用户的多因素认证配置
// @Tags         user-security
// @Produce      json
// @Success      204 {string} string "No Content"
// @Failure      401 {object} map[string]string
// @Router       /api/security/mfa [delete]
func (h *Handler) apiSecurityDisableMFA(c *gin.Context) {
	u, err := h.currentUserRecord(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	u.MFAEnabled = false
	u.MFASecret = ""
	u.MFARecoveryCodes = ""
	u.MFAPendingSecret = ""
	u.MFAPendingRecoveryCodes = ""
	if err := h.userSvc.Save(c, u); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handler) buildOtpauthURL(u *storage.User, secret string) string {
	issuer := strings.TrimSuffix(h.cfg.Issuer, "/")
	if issuer == "" {
		issuer = "GinkgoID"
	}
	account := u.Email
	if account == "" {
		account = u.Username
	}
	label := url.QueryEscape(fmt.Sprintf("%s:%s", issuer, account))
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", issuer)
	params.Set("period", "30")
	params.Set("algorithm", "SHA1")
	params.Set("digits", "6")
	return fmt.Sprintf("otpauth://totp/%s?%s", label, params.Encode())
}

func (h *Handler) buildOTPQRCode(otpauthURL string) string {
	if otpauthURL == "" {
		return ""
	}
	code, err := qr.Encode(otpauthURL, qr.M, qr.Auto)
	if err != nil {
		return ""
	}
	scaled, err := barcode.Scale(code, 256, 256)
	if err != nil {
		return ""
	}
	buf := new(bytes.Buffer)
	if err := png.Encode(buf, scaled); err != nil {
		return ""
	}
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	return "data:image/png;base64," + b64
}

// --- Sessions ----------------------------------------------------------------

// @Summary      会话列表
// @Description  列出当前用户的所有活跃会话
// @Tags         user-security
// @Produce      json
// @Success      200 {array} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Router       /api/security/sessions [get]
func (h *Handler) apiSecurityListSessions(c *gin.Context) {
	u, err := h.currentUserRecord(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	sidCookie := readSessionCookie(c, h.cfg.Session.CookieName)
	sessions, err := h.sessionSvc.ListByUser(c.Request.Context(), u.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	resp := make([]gin.H, 0, len(sessions))
	for _, sess := range sessions {
		isCurrent := sess.SID == sidCookie
		lastSeen := sess.LastSeen
		if lastSeen.IsZero() {
			lastSeen = sess.AuthTime
		}
		resp = append(resp, gin.H{
			"id":           sess.SID,
			"created_at":   sess.AuthTime.Unix(),
			"last_seen_at": lastSeen.Unix(),
			"user_agent":   sess.UserAgent,
			"ip":           sess.IP,
			"location":     "",
			"current":      isCurrent,
		})
	}
	c.JSON(http.StatusOK, resp)
}

// @Summary      注销其他会话
// @Description  注销除当前会话外的全部登录会话
// @Tags         user-security
// @Produce      json
// @Success      204 {string} string "No Content"
// @Failure      401 {object} map[string]string
// @Router       /api/security/sessions [delete]
func (h *Handler) apiSecurityDeleteSessions(c *gin.Context) {
	u, err := h.currentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	sidCookie := readSessionCookie(c, h.cfg.Session.CookieName)
	if err := h.sessionSvc.DeleteOthers(c.Request.Context(), *u, sidCookie); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	c.Status(http.StatusNoContent)
}

// @Summary      注销指定会话
// @Description  注销当前用户的指定会话 ID
// @Tags         user-security
// @Produce      json
// @Param        id path string true "会话 ID"
// @Success      204 {string} string "No Content"
// @Failure      401 {object} map[string]string
// @Failure      404 {object} map[string]string
// @Router       /api/security/sessions/{id} [delete]
func (h *Handler) apiSecurityDeleteSession(c *gin.Context) {
	u, err := h.currentUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	sid := c.Param("id")
	if sid == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad_session"})
		return
	}
	if err := h.sessionSvc.DeleteForUser(c.Request.Context(), *u, sid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	c.Status(http.StatusNoContent)
}

// --- Privacy -----------------------------------------------------------------

type privacyExportResponse struct {
	DownloadURL string `json:"download_url"`
	Message     string `json:"message,omitempty"`
}

// @Summary      导出个人数据
// @Description  触发当前用户的数据导出请求，生成临时下载链接
// @Tags         user-privacy
// @Produce      json
// @Success      200 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Router       /api/privacy/export [post]
func (h *Handler) apiPrivacyExport(c *gin.Context) {
	u, err := h.currentUserRecord(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	token := uuid.NewString()
	payload := gin.H{
		"generated_at": time.Now().Format(time.RFC3339),
		"user": gin.H{
			"id":               u.ID,
			"username":         u.Username,
			"email":            u.Email,
			"name":             u.Name,
			"email_verified":   u.EmailVerified,
			"marketing_opt_in": u.MarketingOptIn,
		},
	}
	data, _ := json.Marshal(payload)
	if err := h.rdb.Set(c.Request.Context(), privacyExportPrefix+token, data, 15*time.Minute).Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "store_failed"})
		return
	}
	c.JSON(http.StatusOK, privacyExportResponse{
		DownloadURL: fmt.Sprintf("/api/privacy/export/%s", token),
		Message:     "导出任务已生成，下载链接 15 分钟内有效。",
	})
}

// @Summary      下载导出结果
// @Description  通过导出令牌下载个人数据归档
// @Tags         user-privacy
// @Produce      application/zip
// @Param        token path string true "导出令牌"
// @Success      200 {file} file
// @Failure      404 {object} map[string]string
// @Router       /api/privacy/export/{token} [get]
func (h *Handler) apiPrivacyDownload(c *gin.Context) {
	token := c.Param("token")
	if token == "" {
		c.Status(http.StatusNotFound)
		return
	}
	cmd := h.rdb.Get(c.Request.Context(), privacyExportPrefix+token)
	if cmd.Err() != nil {
		c.Status(http.StatusNotFound)
		return
	}
	data := cmd.Val()
	c.Header("Content-Type", "application/json")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=export-%s.json", token))
	c.String(http.StatusOK, data)
}

type privacyDeleteReq struct {
	Reason string `json:"reason"`
}

// @Summary      删除个人数据
// @Description  提交删除当前用户数据的请求
// @Tags         user-privacy
// @Produce      json
// @Success      202 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Router       /api/privacy/delete [post]
func (h *Handler) apiPrivacyDelete(c *gin.Context) {
	u, err := h.currentUserRecord(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	var req privacyDeleteReq
	if err := c.ShouldBindJSON(&req); err != nil {
		req.Reason = ""
	}
	now := time.Now()
	u.DeletionRequestedAt = &now
	u.DeletionReason = strings.TrimSpace(req.Reason)
	if err := h.userSvc.Save(c, u); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"status":  "queued",
		"message": "删除请求已记录，管理员会在后台处理。如需撤回请联系支持。",
	})
}

// --- Additional handlers (clients/admin) will be implemented below ---

func (h *Handler) ensureClientAccess(c *gin.Context, u *storage.User, clientID string) (*storage.Client, error) {
	cl, err := h.clientSvc.FindAnyByID(c.Request.Context(), clientID)
	if err != nil {
		return nil, err
	}
	if cl.OwnerUserID != u.ID && !h.isAdmin(u) {
		return nil, fmt.Errorf("forbidden")
	}
	return cl, nil
}

// @Summary      客户端日志
// @Description  查询当前登录用户拥有的客户端的授权与令牌日志
// @Tags         developer-api
// @Produce      json
// @Param        client_id path string true "客户端 ID"
// @Param        level     query string false "日志级别"
// @Param        q         query string false "关键字过滤"
// @Param        limit     query int    false "返回数量"
// @Success      200 {array} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Failure      403 {object} map[string]string
// @Router       /api/my/clients/{client_id}/logs [get]
func (h *Handler) apiMyClientLogs(c *gin.Context) {
	user, err := h.currentUserRecord(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	clientID := c.Param("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad_client"})
		return
	}
	_, err = h.ensureClientAccess(c, user, clientID)
	if err != nil {
		if strings.Contains(err.Error(), "forbidden") {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	level := strings.ToUpper(strings.TrimSpace(c.Query("level")))
	keyword := strings.TrimSpace(c.Query("q"))
	limit := 200
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	clientIDPtr := clientID
	logs, err := h.logSvc.Query2(c.Request.Context(), services.LogQuery{ClientID: &clientIDPtr, Level: level, Limit: limit})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	q := strings.ToLower(keyword)
	resp := make([]gin.H, 0, len(logs))
	for _, item := range logs {
		blob := strings.ToLower(strings.Join([]string{item.Event, item.Description, item.Outcome, item.ErrorCode, item.RequestID}, " "))
		if q != "" && !strings.Contains(blob, q) {
			continue
		}
		resp = append(resp, gin.H{
			"ts":         item.Timestamp.Unix(),
			"level":      item.Level,
			"event":      item.Event,
			"desc":       item.Description,
			"request_id": item.RequestID,
			"user_id":    item.UserID,
			"outcome":    item.Outcome,
			"error_code": item.ErrorCode,
		})
	}
	c.JSON(http.StatusOK, resp)
}

// @Summary      客户端授权用户
// @Description  列出指定客户端已授权的终端用户
// @Tags         developer-api
// @Produce      json
// @Param        client_id path string true "客户端 ID"
// @Success      200 {array} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Failure      403 {object} map[string]string
// @Router       /api/my/clients/{client_id}/users [get]
func (h *Handler) apiMyClientUsers(c *gin.Context) {
	user, err := h.currentUserRecord(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	clientID := c.Param("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad_client"})
		return
	}
	_, err = h.ensureClientAccess(c, user, clientID)
	if err != nil {
		if strings.Contains(err.Error(), "forbidden") {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	list, err := h.consentSvc.ListUsersForClient(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	resp := make([]gin.H, 0, len(list))
	for _, item := range list {
		scopes := strings.Fields(item.Scope)
		resp = append(resp, gin.H{
			"user_id":    item.UserID,
			"username":   item.Username,
			"email":      item.Email,
			"name":       item.Name,
			"granted_at": item.GrantedAt.Unix(),
			"scopes":     scopes,
		})
	}
	c.JSON(http.StatusOK, resp)
}

// @Summary      解除客户端授权
// @Description  撤销指定用户对客户端的授权
// @Tags         developer-api
// @Produce      json
// @Param        client_id path string true "客户端 ID"
// @Param        user_id   path string true "用户 ID"
// @Success      204 {string} string "No Content"
// @Failure      400 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Failure      403 {object} map[string]string
// @Router       /api/my/clients/{client_id}/users/{user_id} [delete]
func (h *Handler) apiMyClientUserDelete(c *gin.Context) {
	user, err := h.currentUserRecord(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	clientID := c.Param("client_id")
	uidStr := c.Param("user_id")
	if clientID == "" || uidStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad_request"})
		return
	}
	_, err = h.ensureClientAccess(c, user, clientID)
	if err != nil {
		if strings.Contains(err.Error(), "forbidden") {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	uid, err := strconv.ParseUint(uidStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad_user"})
		return
	}
	if err := h.consentSvc.Revoke(c.Request.Context(), uid, clientID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	if h.refreshSvc != nil {
		_, _ = h.refreshSvc.DeleteByUserClient(c.Request.Context(), uid, clientID)
	}
	c.Status(http.StatusNoContent)
}

// @Summary      客户端统计
// @Description  获取客户端最近授权与登录统计信息
// @Tags         developer-api
// @Produce      json
// @Param        client_id path string true "客户端 ID"
// @Param        period    query string false "统计周期"
// @Success      200 {object} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Failure      403 {object} map[string]string
// @Router       /api/my/clients/{client_id}/analytics [get]
func (h *Handler) apiMyClientAnalytics(c *gin.Context) {
	user, err := h.currentUserRecord(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	clientID := c.Param("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad_client"})
		return
	}
	_, err = h.ensureClientAccess(c, user, clientID)
	if err != nil {
		if strings.Contains(err.Error(), "forbidden") {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	period := strings.TrimSpace(c.Query("period"))
	duration := 7 * 24 * time.Hour
	switch period {
	case "24h":
		duration = 24 * time.Hour
	case "30d":
		duration = 30 * 24 * time.Hour
	}
	now := time.Now()
	from := now.Add(-duration)
	clientIDPtr := clientID
	logs, err := h.logSvc.Query2(c.Request.Context(), services.LogQuery{From: &from, ClientID: &clientIDPtr, Limit: 1000})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	success := 0
	failure := 0
	dayBuckets := map[string]map[string]int{}
	for _, rec := range logs {
		day := rec.Timestamp.Format("2006-01-02")
		bucket, ok := dayBuckets[day]
		if !ok {
			bucket = map[string]int{}
			dayBuckets[day] = bucket
		}
		if rec.Outcome == "failure" || strings.HasPrefix(rec.Event, "TOKEN_") && rec.Level != "INFO" {
			bucket["failed"]++
			failure++
			continue
		}
		if strings.HasPrefix(rec.Event, "TOKEN_") || rec.Event == "USER_LOGIN" {
			bucket["success"]++
			success++
		}
	}
	consents, err := h.consentSvc.ListUsersForClient(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	newUsers := 0
	newUsersByDay := map[string]int{}
	for _, it := range consents {
		if it.GrantedAt.After(from) {
			newUsers++
			day := it.GrantedAt.Format("2006-01-02")
			newUsersByDay[day]++
		}
	}
	periodDays := int(duration.Hours()/24 + 0.5)
	if periodDays <= 0 {
		periodDays = 1
	}
	points := make([]gin.H, 0, periodDays)
	for i := periodDays - 1; i >= 0; i-- {
		dayTime := now.Add(-time.Duration(i) * 24 * time.Hour)
		dayKey := dayTime.Format("2006-01-02")
		bucket := dayBuckets[dayKey]
		pt := gin.H{
			"date":      dayKey,
			"success":   bucket["success"],
			"failed":    bucket["failed"],
			"logins":    bucket["success"],
			"new_users": newUsersByDay[dayKey],
		}
		points = append(points, pt)
	}
	topErrors := map[string]int{}
	for _, rec := range logs {
		if rec.ErrorCode != "" {
			topErrors[rec.ErrorCode]++
		}
	}
	type errItem struct {
		Code        string `json:"code"`
		Count       int    `json:"count"`
		Description string `json:"description"`
	}
	errList := make([]errItem, 0, len(topErrors))
	for code, count := range topErrors {
		errList = append(errList, errItem{Code: code, Count: count})
	}
	sort.Slice(errList, func(i, j int) bool { return errList[i].Count > errList[j].Count })
	if len(errList) > 5 {
		errList = errList[:5]
	}
	total := success + failure
	successRate := 1.0
	failureRate := 0.0
	if total > 0 {
		successRate = float64(success) / float64(total)
		failureRate = float64(failure) / float64(total)
	}
	c.JSON(http.StatusOK, gin.H{
		"total_logins": success,
		"new_users":    newUsers,
		"success_rate": successRate,
		"failure_rate": failureRate,
		"period":       fmt.Sprintf("最近 %d 天", periodDays),
		"points":       points,
		"top_errors":   errList,
	})
}

// @Summary      管理员仪表盘指标
// @Description  汇总平台用户、客户端与登录统计
// @Tags         admin-api
// @Produce      json
// @Success      200 {object} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Router       /api/admin/metrics [get]
func (h *Handler) apiAdminMetrics(c *gin.Context) {
	totalUsers, _ := h.userSvc.Count(c.Request.Context())
	totalClients, _ := h.clientSvc.Count(c.Request.Context())
	pendingClients, _ := h.clientSvc.CountPending(c.Request.Context())
	mfaEnabled, _ := h.userSvc.CountMFAEnabled(c.Request.Context())
	now := time.Now()
	from7 := now.Add(-7 * 24 * time.Hour)
	logs7, _ := h.logSvc.Query2(c.Request.Context(), services.LogQuery{From: &from7, Limit: 2000})
	success := 0
	failure := 0
	dayBuckets := map[string]int{}
	dayFail := map[string]int{}
	clientUsage := map[string]int{}
	activeUsers := map[uint64]struct{}{}
	for _, rec := range logs7 {
		day := rec.Timestamp.Format("2006-01-02")
		if rec.UserID != nil && (rec.Outcome == "success" || rec.Outcome == "") && (rec.Event == "USER_LOGIN" || strings.HasPrefix(rec.Event, "TOKEN_")) {
			activeUsers[*rec.UserID] = struct{}{}
		}
		if rec.ClientID != nil && (rec.Outcome == "success" || rec.Outcome == "") && strings.HasPrefix(rec.Event, "TOKEN_") {
			clientUsage[*rec.ClientID]++
		}
		if rec.Outcome == "failure" {
			failure++
			dayFail[day]++
			continue
		}
		if strings.HasPrefix(rec.Event, "TOKEN_") || rec.Event == "USER_LOGIN" {
			success++
			dayBuckets[day]++
		}
	}
	from1 := now.Add(-24 * time.Hour)
	logs1, _ := h.logSvc.Query2(c.Request.Context(), services.LogQuery{From: &from1, Limit: 500})
	loginsToday := 0
	for _, rec := range logs1 {
		if rec.Outcome != "failure" && (rec.Event == "USER_LOGIN" || strings.HasPrefix(rec.Event, "TOKEN_")) {
			loginsToday++
		}
	}
	type clientCount struct {
		ID    string
		Name  string
		Count int
	}
	clientList := make([]clientCount, 0, len(clientUsage))
	for id, cnt := range clientUsage {
		clientList = append(clientList, clientCount{ID: id, Count: cnt})
	}
	sort.Slice(clientList, func(i, j int) bool { return clientList[i].Count > clientList[j].Count })
	topIDs := make([]string, 0, len(clientList))
	for i, item := range clientList {
		if i >= 5 {
			break
		}
		topIDs = append(topIDs, item.ID)
	}
	metaClients := map[string]storage.Client{}
	if len(topIDs) > 0 {
		var rows []storage.Client
		if err := h.clientSvc.DB().WithContext(c.Request.Context()).Where("client_id IN ?", topIDs).Find(&rows).Error; err == nil {
			for _, r := range rows {
				metaClients[r.ClientID] = r
			}
			for i := range clientList {
				if m, ok := metaClients[clientList[i].ID]; ok && m.Name != "" {
					clientList[i].Name = m.Name
				}
			}
		}
	}
	if len(clientList) > 5 {
		clientList = clientList[:5]
	}
	points := make([]gin.H, 0, 7)
	for i := 6; i >= 0; i-- {
		day := now.Add(-time.Duration(i) * 24 * time.Hour).Format("2006-01-02")
		points = append(points, gin.H{"date": day, "success": dayBuckets[day], "failed": dayFail[day]})
	}
	totalAuth := success + failure
	successRate := 1.0
	if totalAuth > 0 {
		successRate = float64(success) / float64(totalAuth)
	}
	topClients := make([]gin.H, 0, len(clientList))
	for _, item := range clientList {
		label := item.ID
		if item.Name != "" {
			label = item.Name
		}
		status := "approved"
		if m, ok := metaClients[item.ID]; ok {
			if m.Name != "" {
				label = m.Name
			}
			if !m.Approved {
				if m.Status == 0 {
					status = "pending"
				} else {
					status = "disabled"
				}
			}
		}
		if status == "" {
			status = "approved"
		}
		topClients = append(topClients, gin.H{
			"client_id":       item.ID,
			"name":            label,
			"weekly_logins":   item.Count,
			"approval_status": status,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"total_users":        totalUsers,
		"active_users_7d":    len(activeUsers),
		"total_clients":      totalClients,
		"logins_today":       loginsToday,
		"mfa_enabled":        mfaEnabled,
		"pending_clients":    pendingClients,
		"login_success_rate": successRate,
		"daily_logins":       points,
		"top_clients":        topClients,
	})
}

type scopeSetting struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Claims      []string `json:"claims"`
}

type roleSetting struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type policySetting struct {
	PasswordMinLength     int  `json:"password_min_length"`
	PasswordRequireNumber bool `json:"password_require_number"`
	PasswordRequireSymbol bool `json:"password_require_symbol"`
	TokenTTLSec           int  `json:"token_ttl_seconds"`
	RefreshTokenTTLDays   int  `json:"refresh_token_ttl_days"`
	RequireMFA            bool `json:"require_mfa"`
}

type brandingSetting struct {
	PrimaryColor    string `json:"primary_color"`
	AccentColor     string `json:"accent_color"`
	BackgroundColor string `json:"background_color"`
	LogoURL         string `json:"logo_url"`
	DarkModeLogoURL string `json:"dark_mode_logo_url"`
	EmailSubject    string `json:"email_subject"`
	EmailBody       string `json:"email_body"`
}

func defaultScopes() []scopeSetting {
	return []scopeSetting{
		{Name: "openid", Description: "基础身份标识 (sub)", Claims: []string{"sub"}},
		{Name: "profile", Description: "姓名、昵称等基础资料", Claims: []string{"name", "preferred_username"}},
		{Name: "email", Description: "邮箱地址", Claims: []string{"email", "email_verified"}},
	}
}

func defaultRoles() []roleSetting {
	return []roleSetting{
		{Name: "admin", Description: "平台管理员", Permissions: []string{"users:manage", "logs:view", "clients:approve", "settings:write"}},
		{Name: "support", Description: "客服支持角色", Permissions: []string{"users:view", "logs:view"}},
	}
}

func defaultPolicies() policySetting {
	return policySetting{PasswordMinLength: 10, PasswordRequireNumber: true, PasswordRequireSymbol: true, TokenTTLSec: 3600, RefreshTokenTTLDays: 14, RequireMFA: false}
}

func defaultBranding() brandingSetting {
	return brandingSetting{
		PrimaryColor:    "#6366F1",
		AccentColor:     "#10B981",
		BackgroundColor: "#F6F7FB",
		EmailSubject:    "欢迎使用 GinkgoID",
		EmailBody:       "您好 {{user.name}}，欢迎加入 GinkgoID 平台。",
	}
}

// @Summary      管理员设置读取
// @Description  读取平台的 scope、角色与安全策略配置
// @Tags         admin-api
// @Produce      json
// @Success      200 {object} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Router       /api/admin/settings [get]
func (h *Handler) apiAdminSettings(c *gin.Context) {
	var scopes []scopeSetting
	if ok, err := h.settingSvc.GetJSON(c.Request.Context(), settingKeyScopes, &scopes); err != nil || !ok {
		scopes = defaultScopes()
	}
	var roles []roleSetting
	if ok, err := h.settingSvc.GetJSON(c.Request.Context(), settingKeyRoles, &roles); err != nil || !ok {
		roles = defaultRoles()
	}
	policies := defaultPolicies()
	_, _ = h.settingSvc.GetJSON(c.Request.Context(), settingKeyPolicies, &policies)
	c.JSON(http.StatusOK, gin.H{"scopes": scopes, "roles": roles, "policies": policies})
}

// @Summary      更新 scope 配置
// @Description  覆盖平台支持的 scope 列表及对应 claim
// @Tags         admin-api
// @Accept       json
// @Produce      json
// @Param        body body []map[string]interface{} true "Scope 列表"
// @Success      204 {string} string "No Content"
// @Failure      400 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Router       /api/admin/scopes [put]
func (h *Handler) apiAdminUpdateScopes(c *gin.Context) {
	var req []scopeSetting
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad_json"})
		return
	}
	for _, item := range req {
		if strings.TrimSpace(item.Name) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name_required"})
			return
		}
	}
	if err := h.settingSvc.SetJSON(c.Request.Context(), settingKeyScopes, req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	c.Status(http.StatusNoContent)
}

// @Summary      更新角色权限
// @Description  设置平台角色及其权限列表
// @Tags         admin-api
// @Accept       json
// @Produce      json
// @Param        body body []map[string]interface{} true "角色列表"
// @Success      204 {string} string "No Content"
// @Failure      400 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Router       /api/admin/roles [put]
func (h *Handler) apiAdminUpdateRoles(c *gin.Context) {
	var req []roleSetting
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad_json"})
		return
	}
	for _, item := range req {
		if strings.TrimSpace(item.Name) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "name_required"})
			return
		}
	}
	if err := h.settingSvc.SetJSON(c.Request.Context(), settingKeyRoles, req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	c.Status(http.StatusNoContent)
}

// @Summary      更新安全策略
// @Description  保存口令复杂度、令牌 TTL、MFA 要求等策略
// @Tags         admin-api
// @Accept       json
// @Produce      json
// @Param        body body policySetting true "安全策略"
// @Success      204 {string} string "No Content"
// @Failure      400 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Router       /api/admin/policies [put]
func (h *Handler) apiAdminUpdatePolicies(c *gin.Context) {
	var req policySetting
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad_json"})
		return
	}
	if req.PasswordMinLength <= 0 {
		req.PasswordMinLength = defaultPolicies().PasswordMinLength
	}
	if req.TokenTTLSec <= 0 {
		req.TokenTTLSec = defaultPolicies().TokenTTLSec
	}
	if req.RefreshTokenTTLDays <= 0 {
		req.RefreshTokenTTLDays = defaultPolicies().RefreshTokenTTLDays
	}
	if err := h.settingSvc.SetJSON(c.Request.Context(), settingKeyPolicies, req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	c.Status(http.StatusNoContent)
}

// @Summary      获取品牌配置
// @Description  读取管理控制台的品牌配色与邮箱模板
// @Tags         admin-api
// @Produce      json
// @Success      200 {object} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Router       /api/admin/branding [get]
func (h *Handler) apiAdminBranding(c *gin.Context) {
	brand := defaultBranding()
	_, _ = h.settingSvc.GetJSON(c.Request.Context(), settingKeyBranding, &brand)
	c.JSON(http.StatusOK, brand)
}

// @Summary      更新品牌配置
// @Description  保存控制台主题色、Logo 与邮件模板
// @Tags         admin-api
// @Accept       json
// @Produce      json
// @Param        body body brandingSetting true "品牌配置"
// @Success      204 {string} string "No Content"
// @Failure      400 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Router       /api/admin/branding [put]
func (h *Handler) apiAdminUpdateBranding(c *gin.Context) {
	var req brandingSetting
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad_json"})
		return
	}
	if req.PrimaryColor == "" {
		req.PrimaryColor = defaultBranding().PrimaryColor
	}
	if req.AccentColor == "" {
		req.AccentColor = defaultBranding().AccentColor
	}
	if req.BackgroundColor == "" {
		req.BackgroundColor = defaultBranding().BackgroundColor
	}
	if err := h.settingSvc.SetJSON(c.Request.Context(), settingKeyBranding, req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db"})
		return
	}
	c.Status(http.StatusNoContent)
}
