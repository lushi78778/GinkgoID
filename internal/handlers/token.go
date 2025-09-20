package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"ginkgoid/internal/metrics"
	"ginkgoid/internal/services"
	"ginkgoid/internal/storage"
	"ginkgoid/internal/utils"
)

// @Summary      令牌端点（Token）
// @Description  交换授权码为令牌，或使用刷新令牌换新令牌
// @Tags         oauth2
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Security     BasicAuth
// @Param        grant_type     formData string true  "authorization_code 或 refresh_token"
// @Param        code           formData string false "授权码（授权码模式）"
// @Param        redirect_uri   formData string false "必须与授权时相同"
// @Param        code_verifier  formData string false "PKCE 校验所需"
// @Param        refresh_token  formData string false "刷新令牌（刷新模式）"
// @Param        client_id      formData string false "当未使用 Basic 时必填"
// @Param        client_secret  formData string false "当未使用 Basic 时必填"
// @Success      200 {object} map[string]interface{} "包含 access_token/id_token/refresh_token"
// @Failure      400 {object} map[string]string
// @Failure      401 {object} map[string]string
// @Router       /token [post]
func (h *Handler) token(c *gin.Context) {
	setNoCache(c)
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if !ok {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
	}
	if clientID == "" {
		c.Header("WWW-Authenticate", "Basic realm=token")
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}
	valid, cl, err := h.clientSvc.ValidateSecret(c, clientID, clientSecret)
	if err != nil || !valid {
		cid := clientID
		_ = h.logSvc.Write(c, "WARN", "TOKEN_CLIENT_AUTH_FAILED", nil, &cid, "invalid client auth", c.ClientIP(), services.LogWriteOpts{
			RequestID: c.GetString("request_id"),
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			Status:    401,
			UserAgent: c.Request.UserAgent(),
			Outcome:   "failure",
			ErrorCode: "invalid_client",
		})
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}
	grantType := c.PostForm("grant_type")
	if grantType == "refresh_token" {
		h.handleRefreshToken(c, clientID, cl)
		return
	}
	if grantType != "authorization_code" {
		c.JSON(400, gin.H{"error": "unsupported_grant_type"})
		return
	}
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	codeVerifier := c.PostForm("code_verifier")
	if code == "" || redirectURI == "" {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}
	ac, err := h.codeSvc.GetAndUse(c, code)
	if err != nil || ac.ClientID != cl.ClientID || ac.RedirectURI != redirectURI {
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}
	if ac.CodeChallenge != "" {
		if codeVerifier == "" {
			c.JSON(400, gin.H{"error": "invalid_grant", "error_description": "code_verifier required"})
			return
		}
		method := strings.ToUpper(ac.CodeChallengeMethod)
		if method == "S256" {
			sum := sha256.Sum256([]byte(codeVerifier))
			expected := base64.RawURLEncoding.EncodeToString(sum[:])
			if expected != ac.CodeChallenge {
				cid := clientID
				_ = h.logSvc.Write(c, "WARN", "TOKEN_PKCE_MISMATCH", nil, &cid, "pkce s256 mismatch", c.ClientIP(), services.LogWriteOpts{
					RequestID: c.GetString("request_id"),
					Method:    c.Request.Method,
					Path:      c.Request.URL.Path,
					Status:    400,
					UserAgent: c.Request.UserAgent(),
					Outcome:   "failure",
					ErrorCode: "invalid_grant",
				})
				c.JSON(400, gin.H{"error": "invalid_grant"})
				return
			}
		} else if method == "PLAIN" || method == "" {
			if h.cfg.Token.RequirePKCES256 {
				cid := clientID
				_ = h.logSvc.Write(c, "WARN", "TOKEN_PKCE_METHOD_UNSUPPORTED", nil, &cid, "plain not allowed", c.ClientIP(), services.LogWriteOpts{
					RequestID: c.GetString("request_id"),
					Method:    c.Request.Method,
					Path:      c.Request.URL.Path,
					Status:    400,
					UserAgent: c.Request.UserAgent(),
					Outcome:   "failure",
					ErrorCode: "invalid_grant",
				})
				c.JSON(400, gin.H{"error": "invalid_grant", "error_description": "pkce_s256_required"})
				return
			}
			if codeVerifier != ac.CodeChallenge {
				cid := clientID
				_ = h.logSvc.Write(c, "WARN", "TOKEN_PKCE_MISMATCH", nil, &cid, "pkce plain mismatch", c.ClientIP(), services.LogWriteOpts{
					RequestID: c.GetString("request_id"),
					Method:    c.Request.Method,
					Path:      c.Request.URL.Path,
					Status:    400,
					UserAgent: c.Request.UserAgent(),
					Outcome:   "failure",
					ErrorCode: "invalid_grant",
				})
				c.JSON(400, gin.H{"error": "invalid_grant"})
				return
			}
		} else {
			cid := clientID
			_ = h.logSvc.Write(c, "WARN", "TOKEN_PKCE_METHOD_UNSUPPORTED", nil, &cid, "unsupported method", c.ClientIP(), services.LogWriteOpts{
				RequestID: c.GetString("request_id"),
				Method:    c.Request.Method,
				Path:      c.Request.URL.Path,
				Status:    400,
				UserAgent: c.Request.UserAgent(),
				Outcome:   "failure",
				ErrorCode: "invalid_grant",
			})
			c.JSON(400, gin.H{"error": "invalid_grant", "error_description": "unsupported_code_challenge_method"})
			return
		}
	} else if strings.EqualFold(cl.TokenEndpointAuthMethod, "none") {
		c.JSON(400, gin.H{"error": "invalid_grant", "error_description": "pkce required"})
		return
	}
	subject := h.subjectFor(cl, ac.UserID)
	// DPoP: 若请求包含 DPoP-Proof，则尝试验证并生成 jkt
	var cnfJKT string
	if proof := c.GetHeader("DPoP"); proof != "" {
		htu := h.fullRequestURL(c)
		res, err := h.dpopVerifier.Verify(c.Request.Context(), proof, c.Request.Method, htu)
		if err != nil {
			cid := clientID
			_ = h.logSvc.Write(c, "WARN", "DPoP_INVALID", nil, &cid, "invalid dpop proof", c.ClientIP(), services.LogWriteOpts{
				RequestID: c.GetString("request_id"),
				Method:    c.Request.Method,
				Path:      c.Request.URL.Path,
				Status:    400,
				UserAgent: c.Request.UserAgent(),
				Outcome:   "failure",
				ErrorCode: "invalid_dpop",
				Extra:     map[string]any{"error": err.Error()},
			})
			c.Header("WWW-Authenticate", "DPoP error=\"invalid_dpop\"")
			c.JSON(400, gin.H{"error": "invalid_dpop"})
			return
		}
		cnfJKT = res.JKT
	}
	at, exp, jti, err := h.tokenSvc.BuildAccessTokenJWT(cl.ClientID, ac.UserID, subject, ac.Scope, ac.SID, cnfJKT)
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	_ = h.tokenRepo.SaveAccessToken(c, cl.ClientID, ac.UserID, ac.Scope, jti, exp)
	atHash := utils.ATHash(at)
	extra := map[string]interface{}{"sid": ac.SID, "azp": cl.ClientID}
	if u, err := h.userSvc.FindByID(c, ac.UserID); err == nil {
		if strings.Contains(ac.Scope, "profile") {
			if u.Name != "" {
				extra["name"] = u.Name
			}
			if u.Username != "" {
				extra["preferred_username"] = u.Username
			}
			if !u.UpdatedAt.IsZero() {
				extra["updated_at"] = u.UpdatedAt.Unix()
			}
		}
		if strings.Contains(ac.Scope, "email") {
			if u.Email != "" {
				extra["email"] = u.Email
			}
			extra["email_verified"] = u.EmailVerified
		}
	}
	if cnfJKT != "" {
		extra["cnf"] = map[string]any{"jkt": cnfJKT}
	}
	idt, err := h.tokenSvc.BuildIDToken(cl.ClientID, subject, ac.Nonce, "urn:op:auth:pwd", atHash, time.Now(), extra)
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	metrics.TokensIssued.Inc()
	resp := gin.H{"access_token": at, "token_type": "Bearer", "expires_in": int(h.cfg.Token.AccessTokenTTL.Seconds()), "id_token": idt}
	if cnfJKT != "" {
		resp["token_type"] = "DPoP"
		_ = h.logSvc.Write(c, "INFO", "DPoP_BOUND", &ac.UserID, &cl.ClientID, "access token bound to dpop key", c.ClientIP(), services.LogWriteOpts{
			RequestID: c.GetString("request_id"),
			SessionID: ac.SID,
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			Status:    200,
			UserAgent: c.Request.UserAgent(),
			Outcome:   "success",
			Extra:     map[string]any{"jkt": cnfJKT},
		})
	}
	if strings.Contains(" "+ac.Scope+" ", " offline_access ") {
		if rt, err := h.refreshSvc.Issue(c, ac.UserID, cl.ClientID, ac.Scope, subject, ac.SID, cnfJKT); err == nil {
			resp["refresh_token"] = rt
		}
	}
	c.JSON(200, resp)
	// 成功签发访问令牌
	_ = h.logSvc.Write(c, "INFO", "TOKEN_ISSUED", &ac.UserID, &cl.ClientID, "access/id token issued", c.ClientIP(), services.LogWriteOpts{
		RequestID: c.GetString("request_id"),
		SessionID: ac.SID,
		Method:    c.Request.Method,
		Path:      c.Request.URL.Path,
		Status:    200,
		UserAgent: c.Request.UserAgent(),
		Outcome:   "success",
		Extra:     map[string]any{"scope": ac.Scope, "has_refresh": strings.Contains(" "+ac.Scope+" ", " offline_access ")},
	})
}

func (h *Handler) handleRefreshToken(c *gin.Context, clientID string, cl *storage.Client) {
	rt := c.PostForm("refresh_token")
	if rt == "" {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}
	rec, newRT, err := h.refreshSvc.Use(c, rt)
	if err != nil || rec.ClientID != clientID {
		c.JSON(400, gin.H{"error": "invalid_grant"})
		return
	}
	cnfJKT := rec.JKT
	if cnfJKT != "" {
		proof := c.GetHeader("DPoP")
		if proof == "" {
			cid := clientID
			_ = h.logSvc.Write(c, "WARN", "DPoP_MISSING", &rec.UserID, &cid, "refresh token dpop missing", c.ClientIP(), services.LogWriteOpts{
				RequestID: c.GetString("request_id"),
				SessionID: rec.SID,
				Method:    c.Request.Method,
				Path:      c.Request.URL.Path,
				Status:    400,
				UserAgent: c.Request.UserAgent(),
				Outcome:   "failure",
				ErrorCode: "invalid_dpop",
			})
			c.Header("WWW-Authenticate", "DPoP error=\"invalid_dpop\"")
			c.JSON(400, gin.H{"error": "invalid_dpop"})
			return
		}
		htu := h.fullRequestURL(c)
		res, verr := h.dpopVerifier.Verify(c.Request.Context(), proof, c.Request.Method, htu)
		if verr != nil || res == nil || res.JKT != cnfJKT {
			cid := clientID
			errCode := "invalid_dpop"
			if verr == nil && res != nil {
				errCode = "dpop_jkt_mismatch"
			}
			actual := ""
			if res != nil {
				actual = res.JKT
			}
			_ = h.logSvc.Write(c, "WARN", "DPoP_INVALID", &rec.UserID, &cid, "refresh token dpop invalid", c.ClientIP(), services.LogWriteOpts{
				RequestID: c.GetString("request_id"),
				SessionID: rec.SID,
				Method:    c.Request.Method,
				Path:      c.Request.URL.Path,
				Status:    400,
				UserAgent: c.Request.UserAgent(),
				Outcome:   "failure",
				ErrorCode: errCode,
				Extra:     map[string]any{"expected_jkt": cnfJKT, "actual_jkt": actual},
			})
			c.Header("WWW-Authenticate", "DPoP error=\"invalid_dpop\"")
			c.JSON(400, gin.H{"error": "invalid_dpop"})
			return
		}
	}
	subject := h.subjectFor(cl, rec.UserID)
	at, exp, jti, err := h.tokenSvc.BuildAccessTokenJWT(cl.ClientID, rec.UserID, subject, rec.Scope, rec.SID, cnfJKT)
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	_ = h.tokenRepo.SaveAccessToken(c, cl.ClientID, rec.UserID, rec.Scope, jti, exp)
	atHash := utils.ATHash(at)
	extra := map[string]interface{}{"sid": rec.SID, "azp": cl.ClientID}
	if cnfJKT != "" {
		extra["cnf"] = map[string]any{"jkt": cnfJKT}
	}
	idt, err := h.tokenSvc.BuildIDToken(cl.ClientID, subject, "", "urn:op:auth:pwd", atHash, time.Now(), extra)
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	metrics.TokensIssued.Inc()
	resp := gin.H{"access_token": at, "token_type": "Bearer", "expires_in": int(h.cfg.Token.AccessTokenTTL.Seconds()), "id_token": idt, "refresh_token": newRT}
	if cnfJKT != "" {
		resp["token_type"] = "DPoP"
		_ = h.logSvc.Write(c, "INFO", "DPoP_BOUND", &rec.UserID, &cl.ClientID, "access token bound to dpop key", c.ClientIP(), services.LogWriteOpts{
			RequestID: c.GetString("request_id"),
			SessionID: rec.SID,
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			Status:    200,
			UserAgent: c.Request.UserAgent(),
			Outcome:   "success",
			Extra:     map[string]any{"jkt": cnfJKT},
		})
	}
	c.JSON(200, resp)
	_ = h.logSvc.Write(c, "INFO", "TOKEN_REFRESHED", &rec.UserID, &cl.ClientID, "access/id token refreshed", c.ClientIP(), services.LogWriteOpts{
		RequestID: c.GetString("request_id"),
		SessionID: rec.SID,
		Method:    c.Request.Method,
		Path:      c.Request.URL.Path,
		Status:    200,
		UserAgent: c.Request.UserAgent(),
		Outcome:   "success",
		Extra:     map[string]any{"scope": rec.Scope, "rotated_refresh": newRT != ""},
	})
}
