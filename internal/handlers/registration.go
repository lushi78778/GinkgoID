package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"ginkgoid/internal/services"
	"strings"
)

// @Summary      动态注册客户端
// @Description  按 OIDC Dynamic Client Registration 注册新客户端
// @Tags         registration
// @Accept       json
// @Produce      json
// @Param        body  body   services.RegisterRequest  true  "注册请求体"
// @Success      201   {object} services.RegisterResponse
// @Failure      400   {object} map[string]string
// @Router       /register [post]
func (h *Handler) registerClient(c *gin.Context) {
	if tok := parseBearer(c.GetHeader("Authorization")); h.cfg.Registration.InitialAccessToken != "" {
		if tok == "" || tok != h.cfg.Registration.InitialAccessToken {
			c.JSON(401, gin.H{"error": "unauthorized"})
			return
		}
	}
	var req services.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "bad json"})
		return
	}
	baseURL := h.baseURL(c)
	resp, cl, err := h.clientSvc.Register(c, baseURL, &req)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_client_metadata", "error_description": err.Error()})
		return
	}
	// 记录拥有者（若当前存在登录会话）
	if sid := readSessionCookie(c, h.cfg.Session.CookieName); sid != "" {
		if sess, err := h.sessionSvc.Get(c, sid); err == nil {
			cl.OwnerUserID = sess.UserID
			_ = h.clientSvc.Save(c, cl)
		}
	}
	c.Header("Location", resp.RegistrationClientURI)
	ip := c.ClientIP()
	_ = h.logSvc.Write(c, "INFO", "CLIENT_REGISTERED", nil, &resp.ClientID, "client registered", ip, services.LogWriteOpts{
		RequestID: c.GetString("request_id"),
		Method:    c.Request.Method,
		Path:      c.Request.URL.Path,
		Status:    201,
		UserAgent: c.Request.UserAgent(),
		Outcome:   "success",
		Extra:     map[string]any{"name": cl.Name},
	})
	c.JSON(201, resp)
}

// @Summary      轮换 Registration Access Token
// @Description  使用现有 registration_access_token 轮换获取新的 token
// @Tags         registration
// @Produce      json
// @Param        client_id   query string true  "客户端 ID"
// @Param        Authorization header string true "Bearer {registration_access_token}"
// @Success      200   {object} map[string]string  "{\"registration_access_token\":\"...\"}"
// @Failure      401   {object} map[string]string
// @Router       /register/rotate [post]
func (h *Handler) rotateRegistrationToken(c *gin.Context) {
	clientID := c.Query("client_id")
	tok := parseBearer(c.GetHeader("Authorization"))
	if clientID == "" || tok == "" {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	ok, cl, err := h.clientSvc.ValidateRegistrationToken(c, clientID, tok)
	if err != nil || !ok {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	now := time.Now()
	sh := sha256.Sum256([]byte(clientID + now.String()))
	newTok := base64.RawURLEncoding.EncodeToString(sh[:])
	if hh, err := bcrypt.GenerateFromPassword([]byte(newTok), bcrypt.DefaultCost); err == nil {
		cl.RegistrationAccessTokenHash = string(hh)
		if h.cfg.Token.RegistrationPATTTL > 0 {
			ex := now.Add(h.cfg.Token.RegistrationPATTTL)
			cl.RegistrationAccessTokenExpiresAt = &ex
		}
		if err := h.clientSvc.Save(c, cl); err != nil {
			c.JSON(500, gin.H{"error": "server_error"})
			return
		}
		c.JSON(200, gin.H{"registration_access_token": newTok})
		_ = h.logSvc.Write(c, "INFO", "REGISTRATION_TOKEN_ROTATED", nil, &cl.ClientID, "registration token rotated", c.ClientIP(), services.LogWriteOpts{
			RequestID: c.GetString("request_id"),
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			Status:    200,
			UserAgent: c.Request.UserAgent(),
			Outcome:   "success",
		})
		return
	}
	c.JSON(500, gin.H{"error": "server_error"})
}

// @Summary      获取已注册客户端
// @Description  使用 registration_access_token 返回客户端元数据
// @Tags         registration
// @Produce      json
// @Param        client_id     query string true  "客户端 ID"
// @Param        Authorization header string true "Bearer {registration_access_token}"
// @Success      200   {object} map[string]interface{}
// @Failure      401   {object} map[string]string
// @Router       /register [get]
func (h *Handler) getRegisteredClient(c *gin.Context) {
	clientID := c.Query("client_id")
	tok := parseBearer(c.GetHeader("Authorization"))
	if clientID == "" || tok == "" {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	ok, cl, err := h.clientSvc.ValidateRegistrationToken(c, clientID, tok)
	if err != nil || !ok {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	var rus []string
	_ = json.Unmarshal([]byte(cl.RedirectURIs), &rus)
	var plrus []string
	_ = json.Unmarshal([]byte(cl.PostLogoutRedirectURIs), &plrus)
	c.JSON(200, gin.H{
		"client_id":                  cl.ClientID,
		"client_name":                cl.Name,
		"redirect_uris":              rus,
		"post_logout_redirect_uris":  plrus,
		"backchannel_logout_uri":     cl.BackchannelLogoutURI,
		"grant_types":                strings.Split(cl.GrantTypes, ","),
		"response_types":             strings.Split(cl.ResponseTypes, ","),
		"token_endpoint_auth_method": cl.TokenEndpointAuthMethod,
		"subject_type":               cl.SubjectType,
		"sector_identifier_uri":      cl.SectorIdentifierURI,
		"approved":                   cl.Approved,
		"client_secret_expires_at":   0,
		"client_id_issued_at":        cl.CreatedAt.Unix(),
		"registration_client_uri":    h.baseURL(c) + "/register?client_id=" + cl.ClientID,
	})
}

// @Summary      更新已注册客户端
// @Description  使用 registration_access_token 更新客户端元数据
// @Tags         registration
// @Accept       json
// @Produce      json
// @Param        client_id     query string true  "客户端 ID"
// @Param        Authorization header string true "Bearer {registration_access_token}"
// @Param        body          body   object      true "变更字段"
// @Success      204   {string} string "No Content"
// @Failure      400   {object} map[string]string
// @Failure      401   {object} map[string]string
// @Router       /register [put]
func (h *Handler) updateRegisteredClient(c *gin.Context) {
	clientID := c.Query("client_id")
	tok := parseBearer(c.GetHeader("Authorization"))
	if clientID == "" || tok == "" {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	ok, cl, err := h.clientSvc.ValidateRegistrationToken(c, clientID, tok)
	if err != nil || !ok {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	var req struct {
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
		FrontchannelLogoutURI   string   `json:"frontchannel_logout_uri"`
		BackchannelLogoutURI    string   `json:"backchannel_logout_uri"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
		SubjectType             string   `json:"subject_type"`
		SectorIdentifierURI     string   `json:"sector_identifier_uri"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}
	if req.ClientName != "" {
		cl.Name = req.ClientName
	}
	if req.FrontchannelLogoutURI != "" {
		cl.FrontchannelLogoutURI = req.FrontchannelLogoutURI
	}
	if req.BackchannelLogoutURI != "" {
		cl.BackchannelLogoutURI = req.BackchannelLogoutURI
	}
	if req.TokenEndpointAuthMethod != "" {
		cl.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	}
	if req.SubjectType != "" {
		cl.SubjectType = req.SubjectType
	}
	if len(req.RedirectURIs) > 0 {
		if req.SectorIdentifierURI != "" {
			if err := h.clientSvc.ValidateSectorIdentifier(c, req.SectorIdentifierURI, req.RedirectURIs); err != nil {
				c.JSON(400, gin.H{"error": "invalid_client_metadata", "error_description": err.Error()})
				return
			}
		}
		if b, _ := json.Marshal(req.RedirectURIs); true {
			cl.RedirectURIs = string(b)
		}
	}
	if req.SectorIdentifierURI != "" {
		cl.SectorIdentifierURI = req.SectorIdentifierURI
	}
	if len(req.PostLogoutRedirectURIs) > 0 {
		if b, _ := json.Marshal(req.PostLogoutRedirectURIs); true {
			cl.PostLogoutRedirectURIs = string(b)
		}
	}
	if err := h.clientSvc.Save(c, cl); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	c.Status(204)
}

func parseBearer(h string) string {
	parts := strings.SplitN(h, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

// @Summary      禁用已注册客户端
// @Description  使用 registration_access_token 将客户端标记为未批准
// @Tags         registration
// @Produce      json
// @Param        client_id     query string true  "客户端 ID"
// @Param        Authorization header string true "Bearer {registration_access_token}"
// @Success      204   {string} string "No Content"
// @Failure      401   {object} map[string]string
// @Router       /register [delete]
func (h *Handler) deleteRegisteredClient(c *gin.Context) {
	clientID := c.Query("client_id")
	tok := parseBearer(c.GetHeader("Authorization"))
	if clientID == "" || tok == "" {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	ok, cl, err := h.clientSvc.ValidateRegistrationToken(c, clientID, tok)
	if err != nil || !ok {
		c.JSON(401, gin.H{"error": "unauthorized"})
		return
	}
	cl.Approved = false
	if err := h.clientSvc.Save(c, cl); err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	c.Status(204)
}
