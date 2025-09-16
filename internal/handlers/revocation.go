package handlers

import (
	"time"

	"ginkgoid/internal/services"

	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
)

// @Summary      吊销端点（Revocation）
// @Description  撤销访问令牌或刷新令牌
// @Tags         oauth2
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Security     BasicAuth
// @Param        token            formData string true  "要撤销的令牌"
// @Param        token_type_hint  formData string false "access_token|refresh_token"
// @Success      200 {string} string "OK"
// @Failure      401 {object} map[string]string
// @Router       /revoke [post]
func (h *Handler) revoke(c *gin.Context) {
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if !ok {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
	}
	if clientID == "" {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}
	valid, cl, err := h.clientSvc.ValidateSecret(c, clientID, clientSecret)
	if err != nil || !valid {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}
	token := c.PostForm("token")
	hint := c.PostForm("token_type_hint")
	if token == "" {
		c.Status(200)
		return
	}
	if hint == "refresh_token" {
		_ = h.refreshSvc.Delete(c, token)
		ip := c.ClientIP()
		cid := cl.ClientID
		h.logSvc.Write(c, "INFO", "REFRESH_REVOKED", nil, &cid, "refresh token revoked", ip, services.LogWriteOpts{
			RequestID: c.GetString("request_id"),
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			Status:    200,
			UserAgent: c.Request.UserAgent(),
			Outcome:   "success",
		})
		c.Status(200)
		return
	}
	claims := jwt.MapClaims{}
	if _, _, err := new(jwt.Parser).ParseUnverified(token, claims); err == nil {
		jti, _ := claims["jti"].(string)
		expF, _ := claims["exp"].(float64)
		now := time.Now()
		ttl := time.Second * 0
		if expF > 0 {
			if exp := time.Unix(int64(expF), 0); exp.After(now) {
				ttl = exp.Sub(now)
			}
		}
		_ = h.revokeSvc.RevokeAccessToken(c, jti, ttl)
	}
	ip := c.ClientIP()
	cid := cl.ClientID
	h.logSvc.Write(c, "INFO", "ACCESS_REVOKED", nil, &cid, "access token revoked", ip, services.LogWriteOpts{
		RequestID: c.GetString("request_id"),
		Method:    c.Request.Method,
		Path:      c.Request.URL.Path,
		Status:    200,
		UserAgent: c.Request.UserAgent(),
		Outcome:   "success",
	})
	c.Status(200)
}
