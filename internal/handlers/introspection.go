package handlers

import (
	"time"

	"github.com/gin-gonic/gin"
)

// @Summary      内省端点（Introspection）
// @Description  返回访问令牌的有效性与基础元信息
// @Tags         oauth2
// @Accept       x-www-form-urlencoded
// @Produce      json
// @Security     BasicAuth
// @Param        token  formData string true  "要内省的令牌"
// @Success      200 {object} map[string]interface{} "{ active: bool, ... }"
// @Failure      401 {object} map[string]string
// @Router       /introspect [post]
func (h *Handler) introspect(c *gin.Context) {
	clientID, clientSecret, ok := c.Request.BasicAuth()
	if !ok {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
	}
	if clientID == "" {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}
	valid, _, err := h.clientSvc.ValidateSecret(c, clientID, clientSecret)
	if err != nil || !valid {
		c.JSON(401, gin.H{"error": "invalid_client"})
		return
	}
	token := c.PostForm("token")
	if token == "" {
		c.JSON(200, gin.H{"active": false})
		return
	}
	claims, err := h.tokenSvc.VerifyJWT(token)
	if err != nil {
		c.JSON(200, gin.H{"active": false})
		return
	}
	now := time.Now().Unix()
	expF, _ := claims["exp"].(float64)
	if expF != 0 && int64(expF) <= now {
		c.JSON(200, gin.H{"active": false})
		return
	}
	if jti, _ := claims["jti"].(string); jti != "" {
		if h.revokeSvc.IsAccessTokenRevoked(c, jti) {
			c.JSON(200, gin.H{"active": false})
			return
		}
	}
	aud := claims["aud"]
	scope, _ := claims["scope"].(string)
	sub, _ := claims["sub"].(string)
	iat, _ := claims["iat"].(float64)
	iss, _ := claims["iss"].(string)
	jti, _ := claims["jti"].(string)
	tokClientID, _ := claims["client_id"].(string)
	resp := gin.H{
		"active": true,
		"scope":  scope,
		"client_id": func() string {
			if tokClientID != "" {
				return tokClientID
			}
			if s, ok := aud.(string); ok {
				return s
			}
			return clientID
		}(),
		"username":   sub,
		"token_type": "access_token",
		"exp":        int64(expF),
		"iat":        int64(iat),
		"iss":        iss,
		"aud":        aud,
		"sub":        sub,
		"jti":        jti,
	}
	c.JSON(200, resp)
}
