package handlers

import (
	"github.com/gin-gonic/gin"
	"strings"
)

// @Summary      用户信息端点（UserInfo）
// @Description  使用 Access Token 获取用户 claims 信息
// @Tags         oidc
// @Produce      json
// @Param        Authorization header string false "Bearer {access_token}"
// @Param        access_token  query  string false "当未设置 Authorization 时可使用"
// @Success      200 {object} map[string]interface{}
// @Failure      401 {object} map[string]string
// @Router       /userinfo [get]
// @Router       /userinfo [post]
func (h *Handler) userinfo(c *gin.Context) {
	setNoCache(c)
	if h.cfg.CORS.EnableUserInfo {
		origin := c.GetHeader("Origin")
		if origin != "" && (len(h.cfg.CORS.AllowedOrigins) == 0 || contains(h.cfg.CORS.AllowedOrigins, origin)) {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
		}
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if c.Request.Method == "OPTIONS" {
			c.Status(204)
			return
		}
	}
	auth := c.GetHeader("Authorization")
	parts := strings.SplitN(auth, " ", 2)
	var tokenStr string
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && parts[1] != "" {
		tokenStr = parts[1]
	} else {
		tokenStr = c.Query("access_token")
		if tokenStr == "" {
			tokenStr = c.PostForm("access_token")
		}
		if tokenStr == "" {
			c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
			c.JSON(401, gin.H{"error": "invalid_token"})
			return
		}
	}
	claims, err := h.tokenSvc.VerifyJWT(tokenStr)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid_token"})
		return
	}
	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)
	if jti, _ := claims["jti"].(string); jti != "" {
		if h.revokeSvc.IsAccessTokenRevoked(c, jti) {
			c.JSON(401, gin.H{"error": "invalid_token"})
			return
		}
	}
	uidF, hasUID := claims["uid"].(float64)
	resp := gin.H{"sub": sub}
	if hasUID {
		uid := uint64(uidF)
		if u, err := h.userSvc.FindByID(c, uid); err == nil {
			if strings.Contains(scope, "profile") {
				if u.Name != "" {
					resp["name"] = u.Name
				}
				if u.Username != "" {
					resp["preferred_username"] = u.Username
				}
				if !u.UpdatedAt.IsZero() {
					resp["updated_at"] = u.UpdatedAt.Unix()
				}
			}
			if strings.Contains(scope, "email") {
				if u.Email != "" {
					resp["email"] = u.Email
				}
				resp["email_verified"] = u.EmailVerified
			}
		}
	}
	c.JSON(200, resp)
}
