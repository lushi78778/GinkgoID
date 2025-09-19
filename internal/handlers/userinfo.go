package handlers

import (
	"strings"

	"github.com/gin-gonic/gin"

	"ginkgoid/internal/services"
)

// @Summary      用户信息端点（UserInfo）
// @Description  使用 Access Token 获取用户 claims 信息
// @Tags         oidc
// @Produce      json
// @Security     BearerAuth
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
	scheme := ""
	if len(parts) == 2 && parts[1] != "" {
		scheme = parts[0]
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
	// 最小 DPoP 校验：当使用 DPoP 授权方案时，验证请求头 DPoP 与 access_token 的 cnf.jkt 一致
	if strings.EqualFold(scheme, "DPoP") {
		proof := c.GetHeader("DPoP")
		res, perr := h.dpopVerifier.Verify(c.Request.Context(), proof, c.Request.Method, c.Request.URL.String())
		if perr != nil {
			h.logSvc.Write(c, "WARN", "DPoP_MISSING_OR_INVALID", nil, nil, "userinfo dpop missing/invalid", c.ClientIP(), services.LogWriteOpts{
				RequestID: c.GetString("request_id"),
				Method:    c.Request.Method,
				Path:      c.Request.URL.Path,
				Status:    401,
				UserAgent: c.Request.UserAgent(),
				Outcome:   "failure",
				ErrorCode: "invalid_dpop",
				Extra:     map[string]any{"error": perr.Error()},
			})
			c.Header("WWW-Authenticate", "DPoP error=\"invalid_dpop\"")
			c.JSON(401, gin.H{"error": "invalid_token"})
			return
		}
		if cnf, ok := claims["cnf"].(map[string]any); ok {
			if jktExpected, ok2 := cnf["jkt"].(string); ok2 && jktExpected != "" {
				if res.JKT != jktExpected {
					h.logSvc.Write(c, "WARN", "DPoP_JKT_MISMATCH", nil, nil, "userinfo jkt mismatch", c.ClientIP(), services.LogWriteOpts{
						RequestID: c.GetString("request_id"),
						Method:    c.Request.Method,
						Path:      c.Request.URL.Path,
						Status:    401,
						UserAgent: c.Request.UserAgent(),
						Outcome:   "failure",
						ErrorCode: "invalid_dpop",
						Extra:     map[string]any{"expected": jktExpected, "actual": res.JKT},
					})
					c.Header("WWW-Authenticate", "DPoP error=\"invalid_dpop\"")
					c.JSON(401, gin.H{"error": "invalid_token"})
					return
				}
			}
		}
		h.logSvc.Write(c, "INFO", "DPoP_VERIFIED", nil, nil, "userinfo dpop verified", c.ClientIP(), services.LogWriteOpts{
			RequestID: c.GetString("request_id"),
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			Status:    200,
			UserAgent: c.Request.UserAgent(),
			Outcome:   "success",
		})
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
