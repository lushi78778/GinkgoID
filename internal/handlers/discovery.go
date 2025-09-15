package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"ginkgoid/internal/handlers/oidc"
	"ginkgoid/internal/metrics"
)

// @Summary      OIDC Discovery
// @Description  获取 OpenID Provider 的元数据文档
// @Tags         .well-known
// @Produce      json
// @Success      200 {object} oidc.Discovery
// @Router       /.well-known/openid-configuration [get]
// @Router       /.well-known/oauth-authorization-server [get]
func (h *Handler) discovery(c *gin.Context) {
	issuer := h.cfg.Issuer
	d := oidc.Discovery{
		Issuer:                 issuer,
		AuthorizationEndpoint:  issuer + "/authorize",
		TokenEndpoint:          issuer + "/token",
		UserInfoEndpoint:       issuer + "/userinfo",
		JWKSURI:                issuer + "/jwks.json",
		ResponseTypesSupported: []string{"code", "code id_token"},
		ResponseModesSupported: []string{"query", "form_post", "fragment"},
		SubjectTypesSupported: func() []string {
			if h.cfg.Pairwise.Enable {
				return []string{"public", "pairwise"}
			}
			return []string{"public"}
		}(),
		IDTokenSigningAlgValuesSupported:  []string{"RS256", "ES256"},
		ScopesSupported:                   []string{"openid", "profile", "email"},
		ClaimsSupported:                   []string{"sub", "name", "email", "email_verified", "given_name", "family_name"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported: func() []string {
			if h.cfg.Token.RequirePKCES256 {
				return []string{"S256"}
			}
			return []string{"S256", "plain"}
		}(),
		GrantTypesSupported:          []string{"authorization_code", "refresh_token"},
		RegistrationEndpoint:         issuer + "/register",
		RevocationEndpoint:           issuer + "/revoke",
		IntrospectionEndpoint:        issuer + "/introspect",
		EndSessionEndpoint:           issuer + "/logout",
		CheckSessionIframe:           issuer + "/check_session",
		AcrValuesSupported:           []string{"urn:op:auth:pwd", "urn:op:auth:otp"},
		PromptValuesSupported:        []string{"none", "login", "consent"},
		ClaimsParameterSupported:     false,
		RequestParameterSupported:    false,
		RequestURIParameterSupported: false,
	}
	c.Header("Revocation-Endpoint", issuer+"/revoke")
	c.Header("Introspection-Endpoint", issuer+"/introspect")
	b := true
	d.BackchannelLogoutSupported = &b
	d.BackchannelLogoutSessionSupported = &b
	d.FrontchannelLogoutSupported = &b
	d.FrontchannelLogoutSessionSupported = &b
	setNoCache(c)
	c.JSON(http.StatusOK, d)
}

// @Summary      JWKS 公钥集合
// @Description  返回用于验证 ID Token/Access Token 的公钥集合（JWK Set）
// @Tags         .well-known
// @Produce      json
// @Success      200 {string} string "JWKS JSON"
// @Router       /jwks.json [get]
func (h *Handler) jwks(c *gin.Context) {
	setNoCache(c)
	js, err := h.keySvc.JWKS(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "jwks_error"})
		return
	}
	c.Data(http.StatusOK, "application/json", js)
}

// @Summary      Prometheus 指标
// @Description  暴露 Prometheus 指标（text/plain; version=0.0.4）
// @Tags         ops
// @Produce      plain
// @Success      200 {string} string
// @Router       /metrics [get]
func (h *Handler) metrics(c *gin.Context) { metrics.Exposer()(c) }

// @Summary      健康检查
// @Tags         ops
// @Produce      json
// @Success      200 {object} map[string]string
// @Router       /healthz [get]
func (h *Handler) healthz(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) }
