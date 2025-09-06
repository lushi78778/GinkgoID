package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"expvar"
	adm "ginkgoid/internal/controller/admin"
	icache "ginkgoid/internal/infra/cache"
	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/infra/logx"
	"ginkgoid/internal/model/entity"
	mw "ginkgoid/internal/server/middleware"
	vld "ginkgoid/internal/server/validate"
	"ginkgoid/internal/service/client"
	"ginkgoid/internal/service/consent"
	"ginkgoid/internal/service/jwk"
	"ginkgoid/internal/service/oidc"
	"ginkgoid/internal/service/revocation"
	"ginkgoid/internal/service/session"
	"ginkgoid/internal/service/user"
	"ginkgoid/internal/utility/passhash"
	"ginkgoid/internal/utility/randx"
	tpl "ginkgoid/resource"
	"github.com/gin-gonic/gin"
)

// NewRouter 初始化并返回 Gin 引擎。
//
// 路由约定：
// - 公共端点：健康检查、Discovery/JWKS、OIDC 链路（/authorize、/token、/userinfo、/logout）；
// - 管理后台页面：/admin/ 前缀（需会话 + CSRF）；
// - 管理后台 API：/admin/api 前缀（JSON 返回，需会话 + CSRF + 严格来源校验）；
// - 静态资源：/assets/...（本地内嵌的 JS/CSS/Font）。
func NewRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(mw.SecurityHeaders())
	r.Use(mw.HSTS())
	// templates (embed FS)
	// Use embedded admin templates to avoid runtime path issues
	if t, err := template.ParseFS(tpl.AdminFS, "templates/admin/*.html", "templates/auth/*.html"); err == nil {
		r.SetHTMLTemplate(t)
	}

	// basic health
	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok"}) })
	// Expose basic runtime/expvar metrics
	r.GET("/debug/vars", gin.WrapH(expvar.Handler()))
	// Minimal /metrics (Prometheus text format subset)
	r.GET("/metrics", metrics)
	r.GET("/readyz", func(c *gin.Context) {
		type probe struct {
			ok  bool
			err string
		}
		out := gin.H{}
		// DB
		dberr := db.G().Exec("SELECT 1").Error
		out["db"] = probe{ok: dberr == nil, err: errString(dberr)}
		// Redis (optional)
		if cache := icache.R(); cache != nil {
			rerr := cache.Ping(context.Background()).Err()
			out["redis"] = probe{ok: rerr == nil, err: errString(rerr)}
		} else {
			out["redis"] = probe{ok: true, err: "disabled"}
		}
		c.JSON(http.StatusOK, out)
	})

	// discovery：公开 OIDC 发现文档
	r.GET("/.well-known/openid-configuration", discovery)
	// service documentation page
	r.GET("/docs", docsPage)
	// public assets for both admin and auth pages (local resources)
	r.GET("/assets/js/*filepath", adm.AssetsJSHandler)
	r.GET("/assets/css/*filepath", adm.AssetsCSSHandler)
	r.GET("/assets/font/*filepath", adm.AssetsFontHandler)

	// jwks (stub for now)
	r.GET("/jwks.json", jwks)

	// login：用户名/密码登录，表单提交（application/x-www-form-urlencoded）
	r.GET("/login", getLogin)
	allowed := buildAllowedOrigins()
	// token bucket: capacity per minute, refill per second
	r.POST("/login", mw.RateLimitTokenBucket(mw.RLKeyByIPUser("login"), config.C().Security.LoginRatePerMin, float64(config.C().Security.LoginRatePerMin)/60.0), mw.CheckOriginRefererSoft(allowed), postLogin)

	// oauth endpoints：OIDC 核心端点
	r.GET("/authorize", authorize)
	r.GET("/consent", getConsent)
	r.POST("/token", mw.RateLimitTokenBucket(mw.RLKeyByClientIP("token"), config.C().Security.TokenRatePerMin, float64(config.C().Security.TokenRatePerMin)/60.0), mw.CheckOriginRefererSoft(allowed), token)
	r.GET("/userinfo", userinfo)
	r.POST("/consent", mw.CheckOriginRefererSoft(allowed), postConsent)
	r.GET("/logout", logout)
	// RFC endpoints
	r.POST("/oauth2/introspect", introspect)
	r.POST("/oauth2/revoke", revoke)
	// no test routes

	// admin pages：管理后台页面（受会话保护）。
	// 仅渲染内嵌模板，不对外暴露任意目录列表。

	adminp := r.Group("/admin", mw.AdminPageRequired(), mw.EnsureCSRFCookie())
	{
		adminp.GET("/", adm.IndexPage)
		adminp.GET("/clients", adm.ClientsPage)
		adminp.GET("/users", adm.UsersPage)
		adminp.GET("/consents", adm.ConsentsPage)
		adminp.GET("/jwks", adm.JWKSPage)
		adminp.GET("/logout", adm.Logout)
		adminp.GET("/ui/*filepath", adm.UIHandler)
	}

	// production: no public test/admin static exposures

	// admin APIs：管理后台 JSON API（需会话 + CSRF + 严格来源校验）。
	// 统一返回：{"code":0,"message":"ok","data":...}
	admin := r.Group("/admin/api", mw.AdminRequired(), mw.EnsureCSRFCookie(), mw.CSRF(), mw.CheckOriginRefererStrict(allowed))
	{
		admin.GET("/ping", adm.Ping)
		admin.GET("/clients", adm.ListClients)
		admin.GET("/clients/table", adm.ListClientsTable)
		admin.POST("/clients", adm.CreateClient)
		admin.PUT("/clients/:id", adm.UpdateClient)
		admin.PATCH("/clients/:id/status", adm.PatchClientStatus)

		admin.GET("/users", adm.ListUsers)
		admin.GET("/users/table", adm.ListUsersTable)
		admin.POST("/users", adm.CreateUser)
		admin.PATCH("/users/:id/password", adm.PatchUserPassword)
		admin.PATCH("/users/:id/email", adm.PatchUserEmail)
		admin.PATCH("/users/:id/role", adm.PatchUserRole)
		admin.POST("/users/:id/sessions/revoke_all", adm.RevokeUserSessions)

		admin.GET("/consents", adm.ListConsents)
		admin.GET("/consents/table", adm.ListConsentsTable)
		admin.DELETE("/consents/:id", adm.DeleteConsent)

		admin.GET("/jwks", adm.ListJWKS)
		admin.POST("/jwks/rotate", adm.RotateJWK)

		// token revocation
		admin.POST("/tokens/revoke_access", adm.RevokeAccess)
		admin.POST("/tokens/revoke_jti", adm.RevokeJTI)
		admin.GET("/tokens/status", adm.TokenStatus)
	}

	return r
}

// discovery 输出 OIDC 发现文档。issuer/端点均基于配置的 oidc.issuer 拼装。
func discovery(c *gin.Context) {
	cfg := config.C()
	issuer := cfg.OIDC.Issuer
	base := issuer
	resp := gin.H{
		"issuer":                                      issuer,
		"authorization_endpoint":                      base + "/authorize",
		"token_endpoint":                              base + "/token",
		"userinfo_endpoint":                           base + "/userinfo",
		"end_session_endpoint":                        base + "/logout",
		"jwks_uri":                                    base + "/jwks.json",
		"response_types_supported":                    []string{"code"},
		"grant_types_supported":                       []string{"authorization_code"},
		"code_challenge_methods_supported":            []string{"S256"},
		"id_token_signing_alg_values_supported":       []string{"RS256", "ES256"},
		"scopes_supported":                            cfg.OIDC.Scopes,
		"subject_types_supported":                     []string{"public"},
		"token_endpoint_auth_methods_supported":       []string{"client_secret_basic", "client_secret_post"},
		"request_object_signing_alg_values_supported": []string{"RS256", "ES256"},
		"service_documentation":                       base + "/docs",
		"claims_supported":                            []string{"sub", "name", "email", "email_verified"},
		"ttl_hint": gin.H{
			"id_token_ttl":     cfg.OIDC.IDTokenTTL,
			"access_token_ttl": cfg.OIDC.AccessTokenTTL,
		},
		"now": time.Now().UTC().Format(time.RFC3339),
	}
	c.JSON(http.StatusOK, resp)
}

// jwks 返回当前激活与灰度中的公钥列表（用于 RP 验签）。
func jwks(c *gin.Context) {
	keys, err := jwk.JWKS(context.Background())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "jwks_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

// metrics 暴露最小化 Prometheus 文本格式指标（无第三方依赖）。
func metrics(c *gin.Context) {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	// quick health checks (best-effort)
	dbok := 1
	if err := db.G().Exec("SELECT 1").Error; err != nil {
		dbok = 0
	}
	redok := 0
	if r := icache.R(); r != nil {
		if err := r.Ping(context.Background()).Err(); err == nil {
			redok = 1
		}
	}
	c.Header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(c.Writer, "# HELP ginkgoid_up Service liveness\n")
	fmt.Fprintf(c.Writer, "# TYPE ginkgoid_up gauge\n")
	fmt.Fprintf(c.Writer, "ginkgoid_up 1\n")
	fmt.Fprintf(c.Writer, "# HELP ginkgoid_db_up Database ping status\n# TYPE ginkgoid_db_up gauge\n")
	fmt.Fprintf(c.Writer, "ginkgoid_db_up %d\n", dbok)
	fmt.Fprintf(c.Writer, "# HELP ginkgoid_redis_up Redis ping status\n# TYPE ginkgoid_redis_up gauge\n")
	fmt.Fprintf(c.Writer, "ginkgoid_redis_up %d\n", redok)
	fmt.Fprintf(c.Writer, "# HELP ginkgoid_goroutines Number of goroutines\n# TYPE ginkgoid_goroutines gauge\n")
	fmt.Fprintf(c.Writer, "ginkgoid_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(c.Writer, "# HELP ginkgoid_mem_alloc_bytes Process memory allocation\n# TYPE ginkgoid_mem_alloc_bytes gauge\n")
	fmt.Fprintf(c.Writer, "ginkgoid_mem_alloc_bytes %d\n", ms.Alloc)
}

// docsPage 渲染项目的简版使用文档。
func docsPage(c *gin.Context) {
	cfg := config.C()
	issuer := cfg.OIDC.Issuer
	base := issuer
	c.HTML(http.StatusOK, "docs.html", gin.H{
		"issuer": issuer,
		"base":   base,
	})
}

// buildAllowedOrigins 仅基于 issuer 生成允许的 Origin 列表。
func buildAllowedOrigins() []string {
	iss := config.C().OIDC.Issuer
	if u, err := url.Parse(iss); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		return []string{u.Scheme + "://" + u.Host}
	}
	return nil
}

// errString 将错误转为字符串，nil 返回空串。
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// getLogin 渲染登录页模板。
func getLogin(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"continue":    c.Query("continue"),
		"privacy_url": config.C().Admin.PrivacyURL,
		"terms_url":   config.C().Admin.TermsURL,
	})
}

// getConsent 渲染同意页：当用户尚未针对客户端与所请求 scope 给出授权时触发。
func getConsent(c *gin.Context) {
	ctx := context.Background()
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	scope := c.Query("scope")
	state := c.Query("state")
	nonce := c.Query("nonce")
	codeChallenge := c.Query("code_challenge")
	method := c.Query("code_challenge_method")

	// session required
	// 会话必需：无会话则跳回登录并携带当前 URL
	sid, err := c.Cookie(session.CookieName)
	if err != nil || sid == "" {
		c.Redirect(http.StatusFound, "/login?continue="+url.QueryEscape(c.Request.URL.RequestURI()))
		return
	}
	ss, err := session.Get(ctx, sid)
	if err != nil {
		c.Redirect(http.StatusFound, "/login?continue="+url.QueryEscape(c.Request.URL.RequestURI()))
		return
	}

	// 客户端及 redirect_uri 校验
	cli, err := client.Get(ctx, clientID)
	if err != nil || !client.IsRedirectAllowed(cli, redirectURI) {
		c.String(http.StatusBadRequest, "invalid_client_or_redirect")
		return
	}

	c.HTML(http.StatusOK, "consent.html", gin.H{
		"client_id":             clientID,
		"client_name":           cli.Name,
		"redirect_uri":          redirectURI,
		"state":                 state,
		"nonce":                 nonce,
		"scope":                 scope,
		"scopes":                strings.Fields(scope),
		"code_challenge":        codeChallenge,
		"code_challenge_method": method,
		"sid":                   sid,
		"privacy_url":           config.C().Admin.PrivacyURL,
		"terms_url":             config.C().Admin.TermsURL,
		"remember_default":      config.C().Consent.RememberDefault,
		"user_id":               ss.UserID,
	})
}

// postLogin 处理登录表单提交，成功后建立会话并可按 continue 参数跳转。
func postLogin(c *gin.Context) {
	// Single scheme: application/x-www-form-urlencoded
	username := c.PostForm("username")
	password := c.PostForm("password")
	cont := c.PostForm("continue")
	logx.L().Info("login attempt", logx.String("ct", strings.ToLower(c.GetHeader("Content-Type"))), logx.String("username", username), logx.String("ip", c.ClientIP()))
	ctx := context.Background()

	// 查找用户（仅启用中）
	u, err := user.GetByUsername(ctx, username)
	if err != nil {
		logx.L().Info("login user not found", logx.String("username", username), logx.Err(err))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
		return
	}
	ok, verr := passhash.Verify(password, u.PasswordHash)
	if !ok {
		hpfx := u.PasswordHash
		if len(hpfx) > 24 {
			hpfx = hpfx[:24]
		}
		logx.L().Info("login password verify failed", logx.String("username", username), logx.String("hash_prefix", hpfx), logx.String("verify_err", errString(verr)))
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_credentials"})
		return
	}
	// 防会话固定：若已有旧 SID，先撤销
	if old, _ := c.Cookie(session.CookieName); old != "" {
		_ = session.Revoke(ctx, old)
	}
	sid, err := session.Create(ctx, u.ID, c.Request.UserAgent(), c.ClientIP(), 24*time.Hour)
	if err != nil {
		logx.L().Error("login session create error", logx.Err(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	session.SetCookie(c, sid, 24*time.Hour)
	if tok, err := randx.ID(24); err == nil {
		c.SetCookie(mw.CSRFCookieName, tok, int((24 * time.Hour).Seconds()), "/", config.C().Server.CookieDomain, config.C().Server.SecureCookies, false)
	}
	if cont != "" {
		c.Redirect(http.StatusFound, cont)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ok"})
}

// authorize 处理授权请求：参数校验 → 客户端/回调校验 → 登录/同意校验 → 签发授权码。
func authorize(c *gin.Context) {
	ctx := context.Background()
	q := c.Request.URL.Query()
	ap, err := vld.ParseAuthorize(q, config.C().OIDC.ForceNonce, config.C().OIDC.ForcePKCE)
	if err == vld.ErrUnsupportedResponseType { // 只支持 response_type=code
		returnErrorRedirect(c, q.Get("redirect_uri"), "unsupported_response_type", "", q.Get("state"))
		return
	}
	if err == vld.ErrInvalidScope { // 必须包含 openid
		returnErrorRedirect(c, q.Get("redirect_uri"), "invalid_scope", "missing openid scope", q.Get("state"))
		return
	}
	if err != nil { // 其他无效参数
		returnErrorRedirect(c, q.Get("redirect_uri"), "invalid_request", "", q.Get("state"))
		return
	}
	cli, err := client.Get(ctx, ap.ClientID)
	if err != nil || !client.IsRedirectAllowed(cli, ap.RedirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_or_redirect"})
		return
	}
	// check session
	// 需要有效会话，未登录则先去登录
	sid, err := c.Cookie(session.CookieName)
	if err != nil || sid == "" {
		cont := url.URL{Path: "/authorize", RawQuery: c.Request.URL.RawQuery}
		c.Redirect(http.StatusFound, "/login?continue="+url.QueryEscape(cont.String()))
		return
	}
	ss, err := session.Get(ctx, sid)
	if err != nil {
		cont := url.URL{Path: "/authorize", RawQuery: c.Request.URL.RawQuery}
		c.Redirect(http.StatusFound, "/login?continue="+url.QueryEscape(cont.String()))
		return
	}
	scopes := strings.Fields(ap.Scope)
	// 判断是否已有同意记录
	has, err := consent.HasConsent(ctx, ss.UserID, ap.ClientID, scopes)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if !has {
		if config.C().Consent.RememberDefault {
			_ = consent.Save(ctx, ss.UserID, ap.ClientID, scopes, true)
		} else {
			v := url.Values{}
			v.Set("client_id", ap.ClientID)
			v.Set("redirect_uri", ap.RedirectURI)
			v.Set("state", ap.State)
			v.Set("nonce", ap.Nonce)
			v.Set("scope", ap.Scope)
			v.Set("code_challenge", ap.CodeChallenge)
			v.Set("code_challenge_method", ap.CodeChallengeMethod)
			c.Redirect(http.StatusFound, "/consent?"+v.Encode()) // 引导至同意页
			return
		}
	}
	issueCodeRedirect(c, ss, ap.ClientID, ap.RedirectURI, scopes, ap.Nonce, ap.CodeChallenge, ap.CodeChallengeMethod, ap.State)
}

func token(c *gin.Context) {
	// Basic validation
	tp, perr := vld.ParseTokenForm(c.Request.PostForm)
	if perr != nil {
		// 无效的表单：grant_type/code/redirect_uri/code_verifier 缺失或不合规
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	// client auth (basic or post)
	clientID, clientSecret, _ := c.Request.BasicAuth()
	if clientID == "" {
		clientID = tp.ClientID
		clientSecret = tp.ClientSecret
	}
	ctx := context.Background()
	cli, err := client.Get(ctx, clientID)
	if err != nil {
		// 未找到或禁用的客户端
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}
	// If secret exists, verify; otherwise public client
	if cli.SecretHash != nil && *cli.SecretHash != "" {
		ok, _ := client.CheckSecret(ctx, cli, clientSecret)
		if !ok {
			// 机密客户端口令错误
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
	}
	// Load auth_code
	var ac entity.AuthCode
	ch := sha256.Sum256([]byte(tp.Code))
	chs := fmt.Sprintf("%x", ch[:])
	err = dbGetAuthCode(ctx, chs, &ac)
	if err != nil {
		// 授权码不存在
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	if ac.Used || time.Now().After(ac.ExpireAt) {
		// 授权码已用或过期
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	if ac.ClientID != clientID || ac.RedirectURI != tp.RedirectURI {
		// 客户端/回调地址不匹配（重放或伪造）
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
		return
	}
	// PKCE verify
	sum := sha256.Sum256([]byte(tp.CodeVerifier))
	calc := base64.RawURLEncoding.EncodeToString(sum[:])
	if ac.Method != "S256" || ac.CodeChallenge != calc {
		// PKCE 校验失败：code_verifier 与存储的 code_challenge 不一致
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "pkce mismatch"})
		return
	}
	// Mark used (best-effort)
	_ = dbMarkCodeUsed(ctx, chs)
	// scopes
	var scopes []string
	_ = json.Unmarshal([]byte(ac.Scope), &scopes)
	// tokens
	pair, err := oidc.SignTokens(ctx, ac.UserID, clientID, scopes, ac.Nonce, ac.AuthTime)
	if err != nil {
		// 签发失败：通常是密钥或配置异常
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token_type": "Bearer", "expires_in": pair.ExpiresIn, "access_token": pair.AccessToken, "id_token": pair.IDToken})
}

// userinfo 返回最小化用户信息，字段受 scope 控制。
func userinfo(c *gin.Context) {
	auth := c.GetHeader("Authorization")
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") { // 必须携带 Bearer
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	tok := strings.TrimSpace(auth[7:])
	ctx := context.Background()
	t, err := oidc.VerifyAccessToken(ctx, tok) // 验签 + 撤销检查
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
		return
	}
	subVal, _ := t.Get("sub")
	subStr, _ := subVal.(string)
	uid := parseSub(subStr)
	scopes := parseScopesFromToken(t)
	// base claims
	resp := gin.H{"sub": subStr}
	if contains(scopes, "profile") {
		if u, err := user.GetByID(ctx, uid); err == nil {
			resp["name"] = u.Username
		}
	}
	if contains(scopes, "email") {
		if u, err := user.GetByID(ctx, uid); err == nil {
			if u.Email != nil {
				resp["email"] = *u.Email
			} else {
				resp["email"] = ""
			}
			resp["email_verified"] = u.EmailVerified
		}
	}
	c.JSON(http.StatusOK, resp)
}

// introspect 实现 OAuth 2.0 Token Introspection（RFC 7662）。
func introspect(c *gin.Context) {
	// client auth
	clientID, clientSecret, _ := c.Request.BasicAuth()
	if clientID == "" {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
	}
	ctx := context.Background()
	cli, err := client.Get(ctx, clientID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}
	if cli.SecretHash != nil && *cli.SecretHash != "" {
		ok, _ := client.CheckSecret(ctx, cli, clientSecret)
		if !ok {
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
	}
	tok := c.PostForm("token")
	if tok == "" {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}
	t, err := oidc.VerifyJWT(ctx, tok)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}
	// revocation check
	if jv, ok := t.Get("jti"); ok {
		if jti, _ := jv.(string); jti != "" {
			if revoked, _ := revocation.IsRevoked(ctx, jti); revoked {
				c.JSON(http.StatusOK, gin.H{"active": false})
				return
			}
		}
	}
	// build response
	resp := gin.H{"active": true}
	if sub, ok := t.Get("sub"); ok {
		resp["sub"] = sub
	}
	if aud, ok := t.Get("aud"); ok {
		resp["aud"] = aud
	}
	if sc, ok := t.Get("scope"); ok {
		resp["scope"] = sc
	}
	if iss, ok := t.Get("iss"); ok {
		resp["iss"] = iss
	}
	if iat, ok := t.Get("iat"); ok {
		if tt, ok2 := iat.(time.Time); ok2 {
			resp["iat"] = tt.Unix()
		}
	}
	if exp, ok := t.Get("exp"); ok {
		if tt, ok2 := exp.(time.Time); ok2 {
			resp["exp"] = tt.Unix()
		}
	}
	c.JSON(http.StatusOK, resp)
}

// revoke 实现 OAuth 2.0 Token Revocation（RFC 7009）。
func revoke(c *gin.Context) {
	// client auth
	clientID, clientSecret, _ := c.Request.BasicAuth()
	if clientID == "" {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
	}
	ctx := context.Background()
	cli, err := client.Get(ctx, clientID)
	if err != nil {
		c.Status(http.StatusOK)
		return
	}
	if cli.SecretHash != nil && *cli.SecretHash != "" {
		ok, _ := client.CheckSecret(ctx, cli, clientSecret)
		if !ok {
			c.Status(http.StatusOK)
			return
		}
	}
	tok := c.PostForm("token")
	if tok != "" {
		// 解析 jti 与 exp 并入撤销黑名单
		_, _ = revocation.RevokeAccessToken(ctx, tok)
	}
	c.Status(http.StatusOK)
}

// issueCodeRedirect 生成一次性授权码（仅保存哈希）并 302 回调到 redirect_uri。
func issueCodeRedirect(c *gin.Context, ss *entity.Session, clientID, redirectURI string, scopes []string, nonce, challenge, method, state string) {
	// build code and store hash
	raw, _ := randx.ID(32)
	sum := sha256.Sum256([]byte(raw))
	codeHashHex := fmt.Sprintf("%x", sum[:])
	scb, _ := json.Marshal(scopes)
	ac := entity.AuthCode{CodeHash: codeHashHex, ClientID: clientID, UserID: ss.UserID, RedirectURI: redirectURI, Scope: string(scb), Nonce: nonce, CodeChallenge: challenge, Method: method, AuthTime: time.Now().Unix(), ExpireAt: time.Now().Add(2 * time.Minute), Used: false}
	_ = dbSaveAuthCode(c, &ac) // 容错保存，不阻断主流程
	// redirect
	v := url.Values{}
	v.Set("code", raw)
	v.Set("state", state)
	loc := redirectURI
	if strings.Contains(redirectURI, "?") {
		loc += "&" + v.Encode()
	} else {
		loc += "?" + v.Encode()
	}
	c.Redirect(http.StatusFound, loc)
}

// returnErrorRedirect 将 OAuth 错误以查询串形式附加到回调地址；若缺失回调地址则直接 JSON 响应。
func returnErrorRedirect(c *gin.Context, redirectURI, errCode, desc, state string) {
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": errCode, "error_description": desc})
		return
	}
	v := url.Values{}
	v.Set("error", errCode)
	if desc != "" {
		v.Set("error_description", desc)
	}
	if state != "" {
		v.Set("state", state)
	}
	loc := redirectURI
	if strings.Contains(redirectURI, "?") {
		loc += "&" + v.Encode()
	} else {
		loc += "?" + v.Encode()
	}
	c.Redirect(http.StatusFound, loc)
}

// logout 清除 OP 侧会话，可选校验 id_token_hint 并按白名单回跳。
func logout(c *gin.Context) {
	ctx := context.Background()
	idToken := c.Query("id_token_hint")
	postLogout := c.Query("post_logout_redirect_uri")
	state := c.Query("state")

	// Always clear OP session cookie and DB session when present
	if sid, err := c.Cookie(session.CookieName); err == nil && sid != "" {
		_ = session.Revoke(ctx, sid)
		session.ClearCookie(c)
	}

	if idToken != "" {
		t, err := oidc.VerifyJWT(ctx, idToken)
		if err == nil {
			// Validate iss/aud/sub presence
			audVal, _ := t.Get("aud")
			clientID := firstAud(audVal)
			// If redirect provided, must be whitelisted
			if clientID != "" && postLogout != "" {
				if cli, err := client.Get(ctx, clientID); err == nil && client.IsLogoutRedirectAllowed(cli, postLogout) {
					v := url.Values{}
					if state != "" {
						v.Set("state", state)
					}
					loc := postLogout
					if strings.Contains(loc, "?") {
						loc += "&" + v.Encode()
					} else if len(v) > 0 {
						loc += "?" + v.Encode()
					}
					c.Redirect(http.StatusFound, loc)
					return
				}
			}
		}
	}
	// Default: 200 page
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<html><body><h3>Logged out</h3></body></html>"))
}

// firstAud 解析 aud，返回第一个受众（兼容数组/字符串）。
func firstAud(a any) string {
	switch v := a.(type) {
	case string:
		return v
	case []string:
		if len(v) > 0 {
			return v[0]
		}
	case []any:
		if len(v) > 0 {
			if s, ok := v[0].(string); ok {
				return s
			}
		}
	}
	return ""
}

// parseScopesFromToken 从 JWT 的 scope 字段解析空格分隔的 scope 列表。
func parseScopesFromToken(t any) []string {
	tok, ok := t.(interface {
		Get(string) (interface{}, bool)
	})
	if !ok {
		return nil
	}
	v, _ := tok.Get("scope")
	s, _ := v.(string)
	if s == "" {
		return nil
	}
	return strings.Fields(s)
}

// contains 判断字符串列表是否包含目标值。
func contains(list []string, target string) bool {
	for _, x := range list {
		if x == target {
			return true
		}
	}
	return false
}

// parseSub 解析形如 u_123 的 subject，返回数值 ID。
func parseSub(sub string) uint64 {
	if !strings.HasPrefix(sub, "u_") {
		return 0
	}
	var id uint64
	// simple decimal parse
	for i := 2; i < len(sub); i++ {
		ch := sub[i]
		if ch < '0' || ch > '9' {
			break
		}
		id = id*10 + uint64(ch-'0')
	}
	return id
}

// dbSaveAuthCode 保存授权码记录。
func dbSaveAuthCode(c *gin.Context, ac *entity.AuthCode) error {
	return db.G().WithContext(c.Request.Context()).Create(ac).Error
}

// dbGetAuthCode 根据哈希查询授权码记录。
func dbGetAuthCode(ctx context.Context, codeHash string, ac *entity.AuthCode) error {
	return db.G().WithContext(ctx).Where("code_hash = ?", codeHash).First(ac).Error
}

// dbMarkCodeUsed 将授权码标记为已使用。
func dbMarkCodeUsed(ctx context.Context, codeHash string) error {
	return db.G().WithContext(ctx).Model(&entity.AuthCode{}).Where("code_hash = ?", codeHash).Update("used", true).Error
}

// helpers —— 模板输出的最小工具
func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;").Replace(s)
}
func hidden(k, v string) string {
	return `<input type="hidden" name="` + k + `" value="` + htmlEscape(v) + `"/>`
}

// postConsent 处理同意表单提交，保存/更新同意记录后直接签发授权码并回跳。
func postConsent(c *gin.Context) {
	ctx := context.Background()
	clientID := c.PostForm("client_id")
	redirectURI := c.PostForm("redirect_uri")
	state := c.PostForm("state")
	nonce := c.PostForm("nonce")
	scope := c.PostForm("scope")
	codeChallenge := c.PostForm("code_challenge")
	method := c.PostForm("code_challenge_method")
	remember := c.PostForm("remember") == "1"
	// session
	sid, err := c.Cookie(session.CookieName)
	if err != nil || sid == "" {
		sid = c.PostForm("sid")
	}
	if sid == "" {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	ss, err := session.Get(ctx, sid)
	if err != nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}
	scopes := strings.Fields(scope)
	_ = consent.Save(ctx, ss.UserID, clientID, scopes, remember)
	issueCodeRedirect(c, ss, clientID, redirectURI, scopes, nonce, codeChallenge, method, state)
}
