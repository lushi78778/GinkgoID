package handlers

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "strconv"
    "strings"
    "time"

    jwt "github.com/golang-jwt/jwt/v5"
    "github.com/gin-gonic/gin"
    "github.com/go-redis/redis/v8"
    "golang.org/x/crypto/bcrypt"

    "ginkgoid/internal/config"
    "ginkgoid/internal/handlers/oidc"
    "ginkgoid/internal/middlewares"
    "ginkgoid/internal/metrics"
    "ginkgoid/internal/services"
    "ginkgoid/internal/storage"
    "ginkgoid/internal/utils"
)

// Handler 聚合所有依赖（配置、存储、服务）并注册所有 HTTP 路由。
type Handler struct {
    cfg        config.Config
    keySvc     *services.KeyService
    clientSvc  *services.ClientService
    userSvc    *services.UserService
    sessionSvc *services.SessionService
    tokenSvc   *services.TokenService
    codeSvc    *services.CodeService
    consentSvc *services.ConsentService
    refreshSvc *services.RefreshService
    revokeSvc  *services.RevocationService
    logSvc     *services.LogService
    tokenRepo  *services.TokenRepo
    rdb        *redis.Client
}

// New 构造 Handler，将各领域服务注入，用于后续路由注册与处理。
func New(cfg config.Config, ks *services.KeyService, cs *services.ClientService, us *services.UserService, ss *services.SessionService, ts *services.TokenService, codes *services.CodeService, cons *services.ConsentService, rs *services.RefreshService, rv *services.RevocationService, ls *services.LogService, tr *services.TokenRepo, rdb *redis.Client) *Handler {
    return &Handler{cfg: cfg, keySvc: ks, clientSvc: cs, userSvc: us, sessionSvc: ss, tokenSvc: ts, codeSvc: codes, consentSvc: cons, refreshSvc: rs, revokeSvc: rv, logSvc: ls, tokenRepo: tr, rdb: rdb}
}

// RegisterRoutes 在 Gin 路由上挂载 OP 的全部端点（Discovery、JWKS、动态注册、授权、令牌、用户信息、注销等）。
func (h *Handler) RegisterRoutes(r *gin.Engine) {
    // 模板：登录页、授权同意页、前端通道注销页
    r.LoadHTMLGlob("web/templates/*")

    // Discovery & JWKS（公开元数据与公钥）
    r.GET("/.well-known/openid-configuration", h.discovery)
    // OAuth Authorization Server 元数据别名
    r.GET("/.well-known/oauth-authorization-server", h.discovery)
    r.GET("/jwks.json", h.jwks)
    // Session 管理（可选）：检查会话 iframe（用于前端轮询）
    r.GET("/check_session", h.checkSessionIframe)

    // 动态客户端注册（创建/查询/更新/删除）
    r.POST("/register", h.registerClient)
    r.GET("/register", h.getRegisteredClient)
    r.PUT("/register", h.updateRegisteredClient)
    r.DELETE("/register", h.deleteRegisteredClient)
    // 轮换注册访问令牌（Registration Access Token）
    r.POST("/register/rotate", h.rotateRegistrationToken)

    // 身份验证与 OAuth2/OIDC 核心端点
    r.GET("/authorize", h.authorize)
    r.POST("/token", middlewares.RateLimit(h.rdb, "token", h.cfg.Limits.TokenPerMinute, func() time.Duration { if h.cfg.Limits.Window > 0 { return h.cfg.Limits.Window }; return time.Minute }(), func(c *gin.Context) string {
        id, _, ok := c.Request.BasicAuth()
        if !ok { id = c.PostForm("client_id") }
        if id == "" { return c.ClientIP() }
        return id + "|" + c.ClientIP()
    }), h.token)
    r.POST("/revoke", h.revoke)
    r.POST("/introspect", h.introspect)
    r.GET("/userinfo", h.userinfo)
    r.POST("/userinfo", h.userinfo)

    // RP 发起的注销（End Session）
    r.GET("/logout", h.logout)

    // 简单的登录与授权同意页面（示例/开发环境）
    r.GET("/login", h.loginPage)
    r.POST("/login", middlewares.RateLimit(h.rdb, "login", h.cfg.Limits.LoginPerMinute, func() time.Duration { if h.cfg.Limits.Window > 0 { return h.cfg.Limits.Window }; return time.Minute }(), func(c *gin.Context) string { return c.ClientIP() }), h.loginSubmit)
    r.GET("/consent", h.consentPage)
    r.POST("/consent", h.consentSubmit)

    // 运维端点
    r.GET("/metrics", h.metrics)
    r.GET("/healthz", h.healthz)

    // 开发辅助接口：创建用户、列出用户、轮换密钥
    if h.cfg.Env != "prod" {
        r.POST("/dev/users", h.devCreateUser)
        r.GET("/dev/users", h.devListUsers)
        r.POST("/dev/keys/rotate", h.devRotateKeys)
    }
}

// baseURL 根据请求与反向代理头推导基础地址（issuer 等动态值需要）。
func (h *Handler) baseURL(c *gin.Context) string {
    // 若存在反向代理头 X-Forwarded-Proto/Host 则优先使用
    proto := c.GetHeader("X-Forwarded-Proto")
    host := c.GetHeader("X-Forwarded-Host")
    if proto == "" { proto = c.Request.URL.Scheme }
    if proto == "" { proto = "http" }
    if host == "" { host = c.Request.Host }
    return proto + "://" + host
}

// setNoCache 为敏感响应添加禁止缓存的标准响应头。
func setNoCache(c *gin.Context) {
    c.Header("Cache-Control", "no-store")
    c.Header("Pragma", "no-cache")
}

// splitScope 将 scope 规范为单空格分隔，返回字符串与切片。
func splitScope(scope string) (string, []string) {
    parts := strings.Fields(scope)
    return strings.Join(parts, " "), parts
}

// 下方实现 OIDC/OAuth2 的主要端点：Discovery、JWKS、动态注册、Authorize、Token、UserInfo、Logout 以及登录/同意。
//
// --- Discovery & JWKS ---
// @Summary      OIDC Discovery
// @Description  获取 OpenID Provider 的元数据文档
// @Tags         .well-known
// @Produce      json
// @Success      200 {object} oidc.Discovery
// @Router       /.well-known/openid-configuration [get]
// @Router       /.well-known/oauth-authorization-server [get]
func (h *Handler) discovery(c *gin.Context) {
    issuer := h.cfg.Issuer
    // 若未配置 issuer，回退为运行时推导的基础 URL
    if issuer == "" {
        issuer = h.baseURL(c)
    }
    d := oidc.Discovery{
        Issuer:                issuer,
        AuthorizationEndpoint: issuer + "/authorize",
        TokenEndpoint:         issuer + "/token",
        UserInfoEndpoint:      issuer + "/userinfo",
        JWKSURI:               issuer + "/jwks.json",
        ResponseTypesSupported: []string{"code", "code id_token"},
        ResponseModesSupported: []string{"query", "form_post", "fragment"},
        SubjectTypesSupported:  func() []string { if h.cfg.Pairwise.Enable { return []string{"public", "pairwise"} } ; return []string{"public"} }(),
        IDTokenSigningAlgValuesSupported: []string{"RS256", "ES256"},
        ScopesSupported: []string{"openid", "profile", "email"},
        ClaimsSupported: []string{"sub", "name", "email", "email_verified", "given_name", "family_name"},
        TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
        CodeChallengeMethodsSupported: func() []string { if h.cfg.Token.RequirePKCES256 { return []string{"S256"} }; return []string{"S256", "plain"} }(),
        GrantTypesSupported: []string{"authorization_code", "refresh_token"},
        RegistrationEndpoint: h.baseURL(c) + "/register",
        RevocationEndpoint:   issuer + "/revoke",
        IntrospectionEndpoint: issuer + "/introspect",
        EndSessionEndpoint:   h.baseURL(c) + "/logout",
        CheckSessionIframe:   issuer + "/check_session",
        AcrValuesSupported:   []string{"urn:op:auth:pwd", "urn:op:auth:otp"},
        PromptValuesSupported: []string{"none", "login", "consent"},
        ClaimsParameterSupported: false,
        RequestParameterSupported: false,
        RequestURIParameterSupported: false,
    }
    // 便于客户端发现的额外端点头（非规范字段）
    c.Header("Revocation-Endpoint", issuer+"/revoke")
    c.Header("Introspection-Endpoint", issuer+"/introspect")
    // 标注支持后端/前端通道注销
    b := true
    d.BackchannelLogoutSupported = &b
    d.BackchannelLogoutSessionSupported = &b
    d.FrontchannelLogoutSupported = &b
    d.FrontchannelLogoutSessionSupported = &b
    setNoCache(c)
    c.JSON(http.StatusOK, d)
}

// jwks 返回公开的 JWK Set（仅公钥），供 RP 验证 JWT 签名。
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

// --- 登录与授权同意（示例实现） ---
// checkSessionIframe 提供一个极简的会话探测 iframe（供 RP 轮询 postMessage）。
// 规范实现较复杂，此处按是否存在 OP 会话 Cookie 粗略返回状态：unchanged/changed。
// @Summary      会话探测 Iframe（简化）
// @Description  返回可被前端轮询的 iframe 页面，用于检测 OP 会话状态
// @Tags         session
// @Produce      html
// @Success      200 {string} string "HTML"
// @Router       /check_session [get]
func (h *Handler) checkSessionIframe(c *gin.Context) {
    c.Header("Content-Type", "text/html; charset=utf-8")
    cookieName := h.cfg.Session.CookieName
    html := `<!DOCTYPE html><html><head><meta charset="utf-8"><title>check_session</title></head><body><script>
    (function(){
      function hasSession(){ return document.cookie.indexOf('` + cookieName + `=') >= 0; }
      window.addEventListener('message', function(e){
        try {
          var state = hasSession() ? 'unchanged' : 'changed';
          e.source && e.source.postMessage(state, e.origin);
        } catch(err){}
      }, false);
    })();
    </script></body></html>`
    c.String(200, html)
}
// @Summary      登录页
// @Description  渲染用户名密码登录页面（开发/示例用途）
// @Tags         auth
// @Produce      html
// @Success      200 {string} string "HTML"
// @Router       /login [get]
func (h *Handler) loginPage(c *gin.Context) {
    c.HTML(http.StatusOK, "login.html", gin.H{"params": c.Request.URL.Query()})
}

// @Summary      提交登录
// @Description  使用表单提交用户名与密码，成功后创建会话并重定向回 /authorize
// @Tags         auth
// @Accept       x-www-form-urlencoded
// @Param        username  formData string true  "用户名"
// @Param        password  formData string true  "密码"
// @Success      302 {string} string "重定向至 /authorize"
// @Failure      401 {string} string "用户名或密码错误"
// @Router       /login [post]
func (h *Handler) loginSubmit(c *gin.Context) {
    username := c.PostForm("username")
    password := c.PostForm("password")
    // 保留原始 authorize 参数（排除凭据），用于后续回跳
    if err := c.Request.ParseForm(); err != nil { c.String(400, "bad_request"); return }
    orig := url.Values{}
    for k, v := range c.Request.PostForm {
        if k == "username" || k == "password" { continue }
        for _, iv := range v { orig.Add(k, iv) }
    }
    u, err := h.userSvc.FindByUsername(c, username)
    if err != nil || !h.userSvc.CheckPassword(u, password) {
        // 审计：登录失败
        ip := c.ClientIP()
        h.logSvc.Write(c, "WARN", "USER_LOGIN_FAILED", nil, nil, "bad credentials", ip)
        c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error":"用户名或密码错误", "params": c.Request.PostForm})
        return
    }
    // 创建 OP 会话（存 Redis）
    sess, err := h.sessionSvc.New(c, u.ID, "urn:op:auth:pwd", []string{"pwd"})
    if err != nil { c.String(500, "session error"); return }

    // 设置会话 Cookie
    cookie := &http.Cookie{Name: h.cfg.Session.CookieName, Value: sess.SID, Path: "/", HttpOnly: true, Secure: h.cfg.Session.CookieSecure}
    switch strings.ToLower(h.cfg.Session.CookieSameSite) {
    case "strict": cookie.SameSite = http.SameSiteStrictMode
    case "none": cookie.SameSite = http.SameSiteNoneMode
    default: cookie.SameSite = http.SameSiteLaxMode
    }
    if h.cfg.Session.CookieDomain != "" { cookie.Domain = h.cfg.Session.CookieDomain }
    http.SetCookie(c.Writer, cookie)
    // 审计：登录成功
    ip := c.ClientIP()
    h.logSvc.Write(c, "INFO", "USER_LOGIN", h.userSvc.IDPtr(u.ID), nil, "login success", ip)

    // 重定向回 /authorize，附回原始参数
    q := orig.Encode()
    c.Redirect(http.StatusFound, "/authorize?"+q)
}

// consentPage 渲染授权同意页，展示应用与所请求的 scope。
// @Summary      授权同意页
// @Description  展示客户端名称与申请的 scope，供用户确认
// @Tags         consent
// @Produce      html
// @Param        client_id  query string true  "客户端 ID"
// @Param        scope      query string true  "请求的 scope（空格分隔）"
// @Success      200 {string} string "HTML"
// @Router       /consent [get]
func (h *Handler) consentPage(c *gin.Context) {
    clientID := c.Query("client_id")
    scope := c.Query("scope")
    cl, err := h.clientSvc.FindByID(c, clientID)
    if err != nil { c.String(400, "invalid client"); return }
    _, scopes := splitScope(scope)
    c.HTML(http.StatusOK, "consent.html", gin.H{"client_name": cl.Name, "scopes": scopes, "params": c.Request.URL.Query()})
}

// consentSubmit 处理授权同意：同意则记录 consent，随后回跳 /authorize。
// @Summary      提交授权同意
// @Description  用户同意后记录 consent 并重定向回 /authorize
// @Tags         consent
// @Accept       x-www-form-urlencoded
// @Param        decision   formData string true  "approve 或 deny"
// @Success      302 {string} string "重定向至 /authorize"
// @Failure      400 {object} map[string]string
// @Router       /consent [post]
func (h *Handler) consentSubmit(c *gin.Context) {
    decision := c.PostForm("decision")
    if decision != "approve" {
        c.JSON(400, gin.H{"error":"access_denied"})
        return
    }
    if err := c.Request.ParseForm(); err != nil { c.String(400, "bad_request"); return }
    // 重建原始 authorize 参数（排除 decision），随后标记已同意
    qv := url.Values{}
    for k, v := range c.Request.PostForm {
        if k == "decision" { continue }
        for _, iv := range v { qv.Add(k, iv) }
    }
    // 记录用户对该客户端的授权同意，便于下次免提示
    sid := readSessionCookie(c, h.cfg.Session.CookieName)
    if sid != "" {
        if sess, err := h.sessionSvc.Get(c, sid); err == nil {
            clientID := qv.Get("client_id")
            scope := qv.Get("scope")
            _ = h.consentSvc.Save(c, sess.UserID, clientID, scope)
        }
    }
    qv.Set("consent", "approve")
    q := qv.Encode()
    c.Redirect(http.StatusFound, "/authorize?"+q)
}

// --- 动态客户端注册 ---
// registerClient 动态注册客户端，返回 client_id/client_secret（如适用）与 registration_access_token。
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
    // 初始访问令牌保护：当配置不为空时，要求 Authorization: Bearer <token>
    if tok := parseBearer(c.GetHeader("Authorization")); h.cfg.Registration.InitialAccessToken != "" {
        if tok == "" || tok != h.cfg.Registration.InitialAccessToken {
            c.JSON(401, gin.H{"error":"unauthorized"}); return
        }
    }
    var req services.RegisterRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error":"invalid_request","error_description": "bad json"})
        return
    }
    baseURL := h.baseURL(c)
    resp, _, err := h.clientSvc.Register(c, baseURL, &req)
    if err != nil {
        c.JSON(400, gin.H{"error":"invalid_client_metadata","error_description": err.Error()})
        return
    }
    c.Header("Location", resp.RegistrationClientURI)
    // 审计：客户端已注册
    ip := c.ClientIP()
    h.logSvc.Write(c, "INFO", "CLIENT_REGISTERED", nil, &resp.ClientID, "client registered", ip)
    c.JSON(http.StatusCreated, resp)
}

// rotateRegistrationToken 轮换注册访问令牌（需要现有 registration_access_token）。
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
    if clientID == "" || tok == "" { c.JSON(401, gin.H{"error":"unauthorized"}); return }
    ok, cl, err := h.clientSvc.ValidateRegistrationToken(c, clientID, tok)
    if err != nil || !ok { c.JSON(401, gin.H{"error":"unauthorized"}); return }
    // 生成新 token 与过期时间
    now := time.Now()
    sh := sha256.Sum256([]byte(clientID + now.String()))
    newTok := base64.RawURLEncoding.EncodeToString(sh[:])
    if hh, err := bcrypt.GenerateFromPassword([]byte(newTok), bcrypt.DefaultCost); err == nil {
        cl.RegistrationAccessTokenHash = string(hh)
        // 应用 TTL（若配置）
        if h.cfg.Token.RegistrationPATTTL > 0 {
            cl.RegistrationAccessTokenExpiresAt = now.Add(h.cfg.Token.RegistrationPATTTL)
        }
        if err := h.clientSvc.Save(c, cl); err != nil { c.JSON(500, gin.H{"error":"server_error"}); return }
        c.JSON(200, gin.H{"registration_access_token": newTok})
        return
    }
    c.JSON(500, gin.H{"error":"server_error"})
}

// getRegisteredClient 通过 registration_access_token 查询客户端元数据。
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
    if clientID == "" || tok == "" { c.JSON(401, gin.H{"error":"unauthorized"}); return }
    ok, cl, err := h.clientSvc.ValidateRegistrationToken(c, clientID, tok)
    if err != nil || !ok { c.JSON(401, gin.H{"error":"unauthorized"}); return }
    // 构建返回的客户端元数据
    var rus []string; _ = json.Unmarshal([]byte(cl.RedirectURIs), &rus)
    var plrus []string; _ = json.Unmarshal([]byte(cl.PostLogoutRedirectURIs), &plrus)
    c.JSON(200, gin.H{
        "client_id": cl.ClientID,
        "client_name": cl.Name,
        "redirect_uris": rus,
        "post_logout_redirect_uris": plrus,
        "backchannel_logout_uri": cl.BackchannelLogoutURI,
        "grant_types": strings.Split(cl.GrantTypes, ","),
        "response_types": strings.Split(cl.ResponseTypes, ","),
        "token_endpoint_auth_method": cl.TokenEndpointAuthMethod,
        "subject_type": cl.SubjectType,
        "sector_identifier_uri": cl.SectorIdentifierURI,
        "client_secret_expires_at": 0,
        "client_id_issued_at": cl.CreatedAt.Unix(),
        "registration_client_uri": h.baseURL(c) + "/register?client_id=" + cl.ClientID,
    })
}

// updateRegisteredClient 更新已注册客户端的元数据（需注册访问令牌）。
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
    if clientID == "" || tok == "" { c.JSON(401, gin.H{"error":"unauthorized"}); return }
    ok, cl, err := h.clientSvc.ValidateRegistrationToken(c, clientID, tok)
    if err != nil || !ok { c.JSON(401, gin.H{"error":"unauthorized"}); return }
    var req struct{
        ClientName string `json:"client_name"`
        RedirectURIs []string `json:"redirect_uris"`
        PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
        FrontchannelLogoutURI string `json:"frontchannel_logout_uri"`
        BackchannelLogoutURI string `json:"backchannel_logout_uri"`
        TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
        SubjectType string `json:"subject_type"`
        SectorIdentifierURI string `json:"sector_identifier_uri"`
    }
    if err := c.ShouldBindJSON(&req); err != nil { c.JSON(400, gin.H{"error":"invalid_request"}); return }
    if req.ClientName != "" { cl.Name = req.ClientName }
    if req.FrontchannelLogoutURI != "" { cl.FrontchannelLogoutURI = req.FrontchannelLogoutURI }
    if req.BackchannelLogoutURI != "" { cl.BackchannelLogoutURI = req.BackchannelLogoutURI }
    if req.TokenEndpointAuthMethod != "" { cl.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod }
    if req.SubjectType != "" { cl.SubjectType = req.SubjectType }
    // 变更 sector_identifier_uri 时必须校验其 JSON 列表包含所有 redirect_uris
    if len(req.RedirectURIs) > 0 {
        if req.SectorIdentifierURI != "" {
            if err := h.clientSvc.ValidateSectorIdentifier(c, req.SectorIdentifierURI, req.RedirectURIs); err != nil {
                c.JSON(400, gin.H{"error":"invalid_client_metadata","error_description": err.Error()}); return
            }
        }
        if b, _ := json.Marshal(req.RedirectURIs); true { cl.RedirectURIs = string(b) }
    }
    if req.SectorIdentifierURI != "" { cl.SectorIdentifierURI = req.SectorIdentifierURI }
    if len(req.PostLogoutRedirectURIs) > 0 { if b, _ := json.Marshal(req.PostLogoutRedirectURIs); true { cl.PostLogoutRedirectURIs = string(b) } }
    if err := h.clientSvc.Save(c, cl); err != nil { c.JSON(500, gin.H{"error":"server_error"}); return }
    c.Status(204)
}

// deleteRegisteredClient 将客户端标记为未批准（等价于删除/禁用）。
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
    if clientID == "" || tok == "" { c.JSON(401, gin.H{"error":"unauthorized"}); return }
    ok, cl, err := h.clientSvc.ValidateRegistrationToken(c, clientID, tok)
    if err != nil || !ok { c.JSON(401, gin.H{"error":"unauthorized"}); return }
    cl.Approved = false
    if err := h.clientSvc.Save(c, cl); err != nil { c.JSON(500, gin.H{"error":"server_error"}); return }
    c.Status(204)
}

func parseBearer(h string) string {
    parts := strings.SplitN(h, " ", 2)
    if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") { return parts[1] }
    return ""
}

// --- Authorize 端点 ---
// authorize 实现授权码（必需 PKCE）及可选 Hybrid（code id_token）流程。
// @Summary      授权端点（Authorization）
// @Description  实现授权码 + PKCE 及可选 Hybrid 流程
// @Tags         oauth2
// @Produce      html
// @Param        response_type   query string true  "code 或 code id_token"
// @Param        client_id       query string true  "客户端 ID"
// @Param        redirect_uri    query string true  "重定向 URI"
// @Param        scope           query string true  "openid 等空格分隔"
// @Param        state           query string false "状态参数"
// @Param        nonce           query string false "Hybrid 必需"
// @Param        response_mode   query string false "fragment|form_post|query"
// @Param        code_challenge  query string false "PKCE 挑战"
// @Param        code_challenge_method query string false "S256|plain"
// @Param        prompt          query string false "none|login|consent"
// @Param        acr_values      query string false "ACR 要求"
// @Success      302 {string} string "重定向到 redirect_uri"
// @Failure      400 {object} map[string]string
// @Router       /authorize [get]
func (h *Handler) authorize(c *gin.Context) {
    // 1) 解析关键参数
    responseType := c.Query("response_type")
    clientID := c.Query("client_id")
    redirectURI := c.Query("redirect_uri")
    scope := c.Query("scope")
    state := c.Query("state")
    nonce := c.Query("nonce")
    responseMode := c.Query("response_mode") // 可选：fragment、form_post、query（响应模式）
    codeChallenge := c.Query("code_challenge")
    codeChallengeMethod := c.Query("code_challenge_method") // 可选：S256、plain（PKCE 挑战算法）
    prompt := c.Query("prompt")
    acrValues := c.Query("acr_values")
    // 支持 response_type=code 与可选 Hybrid（code id_token / id_token code）；scope 必须包含 openid
    rt0 := strings.TrimSpace(responseType)
    if !(rt0 == "code" || rt0 == "code id_token" || rt0 == "id_token code") {
        h.redirectError(c, redirectURI, "unsupported_response_type", state)
        return
    }
    if !strings.Contains(" "+scope+" ", " openid ") {
        h.redirectError(c, redirectURI, "invalid_scope", state)
        return
    }
    // 2) 校验客户端与 redirect_uri
    cl, err := h.clientSvc.FindByID(c, clientID)
    if err != nil {
        c.JSON(400, gin.H{"error": "unauthorized_client"})
        return
    }
    if !redirectURIMatches(cl, redirectURI) {
        c.JSON(400, gin.H{"error": "invalid_request", "error_description":"redirect_uri mismatch"})
        return
    }
    // 3) 检查 OP 会话 Cookie
    sid := readSessionCookie(c, h.cfg.Session.CookieName)
    var sess *services.Session
    if sid != "" {
        if s, err := h.sessionSvc.Get(c, sid); err == nil { sess = s }
    }
    // 3.1) 若无会话或 prompt=login：渲染登录页；若 prompt=none：返回 login_required
    if sess == nil || strings.Contains(prompt, "login") {
        if prompt == "none" {
            h.redirectError(c, redirectURI, "login_required", state); return
        }
        // 登录页通过隐藏字段保留原始参数
        c.HTML(http.StatusOK, "login.html", gin.H{"params": c.Request.URL.Query()})
        return
    }
    // 3.2) ACR 要求检查
    if acrValues != "" {
        required := strings.Fields(acrValues)
        ok := false
        for _, r := range required { if r == sess.ACR { ok = true; break } }
        if !ok { h.redirectError(c, redirectURI, "unmet_authentication_requirements", state); return }
    }
    // 3.3) max_age（秒）检查：超时需重新认证
    if mv := c.Query("max_age"); mv != "" {
        if sec, err := strconv.Atoi(mv); err == nil && sec >= 0 {
            if time.Since(sess.AuthTime) > time.Duration(sec)*time.Second {
                if prompt == "none" {
                    h.redirectError(c, redirectURI, "login_required", state); return
                }
                c.HTML(http.StatusOK, "login.html", gin.H{"params": c.Request.URL.Query()})
                return
            }
        }
    }
    // 4) 授权同意：prompt=consent 强制展示；prompt=none 但需要同意则返回错误
    approved := c.Query("consent") == "approve"
    prior := h.consentSvc.HasConsent(c, sess.UserID, cl.ClientID, scope)
    needConsent := !prior || strings.Contains(prompt, "consent")
    if !approved && needConsent {
        if prompt == "none" {
            h.redirectError(c, redirectURI, "consent_required", state); return
        }
        _, scopes := splitScope(scope)
        c.HTML(http.StatusOK, "consent.html", gin.H{"client_name": cl.Name, "scopes": scopes, "params": c.Request.URL.Query()})
        return
    }
    // 5) PKCE 要求：授权码流程必须提供 code_challenge
    if codeChallenge == "" {
        h.redirectError(c, redirectURI, "invalid_request", state)
        return
    }
    // 按配置强制 S256
    if h.cfg.Token.RequirePKCES256 {
        if strings.ToUpper(codeChallengeMethod) != "S256" {
            h.redirectError(c, redirectURI, "invalid_request", state)
            return
        }
    }
    // 6) 颁发授权码并记录到 Redis（一次性，短 TTL）
    ac, err := h.codeSvc.New(c, cl.ClientID, sess.UserID, redirectURI, scope, nonce, sess.SID, codeChallenge, codeChallengeMethod)
    if err != nil { c.String(500, "server_error"); return }
    // 记录该会话下已登录的客户端，用于后端通道注销通知
    _ = h.rdb.SAdd(c, "sid:clients:"+sess.SID, cl.ClientID).Err()
    // 7) 构造响应（默认查询参数；Hybrid 时默认 fragment 或 form_post）
    rt := strings.TrimSpace(responseType)
    if rt == "code id_token" || rt == "id_token code" {
        // Hybrid：必须提供 nonce
        if nonce == "" {
            h.redirectError(c, redirectURI, "invalid_request", state); return
        }
        // 生成带 c_hash 的 ID Token（此处不含 access_token），并按 scope 注入可选 Claims
        ch := utils.CHash(ac.Code)
        extra := map[string]interface{}{"sid": sess.SID, "azp": cl.ClientID, "c_hash": ch}
        if u, err := h.userSvc.FindByID(c, sess.UserID); err == nil {
            if strings.Contains(scope, "profile") {
                if u.Name != "" { extra["name"] = u.Name }
                if u.Username != "" { extra["preferred_username"] = u.Username }
                if !u.UpdatedAt.IsZero() { extra["updated_at"] = u.UpdatedAt.Unix() }
            }
            if strings.Contains(scope, "email") {
                if u.Email != "" { extra["email"] = u.Email }
                extra["email_verified"] = u.EmailVerified
            }
        }
        idt, err := h.tokenSvc.BuildIDToken(cl.ClientID, h.subjectFor(cl, sess.UserID), nonce, sess.ACR, "", sess.AuthTime, extra)
        if err != nil { c.String(500, "server_error"); return }
        // 当存在 id_token 时，默认使用 URL 片段（fragment）承载
        mode := responseMode
        if mode == "" { mode = "fragment" }
        switch mode {
        case "form_post":
            var b strings.Builder
            b.WriteString("<html><body><form method=\"post\" action=\"")
            b.WriteString(redirectURI)
            b.WriteString("\">")
            b.WriteString("<input type=\\\"hidden\\\" name=\\\"code\\\" value=\\\"")
            b.WriteString(ac.Code)
            b.WriteString("\\\"/>")
            if state != "" {
                b.WriteString("<input type=\\\"hidden\\\" name=\\\"state\\\" value=\\\"")
                b.WriteString(state)
                b.WriteString("\\\"/>")
            }
            b.WriteString("<input type=\\\"hidden\\\" name=\\\"id_token\\\" value=\\\"")
            b.WriteString(idt)
            b.WriteString("\\\"/>")
            b.WriteString("<noscript><button type=\\\"submit\\\">Continue</button></noscript>")
            b.WriteString("</form><script>document.forms[0].submit();</script></body></html>")
            c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(b.String()))
            return
        case "fragment":
            // 使用 fragment 方式回传参数
            v := url.Values{}
            v.Set("code", ac.Code)
            if state != "" { v.Set("state", state) }
            v.Set("id_token", idt)
            location := redirectURI + "#" + v.Encode()
            c.Redirect(http.StatusFound, location)
            return
        default:
            // query 不适合携带 id_token；回退为 fragment
            v := url.Values{}
            v.Set("code", ac.Code)
            if state != "" { v.Set("state", state) }
            v.Set("id_token", idt)
            location := redirectURI + "#" + v.Encode()
            c.Redirect(http.StatusFound, location)
            return
        }
    } else {
        // 仅授权码：支持 response_mode=form_post，否则按查询参数重定向
        if strings.EqualFold(responseMode, "form_post") {
            var b strings.Builder
            b.WriteString("<html><body><form method=\"post\" action=\"")
            b.WriteString(redirectURI)
            b.WriteString("\">")
            b.WriteString("<input type=\\\"hidden\\\" name=\\\"code\\\" value=\\\"")
            b.WriteString(ac.Code)
            b.WriteString("\\\"/>")
            if state != "" {
                b.WriteString("<input type=\\\"hidden\\\" name=\\\"state\\\" value=\\\"")
                b.WriteString(state)
                b.WriteString("\\\"/>")
            }
            b.WriteString("<noscript><button type=\\\"submit\\\">Continue</button></noscript>")
            b.WriteString("</form><script>document.forms[0].submit();</script></body></html>")
            c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(b.String()))
            return
        }
        sep := "?"
        if strings.Contains(redirectURI, "?") { sep = "&" }
        location := redirectURI + sep + "code=" + ac.Code
        if state != "" { location += "&state=" + urlQueryEscape(state) }
        c.Redirect(http.StatusFound, location)
    }
}

// redirectError 辅助：若可用，带错误码重定向到 redirect_uri。
func (h *Handler) redirectError(c *gin.Context, redirectURI, code, state string) {
    if redirectURI == "" {
        c.JSON(400, gin.H{"error": code}); return
    }
    sep := "?"; if strings.Contains(redirectURI, "?") { sep = "&" }
    loc := redirectURI + sep + "error=" + urlQueryEscape(code)
    if state != "" { loc += "&state=" + urlQueryEscape(state) }
    c.Redirect(302, loc)
}

func redirectURIMatches(c *storage.Client, redirectURI string) bool {
    var list []string
    _ = json.Unmarshal([]byte(c.RedirectURIs), &list)
    for _, v := range list { if v == redirectURI { return true } }
    return false
}

// --- Token 端点 ---
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
    // 客户端认证：支持 HTTP Basic 或表单字段
    clientID, clientSecret, ok := c.Request.BasicAuth()
    if !ok {
        clientID = c.PostForm("client_id")
        clientSecret = c.PostForm("client_secret")
    }
    if clientID == "" {
        c.Header("WWW-Authenticate", "Basic realm=token")
        c.JSON(401, gin.H{"error":"invalid_client"})
        return
    }
    valid, cl, err := h.clientSvc.ValidateSecret(c, clientID, clientSecret)
    if err != nil || !valid {
        c.JSON(401, gin.H{"error":"invalid_client"})
        return
    }
    grantType := c.PostForm("grant_type")
    if grantType == "refresh_token" {
        h.handleRefreshToken(c, clientID, cl)
        return
    }
    if grantType != "authorization_code" {
        c.JSON(400, gin.H{"error":"unsupported_grant_type"}); return
    }
    code := c.PostForm("code")
    redirectURI := c.PostForm("redirect_uri")
    codeVerifier := c.PostForm("code_verifier")
    if code == "" || redirectURI == "" {
        c.JSON(400, gin.H{"error":"invalid_request"}); return
    }
    ac, err := h.codeSvc.GetAndUse(c, code)
    if err != nil { c.JSON(400, gin.H{"error":"invalid_grant"}); return }
    if ac.ClientID != cl.ClientID || ac.RedirectURI != redirectURI {
        c.JSON(400, gin.H{"error":"invalid_grant"}); return
    }
    // PKCE 校验（若授权码绑定了 challenge）
    if ac.CodeChallenge != "" {
        if codeVerifier == "" { c.JSON(400, gin.H{"error":"invalid_grant","error_description":"code_verifier required"}); return }
        method := strings.ToUpper(ac.CodeChallengeMethod)
        if method == "S256" {
            // code_challenge = BASE64URL-ENCODE(SHA256(verifier))
            sum := sha256.Sum256([]byte(codeVerifier))
            expected := base64.RawURLEncoding.EncodeToString(sum[:])
            if expected != ac.CodeChallenge { c.JSON(400, gin.H{"error":"invalid_grant"}); return }
        } else if method == "PLAIN" || method == "" { // 明文
            if h.cfg.Token.RequirePKCES256 { c.JSON(400, gin.H{"error":"invalid_grant","error_description":"pkce_s256_required"}); return }
            if codeVerifier != ac.CodeChallenge { c.JSON(400, gin.H{"error":"invalid_grant"}); return }
        } else {
            c.JSON(400, gin.H{"error":"invalid_grant","error_description":"unsupported_code_challenge_method"}); return
        }
    } else {
        // 对 public 客户端强制要求使用 PKCE
        if strings.EqualFold(cl.TokenEndpointAuthMethod, "none") {
            c.JSON(400, gin.H{"error":"invalid_grant","error_description":"pkce required"}); return
        }
    }
    // 计算 subject（public 或 pairwise）
    subject := h.subjectFor(cl, ac.UserID)
    // 签发访问令牌（JWT）与 ID Token
    at, exp, jti, err := h.tokenSvc.BuildAccessTokenJWT(cl.ClientID, ac.UserID, subject, ac.Scope, ac.SID)
    if err != nil { c.JSON(500, gin.H{"error":"server_error"}); return }
    // 持久化访问令牌审计记录
    _ = h.tokenRepo.SaveAccessToken(c, cl.ClientID, ac.UserID, ac.Scope, jti, exp)
    // 审计
    ip := c.ClientIP()
    cid := cl.ClientID
    h.logSvc.Write(c, "INFO", "TOKEN_ISSUED", h.userSvc.IDPtr(ac.UserID), &cid, "access+id token issued", ip)
    atHash := utils.ATHash(at)
    // 组装按 scope 的附加 Claims（可选）
    extra := map[string]interface{}{"sid": ac.SID, "azp": cl.ClientID}
    if u, err := h.userSvc.FindByID(c, ac.UserID); err == nil {
        if strings.Contains(ac.Scope, "profile") {
            if u.Name != "" { extra["name"] = u.Name }
            if u.Username != "" { extra["preferred_username"] = u.Username }
            if !u.UpdatedAt.IsZero() { extra["updated_at"] = u.UpdatedAt.Unix() }
        }
        if strings.Contains(ac.Scope, "email") {
            if u.Email != "" { extra["email"] = u.Email }
            extra["email_verified"] = u.EmailVerified
        }
    }
    // 授权码流程的 token 端点返回的 ID Token 通常不包含 c_hash
    idt, err := h.tokenSvc.BuildIDToken(cl.ClientID, subject, ac.Nonce, "urn:op:auth:pwd", atHash, time.Now(), extra)
    if err != nil { c.JSON(500, gin.H{"error":"server_error"}); return }
    // 指标
    metrics.TokensIssued.Inc()
    resp := gin.H{
        "access_token": at,
        "token_type":   "Bearer",
        "expires_in":   int(h.cfg.Token.AccessTokenTTL.Seconds()),
        "id_token":     idt,
    }
    // 如包含 offline_access scope，则附加刷新令牌
    if strings.Contains(" "+ac.Scope+" ", " offline_access ") {
        if rt, err := h.refreshSvc.Issue(c, ac.UserID, cl.ClientID, ac.Scope, subject, ac.SID); err == nil {
            resp["refresh_token"] = rt
        }
    }
    c.JSON(200, resp)
}

// handleRefreshToken 处理 refresh_token 授权类型。
func (h *Handler) handleRefreshToken(c *gin.Context, clientID string, cl *storage.Client) {
    rt := c.PostForm("refresh_token")
    if rt == "" { c.JSON(400, gin.H{"error":"invalid_request"}); return }
    rec, newRT, err := h.refreshSvc.Use(c, rt)
    if err != nil || rec.ClientID != clientID {
        c.JSON(400, gin.H{"error":"invalid_grant"}); return
    }
    subject := h.subjectFor(cl, rec.UserID)
    at, exp, jti, err := h.tokenSvc.BuildAccessTokenJWT(cl.ClientID, rec.UserID, subject, rec.Scope, rec.SID)
    if err != nil { c.JSON(500, gin.H{"error":"server_error"}); return }
    _ = h.tokenRepo.SaveAccessToken(c, cl.ClientID, rec.UserID, rec.Scope, jti, exp)
    atHash := utils.ATHash(at)
    idt, err := h.tokenSvc.BuildIDToken(cl.ClientID, subject, "", "urn:op:auth:pwd", atHash, time.Now(), map[string]interface{}{"sid": rec.SID, "azp": cl.ClientID})
    if err != nil { c.JSON(500, gin.H{"error":"server_error"}); return }
    metrics.TokensIssued.Inc()
    c.JSON(200, gin.H{
        "access_token": at,
        "token_type":   "Bearer",
        "expires_in":   int(h.cfg.Token.AccessTokenTTL.Seconds()),
        "id_token":     idt,
        "refresh_token": newRT,
    })
}

// subjectFor 按 subject_type 与 sector_identifier_uri 规则为指定客户端与用户计算 sub 值。
func (h *Handler) subjectFor(cl *storage.Client, userID uint64) string {
    if !h.cfg.Pairwise.Enable || strings.ToLower(cl.SubjectType) != "pairwise" {
        return fmt.Sprintf("%d", userID)
    }
    sector := sectorHostForClient(cl)
    return utils.PairwiseSub(sector, userID, h.cfg.Pairwise.Salt)
}

func sectorHostForClient(cl *storage.Client) string {
    if cl.SectorIdentifierURI != "" {
        if u, err := url.Parse(cl.SectorIdentifierURI); err == nil { return u.Host }
    }
    var list []string
    _ = json.Unmarshal([]byte(cl.RedirectURIs), &list)
    if len(list) == 0 { return "" }
    if u, err := url.Parse(list[0]); err == nil { return u.Host }
    return ""
}

// --- UserInfo 端点 ---
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
    // CORS 开关（默认关闭）
    if h.cfg.CORS.EnableUserInfo {
        origin := c.GetHeader("Origin")
        if origin != "" && (len(h.cfg.CORS.AllowedOrigins) == 0 || contains(h.cfg.CORS.AllowedOrigins, origin)) {
            c.Header("Access-Control-Allow-Origin", origin)
            c.Header("Vary", "Origin")
        }
        c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        if c.Request.Method == "OPTIONS" { c.Status(204); return }
    }
    // 接受 Authorization: Bearer；若缺省则回退读取 access_token 参数
    auth := c.GetHeader("Authorization")
    parts := strings.SplitN(auth, " ", 2)
    var tokenStr string
    if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && parts[1] != "" {
        tokenStr = parts[1]
    } else {
        // 回退读取查询参数或表单中的 access_token
        tokenStr = c.Query("access_token")
        if tokenStr == "" { tokenStr = c.PostForm("access_token") }
        if tokenStr == "" {
            c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
            c.JSON(401, gin.H{"error":"invalid_token"})
            return
        }
    }
    claims, err := h.tokenSvc.VerifyJWT(tokenStr)
    if err != nil { c.JSON(401, gin.H{"error":"invalid_token"}); return }
    sub, _ := claims["sub"].(string)
    scope, _ := claims["scope"].(string)
    // 拒绝已撤销的访问令牌
    if jti, _ := claims["jti"].(string); jti != "" {
        if h.revokeSvc.IsAccessTokenRevoked(c, jti) { c.JSON(401, gin.H{"error":"invalid_token"}); return }
    }
    uidF, hasUID := claims["uid"].(float64)
    resp := gin.H{"sub": sub}
    if hasUID {
        // 按 scope 加载并映射用户字段
        uid := uint64(uidF)
        if u, err := h.userSvc.FindByID(c, uid); err == nil {
            if strings.Contains(scope, "profile") {
                if u.Name != "" { resp["name"] = u.Name }
                if u.Username != "" { resp["preferred_username"] = u.Username }
                if !u.UpdatedAt.IsZero() { resp["updated_at"] = u.UpdatedAt.Unix() }
            }
            if strings.Contains(scope, "email") {
                if u.Email != "" { resp["email"] = u.Email }
                resp["email_verified"] = u.EmailVerified
            }
        }
    }
    c.JSON(200, resp)
}

// --- 吊销端点（RFC 7009） ---
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
    // 客户端认证
    clientID, clientSecret, ok := c.Request.BasicAuth()
    if !ok { clientID = c.PostForm("client_id"); clientSecret = c.PostForm("client_secret") }
    if clientID == "" { c.JSON(401, gin.H{"error":"invalid_client"}); return }
    valid, cl, err := h.clientSvc.ValidateSecret(c, clientID, clientSecret)
    if err != nil || !valid { c.JSON(401, gin.H{"error":"invalid_client"}); return }
    token := c.PostForm("token")
    hint := c.PostForm("token_type_hint") // access_token | refresh_token
    if token == "" { c.Status(200); return }
    if hint == "refresh_token" {
        _ = h.refreshSvc.Delete(c, token)
        // 审计
        ip := c.ClientIP(); cid := cl.ClientID
        h.logSvc.Write(c, "INFO", "REFRESH_REVOKED", nil, &cid, "refresh token revoked", ip)
        c.Status(200); return
    }
    // 尝试按访问令牌（JWT）处理
    claims := jwt.MapClaims{}
    if _, _, err := new(jwt.Parser).ParseUnverified(token, claims); err == nil {
        jti, _ := claims["jti"].(string)
        expF, _ := claims["exp"].(float64)
        now := time.Now()
        ttl := time.Second * 0
        if expF > 0 {
            exp := time.Unix(int64(expF), 0)
            if exp.After(now) { ttl = exp.Sub(now) }
        }
        _ = h.revokeSvc.RevokeAccessToken(c, jti, ttl)
    }
    // 审计
    ip := c.ClientIP(); cid := cl.ClientID
    h.logSvc.Write(c, "INFO", "ACCESS_REVOKED", nil, &cid, "access token revoked", ip)
    c.Status(200)
}

// --- 内省端点（RFC 7662） ---
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
    // 客户端认证
    clientID, clientSecret, ok := c.Request.BasicAuth()
    if !ok { clientID = c.PostForm("client_id"); clientSecret = c.PostForm("client_secret") }
    if clientID == "" { c.JSON(401, gin.H{"error":"invalid_client"}); return }
    valid, _, err := h.clientSvc.ValidateSecret(c, clientID, clientSecret)
    if err != nil || !valid { c.JSON(401, gin.H{"error":"invalid_client"}); return }
    token := c.PostForm("token")
    if token == "" { c.JSON(200, gin.H{"active": false}); return }
    claims, err := h.tokenSvc.VerifyJWT(token)
    if err != nil { c.JSON(200, gin.H{"active": false}); return }
    // 过期校验
    now := time.Now().Unix()
    expF, _ := claims["exp"].(float64)
    if expF != 0 && int64(expF) <= now { c.JSON(200, gin.H{"active": false}); return }
    // 撤销名单校验（jti）
    if jti, _ := claims["jti"].(string); jti != "" {
        if h.revokeSvc.IsAccessTokenRevoked(c, jti) { c.JSON(200, gin.H{"active": false}); return }
    }
    // 返回标准字段
    aud := claims["aud"]
    scope, _ := claims["scope"].(string)
    sub, _ := claims["sub"].(string)
    iat, _ := claims["iat"].(float64)
    iss, _ := claims["iss"].(string)
    jti, _ := claims["jti"].(string)
    tokClientID, _ := claims["client_id"].(string)
    resp := gin.H{
        "active": true,
        "scope": scope,
        "client_id": func() string { if tokClientID != "" { return tokClientID }; if s, ok := aud.(string); ok { return s }; return clientID }(),
        "username": sub,
        "token_type": "access_token",
        "exp": int64(expF),
        "iat": int64(iat),
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "jti": jti,
    }
    c.JSON(200, resp)
}

// --- 注销端点 ---
// logout 实现 RP 发起注销：清理 OP 会话，通知已登录 RP（后端/前端通道），并可按需重定向。
// @Summary      注销（RP-Initiated Logout）
// @Description  清理 OP 会话并通知已登录 RP；可选重定向
// @Tags         logout
// @Produce      html
// @Param        id_token_hint            query string false "RP 提供的 ID Token"
// @Param        post_logout_redirect_uri query string false "注销后重定向 URI"
// @Param        state                    query string false "重定向回传状态"
// @Success      200 {string} string "HTML 或 302 重定向"
// @Router       /logout [get]
func (h *Handler) logout(c *gin.Context) {
    idTokenHint := c.Query("id_token_hint")
    postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
    state := c.Query("state")
    // 若提供 id_token_hint，用于提取 aud/sub，便于 post_logout_redirect_uri 校验与通知
    var hintAud string
    var hintSub string
    if idTokenHint != "" {
        if claims, err := h.tokenSvc.VerifyJWT(idTokenHint); err == nil {
            switch v := claims["aud"].(type) {
            case string:
                hintAud = v
            case []any:
                if len(v) > 0 {
                    if s, ok := v[0].(string); ok { hintAud = s }
                }
            }
            if s, ok := claims["sub"].(string); ok { hintSub = s }
        }
    }
    // 根据 Cookie 获取 sid，做最佳努力的会话清理
    sid := readSessionCookie(c, h.cfg.Session.CookieName)
    if sid != "" { _ = h.sessionSvc.Delete(c, sid) }
    // 后端通道注销通知
    if sid != "" {
        go h.notifyBackchannel(c.Request.Context(), sid, hintSub)
    }
    // 若可识别客户端，校验 post_logout_redirect_uri 是否允许
    if postLogoutRedirectURI != "" && hintAud != "" {
        if cl, err := h.clientSvc.FindByID(c, hintAud); err == nil {
            if !logoutRedirectAllowed(cl, postLogoutRedirectURI) {
                postLogoutRedirectURI = ""
            }
        }
    }
    if postLogoutRedirectURI != "" {
        // 审计：RP 发起注销并重定向
        ip := c.ClientIP()
        h.logSvc.Write(c, "INFO", "USER_LOGOUT", nil, nil, "rp-initiated logout", ip)
        sep := "?"; if strings.Contains(postLogoutRedirectURI, "?") { sep = "&" }
        loc := postLogoutRedirectURI
        if state != "" { loc = loc + sep + "state=" + urlQueryEscape(state) }
        c.Redirect(302, loc); return
    }
    ip := c.ClientIP()
    h.logSvc.Write(c, "INFO", "USER_LOGOUT", nil, nil, "logout", ip)
    // 无重定向时，渲染前端通道注销 iframe 列表
    urls := []string{}
    if sid != "" {
        ids, _ := h.rdb.SMembers(c, "sid:clients:"+sid).Result()
        for _, cid := range ids {
            if cl, err := h.clientSvc.FindByID(c, cid); err == nil && cl.FrontchannelLogoutURI != "" {
                u := cl.FrontchannelLogoutURI
                sep2 := "?"; if strings.Contains(u, "?") { sep2 = "&" }
                u = u + sep2 + "sid=" + urlQueryEscape(sid) + "&iss=" + urlQueryEscape(h.cfg.Issuer)
                urls = append(urls, u)
            }
        }
    }
    c.HTML(http.StatusOK, "frontchannel_logout.html", gin.H{"iframes": urls})
}

func logoutRedirectAllowed(cl *storage.Client, uri string) bool {
    if cl.PostLogoutRedirectURIs == "" { return false }
    var list []string
    _ = json.Unmarshal([]byte(cl.PostLogoutRedirectURIs), &list)
    for _, v := range list { if v == uri { return true } }
    return false
}

// notifyBackchannel 异步向所有与该 sid 关联的客户端 POST 注销令牌（Back-Channel Logout）。
func (h *Handler) notifyBackchannel(ctx context.Context, sid string, subject string) {
    // 获取该会话下的客户端列表
    ids, err := h.rdb.SMembers(ctx, "sid:clients:"+sid).Result()
    if err != nil || len(ids) == 0 { return }
    httpc := &http.Client{Timeout: 3 * time.Second}
    for _, cid := range ids {
        cl, err := h.clientSvc.FindByID(ctx, cid)
        if err != nil || cl.BackchannelLogoutURI == "" { continue }
        // 构造 Logout Token（JWT）
        lt, err := h.tokenSvc.BuildLogoutToken(cl.ClientID, subject, sid)
        if err != nil { continue }
        // 以 application/x-www-form-urlencoded 形式 POST logout_token
        form := url.Values{"logout_token": {lt}}
        req, _ := http.NewRequestWithContext(ctx, http.MethodPost, cl.BackchannelLogoutURI, strings.NewReader(form.Encode()))
        req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        // 简单重试（指数退避）
        for attempt := 0; attempt < 3; attempt++ {
            resp, err := httpc.Do(req)
            if err == nil && resp != nil && resp.StatusCode/100 == 2 { break }
            time.Sleep(time.Duration(1<<attempt) * 200 * time.Millisecond)
        }
    }
}

// --- 工具函数 ---
// readSessionCookie 读取指定名称的会话 Cookie。
func readSessionCookie(c *gin.Context, name string) string {
    if ck, err := c.Request.Cookie(name); err == nil { return ck.Value }
    return ""
}

// urlQueryEscape 使用 QueryEscape 进行最小化转义。
func urlQueryEscape(s string) string {
    return url.QueryEscape(s)
}

func contains(list []string, s string) bool { for _, v := range list { if v == s { return true } } ; return false }

// --- 开发辅助（非生产） ---
// devCreateUser 创建新用户（仅开发环境）。
func (h *Handler) devCreateUser(c *gin.Context) {
    // @Summary      开发 - 创建用户
    // @Tags         dev
    // @Accept       json
    // @Produce      json
    // @Param        body  body  object  true  "{username,password,email,name}"
    // @Success      201   {object} map[string]interface{} "{id,username}"
    // @Failure      400   {object} map[string]string
    // @Router       /dev/users [post]
    type req struct{ Username, Password, Email, Name string }
    var r req
    if err := c.ShouldBindJSON(&r); err != nil { c.JSON(400, gin.H{"error":"bad_json"}); return }
    u, err := h.userSvc.Create(c, r.Username, r.Password, r.Email, r.Name)
    if err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
    c.JSON(201, gin.H{"id": u.ID, "username": u.Username})
}

// devListUsers 列出用户（仅开发环境）。
func (h *Handler) devListUsers(c *gin.Context) {
    // @Summary      开发 - 列出用户
    // @Tags         dev
    // @Produce      json
    // @Success      200 {array} map[string]interface{}
    // @Failure      500 {object} map[string]string
    // @Router       /dev/users [get]
    users, err := h.userSvc.List(c, 100)
    if err != nil { c.JSON(500, gin.H{"error":"db"}); return }
    out := make([]gin.H, 0, len(users))
    for _, u := range users { out = append(out, gin.H{"id":u.ID, "username":u.Username, "email":u.Email, "name":u.Name}) }
    c.JSON(200, out)
}

// devRotateKeys 轮换签名密钥（仅开发环境）。
func (h *Handler) devRotateKeys(c *gin.Context) {
    // @Summary      开发 - 轮换签名密钥
    // @Tags         dev
    // @Success      204 {string} string "No Content"
    // @Failure      500 {object} map[string]string
    // @Router       /dev/keys/rotate [post]
    if err := h.keySvc.Rotate(c); err != nil { c.JSON(500, gin.H{"error":"rotate_failed"}); return }
    c.Status(204)
}
