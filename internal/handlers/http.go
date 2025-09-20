package handlers

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"

	"ginkgoid/internal/config"
	"ginkgoid/internal/middlewares"
	"ginkgoid/internal/services"
)

// Handler 聚合所有依赖（配置、存储、服务）并注册所有 HTTP 路由。
type Handler struct {
	cfg          config.Config
	keySvc       *services.KeyService
	clientSvc    *services.ClientService
	userSvc      *services.UserService
	sessionSvc   *services.SessionService
	tokenSvc     *services.TokenService
	codeSvc      *services.CodeService
	consentSvc   *services.ConsentService
	refreshSvc   *services.RefreshService
	revokeSvc    *services.RevocationService
	logSvc       *services.LogService
	tokenRepo    *services.TokenRepo
	rdb          *redis.Client
	dpopVerifier *services.DPoPVerifier
	settingSvc   *services.SettingService
}

// New 构造 Handler，将各领域服务注入，用于后续路由注册与处理。
func New(cfg config.Config, ks *services.KeyService, cs *services.ClientService, us *services.UserService, ss *services.SessionService, ts *services.TokenService, codes *services.CodeService, cons *services.ConsentService, rs *services.RefreshService, rv *services.RevocationService, ls *services.LogService, tr *services.TokenRepo, rdb *redis.Client, dv *services.DPoPVerifier, settings *services.SettingService) *Handler {
	return &Handler{cfg: cfg, keySvc: ks, clientSvc: cs, userSvc: us, sessionSvc: ss, tokenSvc: ts, codeSvc: codes, consentSvc: cons, refreshSvc: rs, revokeSvc: rv, logSvc: ls, tokenRepo: tr, rdb: rdb, dpopVerifier: dv, settingSvc: settings}
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
	r.POST("/token", middlewares.RateLimit(h.rdb, "token", h.cfg.Limits.TokenPerMinute, func() time.Duration {
		if h.cfg.Limits.Window > 0 {
			return h.cfg.Limits.Window
		}
		return time.Minute
	}(), func(c *gin.Context) string {
		id, _, ok := c.Request.BasicAuth()
		if !ok {
			id = c.PostForm("client_id")
		}
		if id == "" {
			return c.ClientIP()
		}
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
	r.POST("/login", middlewares.RateLimit(h.rdb, "login", h.cfg.Limits.LoginPerMinute, func() time.Duration {
		if h.cfg.Limits.Window > 0 {
			return h.cfg.Limits.Window
		}
		return time.Minute
	}(), func(c *gin.Context) string { return c.ClientIP() }), h.loginSubmit)
	r.GET("/consent", h.consentPage)
	r.POST("/consent", h.consentSubmit)

	// 运维端点
	r.GET("/metrics", h.metrics)
	r.GET("/healthz", h.healthz)

	// 用户自服务与管理 API（JSON）
	h.registerAPIRoutes(r)

	// 开发辅助接口：创建用户、列出用户、轮换密钥
	if h.cfg.Env != "prod" {
		r.POST("/dev/users", h.devCreateUser)
		r.GET("/dev/users", h.devListUsers)
		r.POST("/dev/keys/rotate", h.devRotateKeys)
	}
}
