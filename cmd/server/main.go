package main

// @title           GinkgoID OIDC OP API
// @version         0.1.0
// @description     基于 Go(Gin) 的 OpenID Provider，实现 Discovery、JWKS、授权码+PKCE、Token、UserInfo、动态注册、注销、撤销、内省等接口。
// @contact.name    GinkgoID Team
// @contact.url     https://xray.top
// @contact.email   lushi78778@xray.top
// @schemes         http https
// @BasePath        /
// @securityDefinitions.basic BasicAuth
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"ginkgoid/internal/config"
	"ginkgoid/internal/handlers"
	"ginkgoid/internal/metrics"
	"ginkgoid/internal/middlewares"
	"ginkgoid/internal/services"
	"ginkgoid/internal/storage"
)

// main 为 OP 服务入口：加载配置、初始化日志/存储/服务、注册路由并启动 HTTP 服务。
func main() {
	// 配置结构化日志格式
	log.SetFormatter(&log.JSONFormatter{TimestampFormat: time.RFC3339Nano})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)

	startup := time.Now()
	cfgLoadStart := time.Now()
	// 加载配置（以配置文件为主，配合内置默认值）
	cfg := config.Load()
	if strings.TrimSpace(cfg.Issuer) == "" {
		log.Fatal("configuration error: issuer must be set (config.yaml)")
	}
	// 生产环境基线检查：禁止默认弱口令/盐与默认数据库密码进入生产。
	if cfg.Env == "prod" {
		if cfg.MySQL.Password == "123456" || cfg.MySQL.Password == "password" || cfg.MySQL.Password == "" {
			log.Fatal("insecure mysql password in prod; configure mysql.password in config.yaml")
		}
		if strings.Contains(cfg.MySQL.User, "root") {
			log.Warn("using MySQL root in prod is discouraged")
		}
		if cfg.Pairwise.Enable && cfg.Pairwise.Salt == "dev-pairwise-salt-change-me" {
			log.Fatal("insecure pairwise salt in prod; set pairwise.salt")
		}
		if cfg.Bootstrap.InitialAdmin.Enable && (cfg.Bootstrap.InitialAdmin.Password == "123465" || cfg.Bootstrap.InitialAdmin.Password == "") {
			log.Fatal("insecure initial_admin.password in prod; disable bootstrap or set strong password")
		}
	}
	log.WithFields(log.Fields{
		"env":           cfg.Env,
		"http_addr":     cfg.HTTPAddr,
		"mysql_dsn":     cfg.MySQL.DSNMasked(),
		"redis_addr":    cfg.Redis.Addr,
		"issuer":        cfg.Issuer,
		"cors_userinfo": cfg.CORS.EnableUserInfo,
		"took_ms":       time.Since(cfgLoadStart).Milliseconds(),
	}).Info("configuration loaded")

	// 初始化存储（MySQL + Redis）
	mysqlStart := time.Now()
	db, err := storage.InitMySQL(cfg)
	if err != nil {
		log.WithError(err).Fatal("failed to connect mysql")
	}
	defer storage.CloseMySQL(db)
	log.WithFields(log.Fields{
		"stage":   "storage.mysql",
		"took_ms": time.Since(mysqlStart).Milliseconds(),
	}).Info("mysql connected")

	redisStart := time.Now()
	rdb, err := storage.InitRedis(cfg)
	if err != nil {
		log.WithError(err).Fatal("failed to connect redis")
	}
	defer func() { _ = rdb.Close() }()
	log.WithFields(log.Fields{
		"stage":   "storage.redis",
		"took_ms": time.Since(redisStart).Milliseconds(),
	}).Info("redis connected")

	// 初始化核心服务
	svcInitStart := time.Now()
	keySvc := services.NewKeyService(db, cfg)
	keyEnsureStart := time.Now()
	if err := keySvc.EnsureActiveKey(context.Background()); err != nil {
		log.WithError(err).Fatal("ensure active signing key")
	}
	log.WithFields(log.Fields{
		"stage":   "services.ensure_active_key",
		"took_ms": time.Since(keyEnsureStart).Milliseconds(),
	}).Info("active signing key ready")
	clientSvc := services.NewClientService(db, cfg)
	userSvc := services.NewUserService(db)
	consentSvc := services.NewConsentService(db)
	sessionSvc := services.NewSessionService(rdb, cfg)
	tokenSvc := services.NewTokenService(cfg, keySvc)
	codeSvc := services.NewCodeService(rdb, cfg)
	refreshSvc := services.NewRefreshService(rdb, cfg)
	revokeSvc := services.NewRevocationService(rdb)
	logSvc := services.NewLogService(db)
	tokenRepo := services.NewTokenRepo(db)
	dpopVerifier := services.NewDPoPVerifier(rdb, cfg.DPoP.ReplayWindow, cfg.DPoP.ClockSkew)
	settingSvc := services.NewSettingService(db)
	log.WithFields(log.Fields{
		"stage":   "services.init",
		"took_ms": time.Since(svcInitStart).Milliseconds(),
	}).Info("core services ready")

	// HTTP 路由与中间件
	if cfg.Env == "prod" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(middlewares.RequestID())
	router.Use(middlewares.RequestLogger())
	router.Use(middlewares.SecurityHeaders(cfg))
	router.Use(metrics.Handler())

	// 装载 HTTP 处理器
	handlerStart := time.Now()
	h := handlers.New(
		cfg, keySvc, clientSvc, userSvc, sessionSvc, tokenSvc, codeSvc, consentSvc, refreshSvc, revokeSvc, logSvc, tokenRepo, rdb, dpopVerifier, settingSvc,
	)
	h.RegisterRoutes(router)
	log.WithFields(log.Fields{
		"stage":   "router.register_api",
		"took_ms": time.Since(handlerStart).Milliseconds(),
	}).Info("api routes registered")
	// 用户管理 SPA 静态资源与入口页（Next.js 导出的 web/app）
	spaStart := time.Now()
	spaIndex := config.FirstExisting("web/app/index.html", "../web/app/index.html", "../../web/app/index.html")
	if spaIndex != "" {
		// 计算 assets 目录位置
		var base string
		if strings.HasSuffix(spaIndex, "/index.html") {
			base = spaIndex[:len(spaIndex)-len("/index.html")]
		} else {
			base = spaIndex
		}
		router.Static("/assets", base+"/assets")
		if info, err := os.Stat(filepath.Join(base, "_next")); err == nil && info.IsDir() {
			router.Static("/_next", filepath.Join(base, "_next"))
		}
		serveFile := func(c *gin.Context, requestPath string) {
			rel := strings.TrimPrefix(requestPath, "/")
			candidate := filepath.Join(base, rel)
			candidate = filepath.Clean(candidate)
			if !strings.HasPrefix(candidate, base) {
				c.Status(http.StatusNotFound)
				return
			}
			if info, err := os.Stat(candidate); err == nil {
				if info.IsDir() {
					idx := filepath.Join(candidate, "index.html")
					if htmlInfo, err := os.Stat(idx); err == nil && !htmlInfo.IsDir() {
						c.File(idx)
						return
					}
				} else {
					c.File(candidate)
					return
				}
			}
			if info, err := os.Stat(filepath.Join(base, "404/index.html")); err == nil && !info.IsDir() {
				c.File(filepath.Join(base, "404/index.html"))
				return
			}
			c.File(spaIndex)
		}
		router.GET("/", func(c *gin.Context) { c.File(spaIndex) })
		router.NoRoute(func(c *gin.Context) {
			path := c.Request.URL.Path
			if strings.HasPrefix(path, "/api") || strings.HasPrefix(path, "/metrics") || strings.HasPrefix(path, "/healthz") {
				c.Status(http.StatusNotFound)
				return
			}
			if path == "/" {
				c.File(spaIndex)
				return
			}
			serveFile(c, path)
		})
		log.WithFields(log.Fields{
			"stage":   "router.spa_mount",
			"took_ms": time.Since(spaStart).Milliseconds(),
			"index":   spaIndex,
		}).Info("spa assets mounted")
	} else {
		log.WithFields(log.Fields{
			"stage":   "router.spa_mount",
			"took_ms": time.Since(spaStart).Milliseconds(),
		}).Info("spa assets not found")
	}
	// OpenAPI 文档（Stoplight Elements）与静态规范（受配置 docs.enable 控制）
	if cfg.Docs.Enable {
		docRouteStart := time.Now()
		router.GET("/openapi.json", func(c *gin.Context) {
			if p := config.FirstExisting(cfg.Docs.SpecPath, "docs/swagger.json", "../docs/swagger.json", "../../docs/swagger.json"); p != "" {
				c.File(p)
				return
			}
			c.String(404, "openapi spec not found")
		})
		route := cfg.Docs.Route
		if route == "" {
			route = "/docs"
		}
		router.GET(route, func(c *gin.Context) {
			if p := config.FirstExisting(cfg.Docs.PagePath, "web/stoplight.html", "../web/stoplight.html", "../../web/stoplight.html"); p != "" {
				c.File(p)
				return
			}
			c.String(404, "docs page not found")
		})
		log.WithFields(log.Fields{
			"stage":   "router.docs",
			"took_ms": time.Since(docRouteStart).Milliseconds(),
		}).Info("docs routes ready")
	}

	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: router}
	log.WithFields(log.Fields{
		"stage":   "startup.ready",
		"took_ms": time.Since(startup).Milliseconds(),
	}).Info("startup sequence complete")
	go func() {
		log.WithField("addr", cfg.HTTPAddr).Info("starting http server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.WithError(err).Fatal("listen")
		}
	}()

	// 优雅退出
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.WithError(err).Error("server shutdown")
	} else {
		log.Info("server stopped")
	}
}
