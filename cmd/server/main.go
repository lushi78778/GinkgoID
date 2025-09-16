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
	}).Info("configuration loaded")

	// 初始化存储（MySQL + Redis）
	db, err := storage.InitMySQL(cfg)
	if err != nil {
		log.WithError(err).Fatal("failed to connect mysql")
	}
	defer storage.CloseMySQL(db)

	rdb, err := storage.InitRedis(cfg)
	if err != nil {
		log.WithError(err).Fatal("failed to connect redis")
	}
	defer func() { _ = rdb.Close() }()

	// 初始化核心服务
	keySvc := services.NewKeyService(db, cfg)
	if err := keySvc.EnsureActiveKey(context.Background()); err != nil {
		log.WithError(err).Fatal("ensure active signing key")
	}
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
	h := handlers.New(
		cfg, keySvc, clientSvc, userSvc, sessionSvc, tokenSvc, codeSvc, consentSvc, refreshSvc, revokeSvc, logSvc, tokenRepo, rdb,
	)
	h.RegisterRoutes(router)
	// 用户管理 SPA（/app）静态资源与入口页
	if p := config.FirstExisting("web/app/index.html", "../web/app/index.html", "../../web/app/index.html"); p != "" {
		// 计算 assets 目录位置
		var base string
		if strings.HasSuffix(p, "/index.html") {
			base = p[:len(p)-len("/index.html")]
		} else {
			base = p
		}
		router.Static("/app/assets", base+"/assets")
		router.GET("/app", func(c *gin.Context) { c.File(p) })
		// 使用 NoRoute 处理 /app/* 的前端路由，避免与 /app/assets 冲突
		router.NoRoute(func(c *gin.Context) {
			path := c.Request.URL.Path
			if path == "/app" || strings.HasPrefix(path, "/app/") {
				c.File(p)
				return
			}
		})
	}
	// OpenAPI 文档（Stoplight Elements）与静态规范（受配置 docs.enable 控制）
	if cfg.Docs.Enable {
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
	}

	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: router}
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

// 说明：firstExisting 的逻辑已统一移至 config.FirstExisting，避免重复实现。
