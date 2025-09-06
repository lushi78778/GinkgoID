// sso-server 启动入口：加载配置与日志，初始化 DB/Redis，
// 执行 AutoMigrate，完成 JWK 与管理员引导，并启动 HTTP 服务。
//
// @title           GinkgoID OpenAPI
// @version         1.0
// @description     GinkgoID 提供的公开 OIDC 端点与管理后台 API。
// @contact.name    GinkgoID
// @BasePath        /
// @schemes         http https
// @securityDefinitions.apikey Session
// @in              cookie
// @name            sid
// @securityDefinitions.apikey CSRF
// @in              header
// @name            X-CSRF-Token
// @tag.name        Public
// @tag.description 健康与诊断等公共端点（/healthz、/readyz、/metrics、/debug/vars 等）
// @tag.name        OIDC
// @tag.description 认证与 OIDC 流程相关 API（/login、/authorize、/token、/userinfo、/logout、/.well-known/openid-configuration 等）
// @tag.name        Admin
// @tag.description 管理后台 API（/admin/api/...），需会话与 CSRF 校验
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ginkgoid/internal/infra/cache"
	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/infra/logx"
	"ginkgoid/internal/infra/migrate"
	"ginkgoid/internal/server"
	"ginkgoid/internal/service/jwk"
	"ginkgoid/internal/service/user"
)

func main() {
	// 加载配置（支持环境变量覆盖）
	if err := config.Load(); err != nil {
		fmt.Println("config load error:", err)
		os.Exit(1)
	}

	// 初始化日志
	logger, err := logx.Init()
	if err != nil {
		fmt.Println("logger init error:", err)
		os.Exit(1)
	}
	defer logger.Sync()

	// 配置合法性校验
	if err := config.Validate(); err != nil {
		fmt.Println("config validation error:", err)
		os.Exit(1)
	}

	// 初始化数据库
	if err := db.Init(config.C().DB); err != nil {
		logger.Fatal("db init failed", logx.Err(err))
	}
	defer db.Close()

	// 初始化 Redis（可选）
	if err := cache.Init(config.C().Redis); err != nil {
		logger.Fatal("redis init failed", logx.Err(err))
	}
	defer cache.Close()

	// 迁移：按开关执行 AutoMigrate（开发默认开启，生产建议关闭）
	if config.C().Server.AutoMigrate {
		if err := migrate.AutoMigrate(); err != nil {
			logger.Fatal("auto-migrate failed", logx.Err(err))
		} else {
			logger.Info("auto-migrate completed")
		}
	} else {
		logger.Info("auto-migrate skipped (server.auto_migrate=false)")
	}

	// 启动自检：DB/Redis Ping
	if err := db.G().Exec("SELECT 1").Error; err != nil {
		logger.Fatal("db ping failed", logx.Err(err))
	} else {
		logger.Info("db ping ok")
	}
	if config.C().Redis.Enabled && cache.R() != nil {
		if err := cache.R().Ping(context.Background()).Err(); err != nil {
			logger.Fatal("redis ping failed", logx.Err(err))
		} else {
			logger.Info("redis ping ok")
		}
	}

	// 确保每种算法至少存在一把激活密钥
	if err := jwk.EnsureActive(context.Background()); err != nil {
		logger.Fatal("ensure jwk failed", logx.Err(err))
	} else {
		logger.Info("jwk ensure active ok")
	}

	// 引导管理员用户（创建/修复密码/角色）
	if err := user.BootstrapAdmin(context.Background()); err != nil {
		logger.Fatal("bootstrap admin failed", logx.Err(err))
	} else {
		logger.Info("bootstrap admin ok", logx.String("username", config.C().Admin.Bootstrap.Username))
	}

	// 启动 HTTP 服务
	r := server.NewRouter()
	srv := &http.Server{Addr: config.C().Server.Addr, Handler: r}

	go func() {
		logger.Info("http server starting", logx.String("addr", config.C().Server.Addr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("listen failed", logx.Err(err))
		}
	}()

	// 关停：监听信号并在超时时间内关闭
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("server shutdown", logx.Err(err))
	}
}
