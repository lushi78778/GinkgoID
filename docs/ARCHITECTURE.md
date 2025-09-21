# GinkgoID Architecture Overview

本项目实现面向自托管 OIDC/OpenID Provider 的平台。代码按 "cmd / internal / web" 三层划分，以便在保持清晰依赖方向的同时，方便扩展新的运行入口。

## 目录结构

- `cmd/`：进程入口。`server` 负责 HTTP 服务启动，`migrate-keys` 等 CLI 负责一次性运维任务。
- `internal/config/`：配置加载、默认值与文件合并逻辑，向上游暴露 `config.Config` 结构体。
- `internal/storage/`：数据库（MySQL）与缓存（Redis）初始化、GORM 模型、自动迁移。
- `internal/services/`：领域服务层，将存储操作、加密、协议细节聚合为易复用的业务接口。
- `internal/handlers/`：基于 Gin 的 HTTP 处理器，负责路由注册、入参校验与调用服务层。
- `internal/middlewares/`：通用 HTTP 中间件，如请求日志、安全头、指标采集。
- `internal/metrics/`：Prometheus 指标定义与注册。
- `internal/utils/`：跨模块的纯辅助函数。
- `frontend/` 与 `web/`：控制台前端的构建产物。
- `docs/`：开放 API 规范与运行手册。

## 启动流程

1. **配置加载**：`config.Load()` 合并默认值与 `config.yaml`，在 `cmd/server` 中完成。
2. **存储初始化**：`storage.InitMySQL`/`InitRedis` 建立连接，并通过 `autoMigrate` 保证结构符合预期。
3. **服务注册**：`services.New*` 构造核心服务，如密钥轮换、客户端注册、令牌发放等。
4. **HTTP 层装配**：`handlers.New` 挂载 API、OIDC、静态资源，并附加中间件与指标。
5. **运行与退出**：Gin 监听指定地址，收到 SIGINT/SIGTERM 时执行优雅关闭。

## 关键业务流

### 动态客户端注册

- `handlers.registration` 负责解析请求并调用 `services.ClientService.Register`。
- 新逻辑将校验、默认值、持久化集中在 `prepareRegistrationPlan` 中，生成响应与存储模型。
- 注册成功后仅返回一次明文 `client_secret` 与 `registration_access_token`，数据库中存储其哈希。

### 授权与发令牌

- 授权端点在 `internal/handlers/authorize.go`，校验用户会话与 PKCE。
- 令牌发放由 `services.TokenService`、`CodeService`、`RefreshService` 等协同完成，并写入 Redis。

### 审计与指标

- 所有关键动作借助 `services.LogService` 写入 MySQL，便于事后审计。
- `internal/metrics` 暴露 Prometheus 指标，`middlewares.RequestLogger`/`metrics.Handler` 统一上报。

## 后续扩展建议

- 引入 `golangci-lint` 作为 `make lint` 默认实现。
- 为服务层补充 unit test，覆盖注册、令牌颁发等关键路径。
- 将前端构建流程接入 CI，保证 `web/` 与后端接口保持一致。

