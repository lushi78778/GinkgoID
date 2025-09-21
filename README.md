# GinkgoID — 自托管 OpenID Connect Provider

GinkgoID 是一套易读、可运维、便于二次开发的 OpenID Connect Provider (OIDC OP)。后台使用 Go + Gin + GORM 驱动，前端提供基于 Next.js 的用户/开发者控制台，并内置 Prometheus 指标、审计日志、密钥加密与轮换、动态客户端注册等生产必备能力。仓库目标是让团队可以在本地快速跑起来，稳步演进到上线环境。


- [功能概览](#功能概览)
- [系统架构](#系统架构)
- [目录速览](#目录速览)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [存储层与迁移](#存储层与迁移)
- [密钥管理与安全](#密钥管理与安全)
- [OIDC/OAuth2 端点](#oidcoauth2-端点)
- [前端控制台](#前端控制台)
- [观测与运维](#观测与运维)
- [测试与质量保障](#测试与质量保障)
- [开发工作流](#开发工作流)
- [部署建议](#部署建议)
- [备份与恢复](#备份与恢复)
- [常见问题排查](#常见问题排查)
- [附录：常用命令](#附录常用命令)

## 功能概览

- 标准 OIDC/OAuth2：Discovery、JWKS、`/authorize`（PKCE/Hybrid）、`/token`、`/userinfo`、`/introspect`、`/revoke`、`/logout`、动态注册、会话检查、前后通道登出。
- 安全加固：对称加密存储私钥（AES-256-GCM）、pairwise subject、DPoP 校验、最小 ACR 限制与 MFA 提示、限流中间件、结构化日志、内置初始管理员保护。
- 扩展能力：MySQL 持久化 + Redis 会话，授权记录审计表，客户端审批流，Registration Access Token 轮换，Stoplight 渲染的 OpenAPI 文档。
- 运维支持：Prometheus 指标 `/metrics`、健康检查 `/healthz`、Key 轮换 CLI (`cmd/migrate-keys`)、E2E 探针脚本 (`cmd/e2e`)。
- 前端：`frontend/` 为 Next.js 控制台，构建后产物同步到 `web/app` 并由 Go 服务静态托管；登录与授权保留在 `web/templates/login.html` 以便定制品牌样式。

## 系统架构

```
┌────────────┐   ┌───────────────┐
│ Next.js SPA│◀▶ │ REST / API    │  Gin 路由 + Handlers
└────┬───────┘   │  authorize    │
     │           └───────┬───────┘
     │ 静态资源           │
     ▼                   ▼
 ┌────────┐      ┌────────────────┐
 │ web/app│      │    Services    │ key/token/client/session 等
 └────────┘      └───────┬────────┘
                         │
          ┌──────────────┴──────────────┐
          ▼                             ▼
     MySQL (GORM)                 Redis (会话/票据)
```

- 入口：`cmd/server/main.go` —— 加载配置、初始化 MySQL/Redis、实例化服务层、注册路由、托管静态资源。
- 服务层：`internal/services/` —— 将业务拆分为 key、token、client、session、refresh、consent、dpop、日志等模块。
- 传输层：`internal/handlers/` —— 实现 OIDC/OAuth2 端点、控制台 API、模板渲染。
- 中间件：`internal/middlewares/` —— 请求 ID、JSON 日志、安全头、Prometheus 指标、限流。
- 配置：`internal/config/` + `config.yaml` —— 带默认值的结构化配置加载器。

## 目录速览

| 路径 | 说明 |
| ---- | ---- |
| `cmd/server/` | 主服务入口，负责进程生命周期与 gin 路由注册 |
| `cmd/e2e/` | Go 实现的端到端自测脚本，用于 CI 或本地巡检 |
| `cmd/migrate-keys/` | 将 `jwk_keys.private_key` 从明文迁移到 AES-GCM 加密 |
| `internal/config/` | 配置定义与加载逻辑，含默认值与验证 |
| `internal/handlers/` | HTTP 层实现（OIDC 核心、控制台 API、模板页面） |
| `internal/services/` | 业务逻辑与存储操作封装（client/token/session 等） |
| `internal/storage/` | GORM 模型定义与自动迁移，MySQL/Redis 初始化 |
| `internal/metrics/` | Prometheus 指标定义与中间件 |
| `internal/middlewares/` | 请求日志、安全头、限流、Request ID 等 |
| `docs/` | OpenAPI 规范 (`swagger.json/yaml`)、密钥轮换说明 |
| `frontend/` | Next.js 控制台源代码（详情见 `frontend/README.md`） |
| `web/` | 渲染模板与打包后的静态资源（`web/app` 来自 frontend build） |
| `Makefile` | 常用任务封装（run/build/fmt/lint/swagger/e2e 等） |
| `docker-compose.yml` | 本地一键启动 MySQL + Redis + OP 服务 |

## 快速开始

### 依赖准备

- Go 1.22+
- Node.js 18+（需要构建/开发前端时）
- MySQL 8.x（默认 DSN `root:123456@tcp(127.0.0.1:3306)/ginkgoid`）
- Redis 5+
- 可选：Docker 24+、docker compose plugin

### 本地运行（Go 服务）

```bash
# 复制示例配置并按需修改
cp config.example.yaml config.yaml

# 启动数据库（可选，亦可使用 docker-compose）
mysqld --defaults-file=...
redis-server

# 运行服务
GOENV=dev go run ./cmd/server
# 或
make run
```

验证：
- `http://127.0.0.1:8080/.well-known/openid-configuration`
- `http://127.0.0.1:8080/docs` (Stoplight Elements)
- `http://127.0.0.1:8080/metrics`

### Docker Compose 一键启动

```bash
docker compose up -d --build
# 停止并清理
docker compose down -v
```

Compose 会启动 MySQL、Redis、GinkgoID 三个容器。`docker-compose.yml` 顶部集中列出了可通过环境变量覆盖的镜像与端口配置，记得将本地 `config.yaml`（或 secrets）挂载到 `CONFIG_PATH` 指定位置以供服务读取。

### 前端开发模式

详见 [`frontend/README.md`](frontend/README.md)。快速提示：

```bash
cd frontend
pnpm install   # 或 npm install / yarn
pnpm dev       # Next.js 开发服务器，默认 3000 端口
```

开发期间 Go 服务仍然提供 API。构建后运行 `pnpm build && pnpm postbuild`，静态文件会同步到 `web/app`。

## 配置说明

所有配置通过 `config.yaml` 加载，可被环境变量覆盖（自行扩展）。仓库附带 [`config.example.yaml`](config.example.yaml)，包含常用字段示例；复制为实际 `config.yaml` 后再结合环境变量/密钥管理替换敏感值。`internal/config/config.go` 提供默认值。以下是核心段落：

### 核心项

- `env`: `dev` / `prod`，影响日志等级、GIN 模式等。
- `http_addr`: HTTP 监听地址（如 `:8080`）。
- `issuer`: 必填，公开的 Issuer URL；生产必须为 HTTPS，可与反向代理域名一致。
- `docs`: 控制 `/docs` 页面是否启用以及 swagger 文件路径。

### 数据库与缓存

- `mysql`: host/port/user/password/db/params。`DSN()` 会使用合理默认值（`parseTime=true&charset=utf8mb4`）。
- `redis`: `addr`、`db`、`password`。主要用于会话、授权码、刷新令牌、登出黑名单、DPoP 重放窗口。

### 加密与安全

- `crypto.id_token_alg`: 默认 `RS256`，可切换 `ES256`（需生成 EC P-256 密钥）。
- `crypto.key_encryption_key`: 32 字节字符串（Base64 推荐）。开启后，`jwk_keys.private_key` 字段会使用 AES-256-GCM 加密；服务启动时自动透明解密。
- `pairwise.enable/salt`: 控制 pairwise subject 支持。
- `acr.minimum`: 强制最小 ACR，登录环节会提示提升认证方式；`acr.suggest_mfa` 打开后在登录页提醒开启 MFA。
- `security.hsts`: 是否注入 HSTS 头；生产建议开启。

### Token 与 Session

- `token.access_token_ttl` / `id_token_ttl` / `refresh_token_ttl` / `code_ttl`：各类票据 TTL。
- `token.require_pkce_s256`: 强制所有授权码流程使用 PKCE S256。
- `token.registration_pat_ttl`: Registration Access Token 的过期时间。
- `session.cookie_*`: 会话 cookie 名称、domain、secure、same-site 策略，`ttl` 控制会话在 Redis 中的生存期。

### 动态注册与限流

- `registration.require_approval`: 为 true 时新客户端需要管理员在控制台审批；未审批客户端无法发起授权。非生产环境会自动跳过审批流程，以便本地联调（生产环境仍需显式审批）。
- `registration.initial_access_token`: 配置后，调用 `/register` 必须携带该 Bearer token。
- `limits.login_per_minute` / `token_per_minute`: 控制登录与 token 接口的速率。

### DPoP

- `dpop.replay_window`: 接受的 proof 时间窗口。
- `dpop.clock_skew`: 允许的客户端时钟偏差。

详细字段及默认值请直接阅读 [`config.yaml`](config.yaml) 或 `internal/config/config.go`。

## 存储层与迁移

- MySQL：使用 GORM 自动迁移，模型定义在 [`internal/storage/migrate.go`](internal/storage/migrate.go)。包含 `users`、`clients`、`jwk_keys`、`token_records`、`log_records`、`consents`、`settings` 等表。首次启动时会自动建表。
- Redis：用于短期数据（session、code、refresh、revocation、DPoP、登录限流）。连接配置在 `internal/storage/redis.go`。

建议：
- 正式环境前准备 schema 备份，并在 CI 中执行一次迁移验证。
- 针对老库的兼容 SQL（例如 `ALTER TABLE clients ...`）在启动时自动执行，失败会打 warning 但不终止。

## 密钥管理与安全

### 签名密钥

- 密钥持久化在 `jwk_keys` 表，包含 `kid/alg/private_key/public_key/active` 字段。
- 服务启动时调用 `services.KeyService.EnsureActiveKey`。若表中无 active key，会生成新的 RSA/EC 密钥对。
- `KeyService` 负责：轮换、激活、列出历史公钥供 JWKS。

### 私钥加密

- 设置 `crypto.key_encryption_key` 后，所有新生成的私钥都会先经过 `utils.EncryptAESGCM` 再写入数据库。
- `cmd/migrate-keys` 提供上线前迁移工具，将历史明文私钥加密。运行前确保配置了加密密钥并备份数据库。

### 轮换流程

- 开发模式可调用 `POST /dev/keys/rotate`。
- 正式环境建议使用独立的运维脚本或 CLI（可基于 `services.KeyService.Rotate`）。轮换策略：生成新 key -> 激活 -> JWKS 同时保留旧公钥直到票据过期 -> 清理旧私钥。

### ACR / MFA

- 登录模板 (`web/templates/login.html`) 会根据 `acr_hint`、`suggest_mfa` 参数提示用户使用更强的认证因子。
- Session 对象存储 `AuthTime`、`ACR`。`/authorize` 会校验 `max_age` 或最小 ACR 不满足时强制重登。

### DPoP / Token 绑定

- `services.DPoPVerifier` 使用 Redis 存储 `jti` 防重放，clock skew 与窗口可以配置。
- TokenService 支持通过 `cnf.jkt` 写入访问令牌，配合 DPoP Proof:
  - `/token` 验证 `DPoP` 头，刷新令牌轮换同样要求。

## OIDC/OAuth2 端点

核心路由在 [`internal/handlers`](internal/handlers) 注册：

- `GET /.well-known/openid-configuration`：Discovery 文档。
- `GET /jwks.json`：当前与历史公钥集合。
- `GET /authorize`：授权码/Hybrid 流程，支持 PKCE、prompt=none、ACR hints。
- `POST /token`：授权码交换、刷新令牌、Client Credentials（如启用）、DPoP。
- `POST /revoke`、`POST /introspect`：标准 OAuth2 端点。
- `GET /userinfo`：支持 Bearer Token 或 DPoP 访问，按 scope 返回 profile/email。
- `GET /logout`、`POST /logout/backchannel`：前后通道登出。
- `POST /register` / `GET|PUT /register` / `POST /register/rotate`：动态客户端注册与 Registration Access Token 管理。
- `GET /dev/*`：仅 dev 环境开放的便捷接口（创建测试用户、轮换密钥等）。
- 控制台 API (`/api/*`)：用户信息、授权列表、审计日志、客户端管理。详见 `internal/handlers/api.go`、`api_console.go`。

所有 API 均带 Swagger 注释。更新 handler 注释后执行：

```bash
make swagger  # 生成 docs/swagger.json
```

## 前端控制台

- 源码在 [`frontend/`](frontend/)，使用 Next.js 14 (App Router) + Tailwind + Radix UI。
- `package.json` 中定义 `build -> next build`，`postbuild` 负责将 `frontend/out` 复制到 `web/app` 目录，供 Go 服务静态托管。
- 运行时 `cmd/server` 会优先查找 `web/app/index.html` 并提供 `/assets`、`/_next` 静态文件。
- `Providers` 组件注入 `AuthProvider`、主题切换、全局样式，支持控制台导航与角色（用户/开发者/管理员）切换菜单。
- 登录与授权页面仍由 `web/templates/login.html` 渲染，方便做极简部署或自定义品牌。

更细的前端文档请看 [`frontend/README.md`](frontend/README.md)。

## 观测与运维

- **日志**：使用 Logrus JSON Formatter，字段包括 `request_id`、`session_id`、`client_id`、`outcome` 等。核心日志通过 `services.LogService` 写入 `log_records` 表，便于审计。
- **指标**：`/metrics` 暴露 Prometheus 指标（请求计数、请求耗时、authorize 错误计数、令牌签发计数）。中间件位于 `internal/metrics/metrics.go`。
- **健康检查**：`/healthz` 简单返回 200；可根据需要扩展数据库/Redis 连通性检测。
- **OpenAPI**：`/docs` 使用 Stoplight Elements 将 `docs/swagger.json` 渲染为交互式文档。

## 测试与质量保障

- 单元测试：`go test ./...`
- E2E：`go run ./cmd/e2e -base http://127.0.0.1:8080`，脚本会执行 Discovery、动态注册、完整授权码 + PKCE 流程、Refresh Token、Logout、Revocation 等。
- Lint/Vet：`make ci` 会串行执行 `fmt vet build`。
- Swagger 校验：`make swagger` 生成文档后应将 `docs/swagger.json` 提交。
- 前端：`cd frontend && pnpm lint && pnpm test`（如后续添加测试）。

## 开发工作流

1. 创建或更新 handler/service 时补充 Swagger 注释与单元测试。
2. 使用 `make fmt` / `go fmt` 规范代码，必要时运行 `go vet`。
3. 修改存储层结构时更新 `internal/storage/migrate.go`，避免直接手写 SQL 漏掉自动迁移。
4. 前端改动需同步运行 `pnpm build && pnpm postbuild`，确保 `web/app` 中产物与服务器契合。
5. 提交前跑一次 `make ci` + `go test ./...` + （可选）`go run ./cmd/e2e`。

## 部署建议

- **反向代理**：建议在 Nginx/Traefik/Ingress 处终止 TLS，再将流量转发到 GinkgoID（内部 HTTP）。确保 `issuer` 指向公开域名（HTTPS）。
- **TLS**：生产必须启用 HTTPS，Cookie 设置 `secure=true`，必要时 `same_site=strict`。
- **配置管理**：不要直接在仓库中提交敏感配置。可以通过 CI 将 `config.yaml` 模板与环境变量结合，或在容器中挂载 Secrets。
- **密钥保护**：`crypto.key_encryption_key` 可由 Vault/KMS 下发；轮换流程提前演练。
- **扩展**：服务默认单实例。若要横向扩展，确保 Redis/数据库对会话、限流、DPoP 等共享；同时考虑开放 JWKS 缓存、请求日志集中化。
- **容器化**：仓库提供注释化 `Dockerfile`（可通过 `GO_VERSION`、`ALPINE_VERSION`、`APP_NAME` 等 `ARG` 调整构建），以及 `docker-compose.yml` 示例（文件头集中列出可覆盖的镜像/端口环境变量）。部署到 Kubernetes 时记得挂载配置文件与静态资源（或提前 bake 进镜像）。

## 备份与恢复

- MySQL：使用 `mysqldump` 或物理备份，至少每日一次。恢复后验证 `clients`、`users`、`jwk_keys` 与 `consents` 数据完整性。
- Redis：启用 AOF/RDB，定期复制快照。恢复后重新加载即可，无需手工迁移。
- 密钥：下载 MySQL 备份前确保 `jwk_keys` 私钥已加密。恢复后第一次启动务必验证 JWKS 暴露的公钥正确。

演练流程：恢复数据库 -> 启动服务 -> 执行 `cmd/e2e` -> 验证授权正常。

## 常见问题排查

- `login_required` / `prompt=none` 失败：检查会话是否过期、`max_age` 是否过小，或最小 ACR 未满足。
- `redirect_uri mismatch`：客户端的 redirect URI 未登记，检查 `/register` 的记录。
- Token 验证失败（`kid` 不存在）：确认最近是否轮换过密钥，JWKS 是否同步。必要时清理客户端缓存。
- 私钥解密失败：`crypto.key_encryption_key` 不匹配。若在生产，建议回滚到旧配置并重新部署。
- Redis 连接错误：确认 `redis.addr/db/password`，必要时重启 Redis 并检查网络安全组。
- `/docs` 404：执行 `make swagger` 生成 `docs/swagger.json`，并保证 `docs.enable` 设置为 true。

## 附录：常用命令

```bash
# 运行服务（开发）
go run ./cmd/server

# 构建二进制
go build -o ginkgoid ./cmd/server

# 生成 OpenAPI 文档
make swagger

# 端到端巡检
make e2e

# Docker 镜像
docker build -t ginkgoid:latest .

# 清理构建产物与缓存
make clean

# 加密历史私钥
go run ./cmd/migrate-keys -confirm

# 生成随机 32 字节密钥
head -c 32 /dev/urandom | base64
```

欢迎提 Issue / PR。
