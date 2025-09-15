# GinkgoID · OpenID Connect 身份提供服务（OIDC OP）

GinkgoID 是基于 Go（Gin 框架）的 OpenID Provider（OP）。提供 OIDC Discovery、JWKS、公认的授权码 + PKCE 流、令牌签发与校验、UserInfo、动态客户端注册、会话管理、RP 发起注销、令牌撤销/内省、监控指标等能力。

该项目采用 MySQL 作为持久化数据存储（用户/客户端/密钥/审计），Redis 管理有状态对象（会话/授权码/刷新令牌/撤销黑名单）。默认开箱即用，适合本地开发与 PoC；生产部署请参考文末“安全与部署建议”。

## 功能特性
- Discovery 与 JWKS：公开 OP 元数据与公钥
- 授权码 + PKCE：支持 S256（默认强制）与可选 Hybrid（code id_token）
- 令牌端点：签发 Access Token（JWT）、ID Token、可选 Refresh Token（offline_access）
- UserInfo：按 scope 返回 claims；可选开启 CORS
- 动态客户端注册：注册/查询/更新/禁用 + Registration Access Token 轮换
- 会话管理：Redis 存储，示例登录/同意页，支持 ACR/AMR、prompt=none/login/consent
- RP 发起注销：Back-channel Logout + Front-channel Logout + post_logout_redirect_uri 校验
- Pairwise Subject：支持 sector_identifier_uri 校验与 pairwise subject 计算
- 令牌撤销与内省：符合 RFC 7009 与 RFC 7662
- 监控与日志：Prometheus 指标、结构化访问日志与审计日志

## 目录结构
```
cmd/server           # 可执行入口（HTTP 服务）
internal/config      # 配置结构、加载与合并
internal/handlers    # HTTP 端点实现（OIDC/OAuth2/注册/运维等）
internal/services    # 领域服务（用户/客户端/会话/码/令牌/密钥/撤销/同意/日志等）
internal/storage     # MySQL / Redis 初始化与模型定义
internal/middlewares # 请求日志 / 安全头 / 限流 等中间件
internal/metrics     # Prometheus 指标定义与 handler
web/                 # 登录/同意/注销等 HTML 模板与 Stoplight 文档页
docs/                # OpenAPI 规范文件 (swagger.json / swagger.yaml)
config.yaml          # 配置示例（可直接使用）
```

## 架构与数据存储
- MySQL：用户（User）、客户端（Client）、签名密钥（JWKKey）、令牌审计（TokenRecord）、审计日志（LogRecord）、授权同意（Consent）。首次启动自动迁移表结构。
- Redis：
  - 会话：`session:<sid>`
  - 授权码：`code:<code>`
  - 刷新令牌：`rt:<token>`
  - 撤销黑名单：`bl:at:<jti>`
- 密钥管理：首次启动自动生成激活签名密钥（RS256/ES256 可配），JWKS 暴露全部历史公钥。

## 端点速览（只列常用）
- `GET /.well-known/openid-configuration` Discovery
- `GET /jwks.json` JWKS（公钥集合）
- `GET /authorize` 授权端点（授权码/Hybrid）
- `POST /token` 令牌端点（authorization_code / refresh_token）
- `GET|POST /userinfo` 用户信息端点
- `POST /revoke` 撤销端点（RFC 7009）
- `POST /introspect` 内省端点（RFC 7662）
- `GET /logout` RP 发起注销（后端/前端通道）
- `GET|POST /login`、`GET|POST /consent` 示例登录与同意页（非生产）
- `GET /check_session` 会话探测 iframe（简化版）
- `GET /metrics` Prometheus 指标；`GET /healthz` 存活探针

## 快速开始
1. 准备依赖：Go 1.22+、MySQL 8+、Redis 6+
2. 创建数据库：
   - `CREATE DATABASE ginkgoid CHARACTER SET utf8mb4;`
3. 配置文件：复制/编辑根目录 `config.yaml`（见下节），保持 MySQL/Redis 可访问。
4. 启动服务：
   - 开发：`go run ./cmd/server`
   - 编译：`go build -o server ./cmd/server && ./server`
5. 自检：浏览器打开 `http://127.0.0.1:8080/.well-known/openid-configuration`

## 配置说明（config.yaml）
核心配置项（完整示例见根目录 `config.yaml`）：
- `env`: 运行环境（`dev`/`prod`）
- `http_addr`: 监听地址（如 `:8080`）
- `issuer`: 对外 Issuer（建议 https 公网域名，反代统一）
- `mysql.*`: MySQL 连接信息
- `redis.*`: Redis 连接信息
- `crypto.id_token_alg`: `RS256` 或 `ES256`
- `token.*`: AT/RT/授权码 TTL、PKCE 策略、注册访问令牌 TTL
- `session.*`: Cookie 名称/域/secure/samesite/会话 TTL
- `pairwise.*`: 是否启用 pairwise 与盐值
- `cors.*`: 是否允许 `/userinfo` 跨域与白名单
- `registration.*`: 动态注册审批/初始访问令牌/sector 校验
- `limits.*`: 登录与令牌端点限流（窗口/阈值）
- `security.hsts.*`: HSTS 头控制（仅 HTTPS 有效）

## 授权码 + PKCE 流程（概要）
1) RP 构造授权请求：`/authorize?response_type=code&client_id=...&redirect_uri=...&scope=openid ... &code_challenge=...&code_challenge_method=S256`
2) 用户完成登录并（必要时）同意，OP 颁发一次性授权码（短 TTL）。
3) RP 使用授权码 + `code_verifier` 调用 `/token` 交换令牌；公共客户端必须使用 PKCE。
4) OP 返回 `access_token`（JWT）与 `id_token`，scope 含 `offline_access` 时附 `refresh_token`。

## 令牌说明
- Access Token：JWT，含 `iss/sub/aud/iat/exp/scope/sid/client_id/uid/jti`
- ID Token：含 `auth_time`、可选 `nonce`、`acr`、`at_hash`、以及按 scope 注入的可选 claims
- Refresh Token：不透明字符串，Redis 保存，使用即旋转

## 动态客户端注册（节选）
- 注册：`POST /register`，返回 `client_id`、可选 `client_secret`、`registration_access_token`
- 管理：
  - 查询：`GET /register?client_id=...`（Bearer `registration_access_token`）
  - 更新：`PUT /register?client_id=...`
  - 禁用：`DELETE /register?client_id=...`
  - 轮换：`POST /register/rotate?client_id=...`
- `sector_identifier_uri`：若提供，将拉取其 JSON 数组并校验覆盖所有 `redirect_uris`

## UserInfo 与 CORS
- 推荐仅使用 `Authorization: Bearer <access_token>` 调用 `/userinfo`
- 可在 `config.yaml` 中开启跨域并设置白名单（默认关闭）

## 注销（RP-Initiated Logout）
- 后端通道：对已登录 RP 异步 POST `logout_token`（JWT）
- 前端通道：渲染 iframe 调用各 RP 前端注销页面
- 支持 `post_logout_redirect_uri` 白名单与 `state` 回传

## OpenAPI 与在线文档
- 在线 UI：启动后访问 `http://127.0.0.1:8080/docs`（Stoplight Elements 渲染）
- 规范文件：默认 `http://127.0.0.1:8080/openapi.json`（指向仓库 `docs/swagger.json`）
- 维护方式（重要）：当注释有更新后，通过下列命令生成/更新 OpenAPI 文档：

  `go run github.com/swaggo/swag/cmd/swag init --generalInfo cmd/server/main.go --output docs`

  该命令会扫描 `cmd/server/main.go` 及处理器注释，输出到 `docs/` 目录。

## 运维与监控
- Prometheus 指标：`/metrics` 暴露 `http_requests_total`、`http_request_duration_seconds`、`tokens_issued_total`
- 健康检查：`/healthz`
- 日志：结构化访问日志 + 审计日志（登录/令牌签发/撤销/注销等）

## 发行与运行
- 本地构建：`make build`，运行：`make run`
- Docker 构建：`make docker`，或 `docker build -t ginkgoid:latest .`
- Docker 编排（含 MySQL/Redis）：`docker compose up -d`，默认暴露 `8080/3306/6379`
- CI：见 `.github/workflows/ci.yml`（build + vet + fmt 检查）

## 开发辅助（仅非 prod）
- `POST /dev/users` 创建用户
- `GET /dev/users` 列出用户
- `POST /dev/keys/rotate` 轮换签名密钥

## 实用示例（cURL 可复制）

以下示例默认 OP 运行在 `http://127.0.0.1:8080` 且使用示例配置。

### 示例：动态注册客户端
- 新注册（public 客户端，PKCE，授权码流）：

  `curl -sS -X POST http://127.0.0.1:8080/register \
    -H 'Content-Type: application/json' \
    -d '{
      "client_name":"Demo App",
      "redirect_uris":["http://127.0.0.1:8080/callback"],
      "grant_types":["authorization_code"],
      "response_types":["code"],
      "token_endpoint_auth_method":"none",
      "scope":"openid profile email"
    }'`

  若配置了 `registration.initial_access_token`，需加请求头：

  `-H "Authorization: Bearer <initial_access_token>"`

- 查询客户端：

  `curl -sS 'http://127.0.0.1:8080/register?client_id=<client_id>' \
    -H 'Authorization: Bearer <registration_access_token>'`

- 更新客户端 redirect_uris：

  `curl -sS -X PUT 'http://127.0.0.1:8080/register?client_id=<client_id>' \
    -H 'Authorization: Bearer <registration_access_token>' \
    -H 'Content-Type: application/json' \
    -d '{"redirect_uris":["http://127.0.0.1:8080/callback"]}'`

- 轮换 Registration Access Token：

  `curl -sS -X POST 'http://127.0.0.1:8080/register/rotate?client_id=<client_id>' \
    -H 'Authorization: Bearer <registration_access_token>'`

- 禁用（删除）客户端：

  `curl -sS -X DELETE 'http://127.0.0.1:8080/register?client_id=<client_id>' \
    -H 'Authorization: Bearer <registration_access_token>'`

### 示例：授权码 + PKCE 流程
1) 生成 `code_verifier` 与 `code_challenge`（S256）：

   `code_verifier=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=') && \
    code_challenge=$(printf %s "$code_verifier" | openssl dgst -binary -sha256 | openssl base64 | tr '+/' '-_' | tr -d '=') && \
    echo "verifier=$code_verifier" && echo "challenge=$code_challenge"`

2) 浏览器发起授权（将占位符替换为实际值）：

   `http://127.0.0.1:8080/authorize?response_type=code&client_id=<client_id>&redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcallback&scope=openid%20profile%20email&code_challenge_method=S256&code_challenge=<code_challenge>&state=xyz`

3) 使用授权码换取令牌（public 客户端用表单字段，机密客户端可用 Basic）：

   `curl -sS -X POST http://127.0.0.1:8080/token \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d grant_type=authorization_code \
     -d code='<authorization_code>' \
     -d redirect_uri='http://127.0.0.1:8080/callback' \
     -d client_id='<client_id>' \
     -d code_verifier="$code_verifier"`

   机密客户端示例（Basic 认证）：

   `curl -sS -X POST http://127.0.0.1:8080/token \
     -u '<client_id>:<client_secret>' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d grant_type=authorization_code \
     -d code='<authorization_code>' \
     -d redirect_uri='http://127.0.0.1:8080/callback' \
     -d code_verifier="$code_verifier"`

4) 使用刷新令牌换新：

   `curl -sS -X POST http://127.0.0.1:8080/token \
     -u '<client_id>:<client_secret_or_empty>' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d grant_type=refresh_token \
     -d refresh_token='<refresh_token>'`

### 示例：UserInfo
- 推荐仅使用 Authorization 头：

  `curl -sS http://127.0.0.1:8080/userinfo -H "Authorization: Bearer <access_token>"`

### 示例：撤销与内省
- 撤销刷新令牌：

  `curl -sS -X POST http://127.0.0.1:8080/revoke \
    -u '<client_id>:<client_secret_or_empty>' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d token='<refresh_token>' \
    -d token_type_hint=refresh_token`

- 撤销访问令牌（基于 jti 加黑）：

  `curl -sS -X POST http://127.0.0.1:8080/revoke \
    -u '<client_id>:<client_secret_or_empty>' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d token='<access_token>'`

- 内省访问令牌：

  `curl -sS -X POST http://127.0.0.1:8080/introspect \
    -u '<client_id>:<client_secret_or_empty>' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -d token='<access_token>'`

### 示例：RP 发起注销
- 浏览器触发并可重定向回 RP：

  `http://127.0.0.1:8080/logout?id_token_hint=<id_token>&post_logout_redirect_uri=<registered_uri>&state=bye`

### 示例：开发辅助接口（仅非 prod）
- 创建用户：

  `curl -sS -X POST http://127.0.0.1:8080/dev/users \
    -H 'Content-Type: application/json' \
    -d '{"username":"alice","password":"Passw0rd!","email":"alice@example.com","name":"Alice"}'`

---

## 安全与部署建议
- 使用 HTTPS 并在反向代理统一 `issuer`，生产开启 `session.cookie_secure=true`，`cookie_samesite=lax/strict`
- 妥善保护 MySQL/Redis 凭据与 `pairwise.salt`
- 动态注册对外开放场景建议启用初始访问令牌、网关白名单或人工审批
- 私钥默认明文存储于 MySQL（便于开发），生产建议接入 KMS/加密存储
- 请按需收紧 `/userinfo` 的 CORS 策略，仅放通受信任来源

---

如需更深入的二次开发或集成，建议从以下文件入手：
- 服务入口与路由：`cmd/server/main.go`
- 核心端点：`internal/handlers/http.go`
- 令牌与密钥：`internal/services/token.go`、`internal/services/keys.go`
- 存储模型：`internal/storage/migrate.go`

欢迎提交 Issue 与 PR！

## Roadmap（规范扩展）
- PAR（Pushed Authorization Requests）
- Request Object（JAR）
- JARM（JWT Secured Authorization Response Mode）
- 更细粒度审计与失败原因指标暴露
