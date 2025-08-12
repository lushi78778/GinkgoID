# GinkgoID

> 轻量级、标准化的 OpenID Connect 身份提供方（OP），用于为单个或少量站点提供 SSO 能力。实现授权码 + PKCE、ID/Access Token（JWT）、Discovery/JWKS、UserInfo、同意页、RP 发起登出，以及基于 Layui 的管理后台。支持 SQLite/MySQL，Redis 可选。

---

## 目录

- [特性](#特性)
- [系统要求](#系统要求)
- [架构与目录](#架构与目录)
- [快速开始](#快速开始)
  - [配置](#配置)
  - [运行](#运行)
  - [Docker](#docker)
  - [数据库迁移与初始化](#数据库迁移与初始化)
- [端点与协议](#端点与协议)
  - [Discovery](#discovery)
  - [/authorize](#authorize)
  - [/token](#token)
  - [/userinfo](#userinfo)
  - [/jwksjson](#jwksjson)
  - [/logout](#logout)
- [同意页（Consent）](#同意页consent)
- [管理后台](#管理后台)
- [数据模型](#数据模型)
- [安全与合规（中国大陆）](#安全与合规中国大陆)
- [站点（RP）接入说明](#站点rp接入说明)
- [开发指南](#开发指南)
  - [编码规范](#编码规范)
  - [错误码与返回体](#错误码与返回体)
  - [测试与质量](#测试与质量)
  - [日志与可观测](#日志与可观测)
- [版本与发布](#版本与发布)
- [许可证](#许可证)

---

## 特性

- OpenID Connect 核心：
  - 授权码 + **PKCE (S256)**。
  - **ID Token / Access Token**（JWT，RS256/ES256）。
  - `/.well-known/openid-configuration`、`/jwks.json`、`/userinfo`。
  - **RP 发起登出**（清除 OP 会话并可回跳）。
- 交互：
  - 登录页（用户名/密码）。
  - **同意页**：首登或扩大 scope 时展示，可记住授权。
- 管理后台（Layui）：
  - 客户端、用户、同意记录、密钥管理（KID 轮换）。
- 存储：SQLite（单机）/ MySQL（生产）；Redis（授权码/state/会话，按需启用）。
- 非目标（MVP）：
  - 不实现 Refresh Token、撤销列表、Introspection、Revocation、SLO 广播、联邦登录、MFA。

---

## 系统要求

- Go 1.22+
- SQLite（WAL 模式）或 MySQL 8+
- 可选：Redis 6/7
- 反向代理：Caddy/Nginx（TLS/HSTS）

---

## 架构与目录

```
Browser/RP → TLS → Caddy/Nginx → Gin(OP)
                                  ├─ SQLite/MySQL
                                  └─ Redis(可选：code/state/session)
```

```
/
├── api                          # 对外数据结构（最小）
├── hack                         # CLI：初始化用户/客户端、JWK 轮换
├── internal
│   ├── cmd                      # serve/cli 入口
│   ├── consts                   # 常量：TTL/Scopes/Cookie 等
│   ├── controller               # authorize/token/userinfo/jwks/login/logout + admin API
│   ├── dao                      # users/clients/auth_codes/jwks/sessions 的 DB/Redis 访问
│   ├── model
│   │   ├── do                   # 条件/输入结构
│   │   └── entity               # 表实体映射
│   └── service                  # AuthN、Consent、OIDC、Token、JWK、Session
├── manifest
│   ├── config                   # YAML 配置
│   └── docker                   # Dockerfile/compose
├── resource                     # 登录/同意/后台(Layui) 模板与静态资源
├── utility                      # 加密/随机/校验/时间
├── go.mod
└── main.go
```

---

## 快速开始

### 配置

`manifest/config/config.yaml`

```yaml
server:
  addr: ":8080"
  public_base_url: "https://sso.example.com"
  cookie_domain: "example.com"
  secure_cookies: true

db:
  driver: "sqlite"   # "mysql"
  dsn: "file:sso.db?_busy_timeout=10000&_journal_mode=WAL"
# dsn(mysql): "user:pass@tcp(127.0.0.1:3306)/ginkgoid?parseTime=true&charset=utf8mb4"

redis:
  enabled: false
  addr: "127.0.0.1:6379"
  db: 0

oidc:
  issuer: "https://sso.example.com"
  scopes: ["openid","profile","email"]
  id_token_ttl: "10m"
  access_token_ttl: "15m"
  force_pkce: true
  force_nonce: true

consent:
  version: 1
  remember_default: true
  expire_days: 365

security:
  login_rate_per_min: 30
  token_rate_per_min: 120
  password_hash: "bcrypt"   # 或 "argon2id"
  hsts: true
  log_retain_days: 180

admin:
  bootstrap:
    username: "admin"
    password: "ChangeMe_123"
```

### 运行

```bash
go mod tidy
go run ./cmd/sso-server
```

访问：
- 管理后台：`https://sso.example.com/admin/`
- 登录页：`https://sso.example.com/login`
- 发现文档：`https://sso.example.com/.well-known/openid-configuration`

### Docker

`manifest/docker/docker-compose.yml`

```yaml
services:
  sso:
    build: ../..
    ports: ["8080:8080"]
    environment:
      - GIN_MODE=release
    volumes:
      - ../config:/app/config
# 可追加 mysql/redis/caddy 等服务
```

### 数据迁移与初始化

- 迁移：使用内置迁移或 `gorm.AutoMigrate`。
- 初始化管理员与客户端（CLI）：

```bash
go run ./hack/ginkgoctl init   --admin "admin:ChangeMe_123"   --client-id demo-web   --client-secret "ChangeMe_Secret"   --redirect-uris "http://127.0.0.1:8081/cb"   --post-logout-uris "http://127.0.0.1:8081/logout-cb"   --scopes "openid,profile,email"
```

---

## 端点与协议

### Discovery

`GET /.well-known/openid-configuration`

关键字段：
- `issuer`、`authorization_endpoint`、`token_endpoint`、`userinfo_endpoint`、`jwks_uri`
- `response_types_supported=["code"]`
- `grant_types_supported=["authorization_code"]`
- `code_challenge_methods_supported=["S256"]`
- `id_token_signing_alg_values_supported=["RS256","ES256"]`
- `scopes_supported=["openid","profile","email"]`

### /authorize

`GET /authorize`

必备参数：
- `response_type=code`
- `client_id`
- `redirect_uri`（**完全匹配**注册白名单）
- `scope`（包含 `openid`）
- `state`
- `nonce`（开启 `force_nonce` 时必需）
- `code_challenge` + `code_challenge_method=S256`

行为：
1. 未登录：302 至 `/login`。
2. 已登录：根据同意规则决定是否展示同意页；通过后生成一次性 `code`（仅存哈希，TTL 60–120s），302 回跳：`?code&state`。

错误回跳（示例）：
```
HTTP/302 Location: {redirect_uri}?error=invalid_request&error_description=...
```

### /token

`POST /token`（`Content-Type: application/x-www-form-urlencoded`）

- `grant_type=authorization_code`
- `code`
- `redirect_uri`
- `code_verifier`
- 客户端认证：
  - 机密客户端：`Authorization: Basic base64(client_id:client_secret)` 或 `client_secret_post`
  - 公共客户端：无密钥，必须 PKCE

处理：
- 校验授权码（有效/未用/未过期/匹配 client 与 redirect_uri）。
- 校验 PKCE：`S256(base64url(sha256(code_verifier))) == code_challenge`。
- 签发令牌并返回：

```json
{
  "token_type": "Bearer",
  "expires_in": 900,
  "access_token": "<jwt>",
  "id_token": "<jwt>"
}
```

**ID Token (JWT) Claims**：`iss, sub, aud, iat, exp, auth_time, nonce[, amr]`  
**Access Token (JWT) Claims**：`sub, client_id, scope, jti, iat, exp`

错误返回（示例）：
```json
{"error":"invalid_grant","error_description":"pkce mismatch"}
```

### /userinfo

`GET|POST /userinfo`（`Authorization: Bearer <access_token>`）

- 验签 Access Token（JWT），过期与受众检查。
- 按 scope 最小返回：
  - `sub`（必）
  - `name`（当包含 `profile`）
  - `email`,`email_verified`（当包含 `email`）

示例：
```json
{"sub":"u_123","name":"Alice","email":"alice@example.com","email_verified":true}
```

### /jwks.json

`GET /jwks.json` 返回当前与灰度中的公钥（带 `kid`）。

- 轮换：后台提供“一键轮换”，JWKS 同时暴露新旧公钥，旧 key 在灰度窗口后移除。

### /logout

`GET /logout?id_token_hint=&post_logout_redirect_uri=&state=`

- 验证 `id_token_hint` 的 `iss/aud/sub`。
- 清理 OP 会话。
- `post_logout_redirect_uri` 在白名单时 302 回跳并携带原 `state`。

---

## 同意页（Consent）

- 触发条件：用户首次对某客户端授权；请求的 `scope` 超出既有授权；全局 `consent.version` 升级。
- 记住授权：勾选“记住”，保存 `user_id + client_id + scopes + version`。后续相同或更窄 scope 不再弹出。
- 撤销：后台可按用户/客户端撤销。撤销后下一次授权再次弹出同意页。
- 内容：列示将共享的 claims（`sub` 必，`name/email` 可选）与《隐私政策》《用户协议》链接；勾选确认项。

---

## 管理后台

- 路由前缀：`/admin/`，Layui 前端 + JSON API。
- 模块与主要接口：
  - 客户端：
    - `GET /admin/api/clients`（列表/搜索）
    - `POST /admin/api/clients`（新增）
    - `PUT /admin/api/clients/:id`（编辑）
    - `PATCH /admin/api/clients/:id/status`（启停）
  - 用户：
    - `GET /admin/api/users`
    - `POST /admin/api/users`
    - `PATCH /admin/api/users/:id/password`
  - 同意记录：
    - `GET /admin/api/consents?user_id=&client_id=`
    - `DELETE /admin/api/consents/:id`
  - 密钥：
    - `GET /admin/api/jwks`
    - `POST /admin/api/jwks/rotate`

---

## 数据模型

**users**
- `id` BIGINT PK
- `username` UNIQUE
- `email` NULLABLE
- `password_hash`
- `status` TINYINT
- `created_at`

**clients**
- `client_id` PK
- `name`
- `secret_hash`（为空表示公共客户端）
- `redirect_uris` JSON
- `post_logout_uris` JSON
- `scopes` JSON
- `status` TINYINT

**consents**
- `id` PK
- `user_id` FK
- `client_id` FK
- `scopes` JSON
- `version` INT
- `remember` BOOL
- `updated_at`
- 唯一键：`(user_id, client_id)`

**auth_codes**
- `code_hash` CHAR(64) PK（SHA-256）
- `client_id`
- `user_id`
- `redirect_uri`
- `scope` JSON
- `nonce`
- `code_challenge` / `method`
- `auth_time`
- `expire_at`
- `used` TINYINT

**jwks_keys**
- `kid` PK
- `alg`（RS256/ES256）
- `use_key` = "sig"
- `pub_pem` TEXT
- `enc_priv` TEXT（加密后的私钥）
- `not_before` / `not_after`
- `status`（active/grace/retired）

**sessions**
- `sid` PK
- `user_id`
- `ua` / `ip`
- `created_at` / `expire_at`
- `revoked` TINYINT

---

## 安全与合规

- 最小必要：默认仅 `sub`，`profile/email` 通过同意页控制。
- 告知：登录/同意页展示《隐私政策》《用户协议》，说明处理目的、范围、留存周期与联系方式。
- 用户权利：后台支持撤销同意；删除用户能力按工单或后台管理实现。
- 日志留存：登录/授权/登出/密钥轮换等操作日志留存 ≥ 6 个月。
- 密码学：JWT 签名 RS256/ES256；TLS1.2+；HSTS 开启。
- Cookie：`Secure`、`HttpOnly`、`SameSite=Lax`。
- 抗攻击：强制 PKCE + `state` + `nonce`；`redirect_uri` 完整匹配；登录与 `/token` 限流。
- 跨境：在境内部署；如涉及出境，按标准合同/评估/认证流程处理。

---

## 站点（RP）接入说明

### 发现配置
RP 读取 `/.well-known/openid-configuration` 获取端点与 `jwks_uri`。

### 发起授权
```
GET /authorize?
  response_type=code&
  client_id=<id>&
  redirect_uri=<exact-uri>&
  scope=openid%20profile%20email&
  state=<random>&
  nonce=<random>&
  code_challenge=<BASE64URL(SHA256(code_verifier))>&
  code_challenge_method=S256
```

### 兑换 Token
```bash
curl -u <client_id>:<client_secret>   -X POST https://sso.example.com/token   -d grant_type=authorization_code   -d code=<code>   -d redirect_uri=<exact-uri>   -d code_verifier=<verifier>
```

### 验证 ID Token
- 验签：按 `kid` 从 `jwks_uri` 获取公钥。
- 校验：`iss`、`aud`、`exp`、`nonce`。
- RP 内部建立自有会话，Access Token 不持久化到浏览器存储。

### 登出
```
GET /logout?
  id_token_hint=<last_id_token>&
  post_logout_redirect_uri=<whitelisted>&
  state=<random>
```

---

## 开发指南

### 编码规范
- 目录层次：`controller → service → dao → model`，禁止跨层越权调用。
- `dao` 只做通用 CRUD；业务逻辑位于 `service`。
- 密码哈希：`bcrypt`（或 `argon2id`）；授权码与敏感令牌仅存 **哈希**。
- JWT：使用 `lestrrat-go/jwx/v2`；所有签发都带 `kid`。
- 配置：`viper` 读取 `manifest/config/config.yaml`；不可在代码中硬编码密钥。
- 模板：登录/同意/后台使用 `resource/` 下模板与静态资源。

### 错误码与返回体
- OAuth/OIDC 端点遵循标准错误字段：`error`、`error_description`。
- 管理后台 API 使用 HTTP 状态码 + JSON：
  ```json
  {"code":0,"message":"ok","data":{...}}
  ```
  失败：
  ```json
  {"code":1001,"message":"invalid_client"}
  ```

### 测试与质量
- 单元测试：`service` 与 `utility` 层优先覆盖。
- 集成测试：授权码完整链路（authorize→token→userinfo→logout）。
- Lint：`golangci-lint`。
- Makefile（示例）：
  ```
  make dev       # 热重载(air)或一般运行
  make test      # 单元测试
  make build     # 编译
  make migrate   # 数据库迁移
  make seed      # 初始化数据
  ```

### 日志与可观测
- 结构化日志（zap）：记录请求ID、用户ID、client_id、错误与耗时。
- 关键事件：登录成功/失败、授权码签发、token 签发、登出、JWK 轮换、后台变更。
- 保留期与导出：符合配置 `security.log_retain_days`。

---

## 版本与发布

- 语义化版本：`MAJOR.MINOR.PATCH`。
- 变更：`CHANGELOG.md` 记录协议或数据模型变更。
- 发布产物：二进制、Docker 镜像、示例配置与迁移脚本。

---

## 许可证

待定
