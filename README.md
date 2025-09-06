# GinkgoID

一个轻量、纯自研的 OpenID Connect 身份提供方（OP）。面向单站点或少量站点的 SSO 场景，强调实现最小、部署简单、默认安全。

本仓库包含：完整的 OIDC 链路（授权码 + PKCE）、JWT 签发与验签、Discovery/JWKS、UserInfo、同意页与登录页、RP 发起登出、最小管理后台（Layui，内嵌静态资源）、JWK 轮换、令牌撤销/自省、限流/CSRF/安全响应头、启动自检与 /metrics。

> 自用/内网/小规模生产可用的 MVP。默认配置以开发为主。

---

## 功能概览

- OIDC 核心
  - 授权码 + PKCE(S256)
  - ID Token / Access Token（JWT，RS256/ES256，kid 轮换）
  - Discovery：`/.well-known/openid-configuration`
  - JWKS：`/jwks.json`
  - UserInfo：`GET /userinfo`
  - RP 发起登出：`/logout`
  - 令牌自省/撤销：`POST /oauth2/introspect`、`POST /oauth2/revoke`
- 交互页面（内嵌模板与静态资源）
  - 登录页：`/login`
  - 同意页：`/consent`
  - 管理后台：`/admin/`（Layui，本地 JS/CSS/Font，路径统一为 `/assets/...`）
- 管理能力（/admin + /admin/api）
  - 客户端/用户/同意记录/JWK 管理
  - 管理 API 采用 JSON + CSRF（双提交 Cookie）
- 安全
  - 强制 PKCE + state +（可选）nonce
  - 固定重定向 URI 完全匹配
  - CSRF（双提交 Cookie）、Origin/Referer 校验（来源仅基于 `oidc.issuer`）
  - 速率限制：Redis 令牌桶（/login, /token）
  - 安全响应头（CSP/X-Frame-Options/Referrer-Policy/HSTS 可配）
- 可观测
  - 健康：`/healthz`
  - 就绪：`/readyz`（DB/Redis 检查）
  - 运行时：`/debug/vars`（expvar）
  - 指标：`/metrics`（内置最小 Prometheus 文本格式）

---

## 目录结构

```
/  
├── cmd/sso-server              # 服务入口  
├── hack                        # CLI：迁移/创建客户端/轮换 JWK/e2e  
├── internal
│   ├── controller/admin        # 管理后台 Page + API  
│   ├── infra                   # 配置/DB/Redis/日志/迁移  
│   ├── model/entity           # ORM 实体  
│   ├── server                  # 路由/中间件/校验  
│   ├── service                 # 业务：oidc/jwk/user/client/consent/session/revocation  
│   └── utility                 # 通用：hash/加解密/随机  
├── manifest                    # 配置与 Docker  
├── resource                    # 模板与静态资源（内嵌）  
├── Makefile                    # 常用命令  
└── README.md
```
## 环境与依赖

- Go 1.22+
- MySQL 8.x（当前仅支持 MySQL）
- Redis（可选，用于限流与令牌撤销/会话缓存）
- 反向代理：建议 Caddy/Nginx（TLS/HSTS）

## 配置

配置文件：`manifest/config/config.yaml`

关键项（省略不相关字段）：

```yaml
server:
  addr: ":8080"
  cookie_domain: "localhost"
  secure_cookies: false
  auto_migrate: true

db:
  driver: "mysql"
  dsn: "root:123456@tcp(127.0.0.1:3306)/ginkgoid?parseTime=true&charset=utf8mb4"

redis:
  enabled: true
  addr: "127.0.0.1:6379"
  db: 0
  password: ""

oidc:
  issuer: "http://localhost:8080"
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
  password_hash: "argon2id"
  hsts: true
  log_retain_days: 180
  jwk_enc_passphrase: "CHANGE_ME_STRONG"
  max_sessions_per_user: 5
  allow_insecure_local_jwt: false

admin:
  bootstrap:
    username: "admin"
    password: "admin"
  privacy_url: "https://sso.example.com/privacy"
  terms_url:   "https://sso.example.com/terms"
```

说明：
- `oidc.issuer` 是端点与校验的唯一来源，必须是完整 URL（http/https）。
- `server.auto_migrate`：开发环境建议 true；生产 false，改用版本化迁移。
- `security.jwk_enc_passphrase`：务必更换为强口令。

## 启动与初始化

- 安装依赖并运行：

```bash
go mod tidy
go run ./cmd/sso-server
```

- 启动日志包含：配置校验、AutoMigrate 执行结果、DB/Redis Ping、JWK 保证、Bootstrap 管理员状态、HTTP 监听地址。
- 管理后台：`http://localhost:8080/admin/`
- 登录页：`http://localhost:8080/login`
- 文档页：`http://localhost:8080/docs`
- 指标页：`http://localhost:8080/metrics`

可选 CLI（`Makefile`）：

```bash
make migrate          # 运行 hack/migrate（AutoMigrate）
make create-client    # 创建示例客户端
make rotate-jwk       # 轮换 JWK（RS256/ES256，带灰度）
make e2e              # 本地端到端演示
make build            # 构建二进制
```

Docker（可选）：`manifest/docker/docker-compose.yml`（可自行补充 MySQL/Redis 服务）

---

## 端点与协议

### **Discovery**
```shell
GET /.well-known/openid-configuration
```
关键字段：

* issuer、authorization_endpoint、token_endpoint、userinfo_endpoint、jwks_uri  
* response_types_supported=["code"]  
* grant_types_supported=["authorization_code"]  
* code_challenge_methods_supported=["S256"]  
* id_token_signing_alg_values_supported=["RS256","ES256"]  
* scopes_supported=["openid","profile","email"]

### **/authorize**

GET /authorize

必备参数：

* response_type=code  
* client_id  
* redirect_uri（**完全匹配**注册白名单）  
* scope（包含 openid）  
* state  
* nonce（开启 force_nonce 时必需）  
* code_challenge + code_challenge_method=S256

行为：

1. 未登录：302 至 /login。  
2. 已登录：根据同意规则决定是否展示同意页；通过后生成一次性 code（仅存哈希，TTL 60–120s），302 回跳：?code&state。

错误回跳（示例）：
```shell
HTTP/302 Location: {redirect_uri}?rror=invalid_request&error_description=...
```
### **/token**

POST /token（Content-Type: application/x-www-form-urlencoded）

* grant_type=authorization_code  
* code  
* redirect_uri  
* code_verifier  
* 客户端认证：  
  * 机密客户端：Authorization: Basic base64(client_id:client_secret) 或 client_secret_post  
  * 公共客户端：无密钥，必须 PKCE

处理：

* 校验授权码（有效/未用/未过期/匹配 client 与 redirect_uri）。  
* 校验 PKCE：S256(base64url(sha256(code_verifier))) == code_challenge。  
* 签发令牌并返回：
```json
{  
  "token_type": "Bearer",  
  "expires_in": 900,  
  "access_token": "<jwt>",  
  "id_token": "<jwt>"  
}
```
**ID Token (JWT) Claims**：iss, sub, aud, iat, exp, auth_time, nonce[, amr]

**Access Token (JWT) Claims**：sub, client_id, scope, jti, iat, exp

错误返回（示例）：
```json
{
    "error": "invalid_grant",
    "error_description": "pkce mismatch"
}
```
### **/userinfo**

GET /userinfo（Authorization: Bearer <access_token>）

* 验签 Access Token（JWT），过期与受众检查。  
* 按 scope 最小返回：  
  * sub（必）  
  * name（当包含 profile）  
  * email,email_verified（当包含 email）
### **/jwks.json**

GET /jwks.json 返回当前与灰度中的公钥（带 kid）。

* **密钥轮换机制**：后台提供“一键轮换”，JWKS 同时暴露新旧公钥。客户端通过 JWT header 中的 kid 字段找到对应公钥进行验签，实现密钥的平滑过渡。旧 key 在灰度窗口后移除。

### **/logout**

GET /logout?id_token_hint=&post_logout_redirect_uri=&state=

* 验证 id_token_hint 的 iss/aud/sub。  
* 清理 OP 会话。  
* post_logout_redirect_uri 在白名单时 302 回跳并携带原 state。

## **同意页（Consent）**

* 触发条件：用户首次对某客户端授权；请求的 scope 超出既有授权；全局 consent.version 升级。  
* 记住授权：勾选“记住”，保存 user_id + client_id + scopes + version。后续相同或更窄 scope 不再弹出。  
* 撤销：后台可按用户/客户端撤销。撤销后下一次授权再次弹出同意页。  
* 内容：列示将共享的 claims（sub 必，name/email 可选）与《隐私政策》《用户协议》链接；勾选确认项。

## 管理后台

* 路由前缀：/admin/，Layui 前端 + JSON API。  
* 模块与主要接口：  
  * 客户端：  
    * GET /admin/api/clients（列表/搜索）  
    * POST /admin/api/clients（新增）  
    * PUT /admin/api/clients/:id（编辑）  
    * PATCH /admin/api/clients/:id/status（启停）  
  * 用户：  
    * GET /admin/api/users  
    * POST /admin/api/users  
    * PATCH /admin/api/users/:id/password  
  * 同意记录：  
    * GET /admin/api/consents?user_id=&client_id=  
    * DELETE /admin/api/consents/:id  
  * 密钥：  
    * GET /admin/api/jwks  
    * POST /admin/api/jwks/rotate

### 管理 API 速查表（中文）

以下接口需管理员登录、CSRF 校验、严格来源校验（Origin/Referer）。

- 列出客户端（表格）
  - GET `/admin/api/clients/table?page=1&limit=10&q=demo`
  - 返回：`{code, msg, count, data:[{client_id,name,status}]}`

- 创建客户端
  - POST `/admin/api/clients`
  - JSON：`{"client_id":"demo","name":"Demo","redirect_uris":["http://localhost:8081/callback"],"scopes":["openid","profile","email"],"secret":"<可选>"}`

- 更新客户端
  - PUT `/admin/api/clients/:id`
  - JSON 任一字段：`{"name":"New","redirect_uris":[...],"post_logout_uris":[],"scopes":[],"secret":"<可选，留空清除>"}`

- 启停客户端
  - PATCH `/admin/api/clients/:id/status`
  - JSON：`{"status":1}`

- 列出用户（表格）
  - GET `/admin/api/users/table?page=1&limit=10&q=adm`

- 创建用户
  - POST `/admin/api/users`
  - JSON：`{"username":"u1","password":"p1","email":"u1@example.com","email_verified":true,"role":"user"}`

- 重置用户密码
  - PATCH `/admin/api/users/:id/password`
  - JSON：`{"password":"newpass"}`

- 设置邮箱与验证状态
  - PATCH `/admin/api/users/:id/email`
  - JSON：`{"email":"u1@example.com","email_verified":true}`

- 设置角色
  - PATCH `/admin/api/users/:id/role`
  - JSON：`{"role":"admin|operator|auditor|user"}`

- 注销用户全部会话
  - POST `/admin/api/users/:id/sessions/revoke_all`

- 列出同意记录（表格）
  - GET `/admin/api/consents/table?page=1&limit=10&user_id=&client_id=`

- 删除同意记录
  - DELETE `/admin/api/consents/:id`

- 列出 JWK
  - GET `/admin/api/jwks`

- 轮换 JWK
  - POST `/admin/api/jwks/rotate?alg=ALL|RS256|ES256`

- 撤销 Access Token
  - POST `/admin/api/tokens/revoke_access`
  - JSON：`{"access_token":"<jwt>"}`

- 按 jti 撤销
  - POST `/admin/api/tokens/revoke_jti`
  - JSON：`{"jti":"<id>","ttl_seconds":600}`

- 查询撤销状态
  - GET `/admin/api/tokens/status?jti=<id>`

示例 curl（需带 CSRF 与 Cookie，可在浏览器控制台复制 Cookie 与 csrf_token）：

```bash
# 列出客户端（表格）
curl -H "Cookie: gid_session=<sid>; csrf_token=<csrf>" \
     -H "X-CSRF-Token: <csrf>" \
     http://localhost:8080/admin/api/clients/table?page=1&limit=10

# 创建客户端
curl -X POST -H "Content-Type: application/json" \
     -H "Cookie: gid_session=<sid>; csrf_token=<csrf>" -H "X-CSRF-Token: <csrf>" \
     -d '{"client_id":"demo","name":"Demo","redirect_uris":["http://localhost:8081/callback"],"scopes":["openid","profile","email"]}' \
     http://localhost:8080/admin/api/clients

# 轮换 JWK（全部算法）
curl -X POST -H "Cookie: gid_session=<sid>; csrf_token=<csrf>" -H "X-CSRF-Token: <csrf>" \
     http://localhost:8080/admin/api/jwks/rotate?alg=ALL

# 撤销 Access Token
curl -X POST -H "Content-Type: application/json" \
     -H "Cookie: gid_session=<sid>; csrf_token=<csrf>" -H "X-CSRF-Token: <csrf>" \
     -d '{"access_token":"<jwt>"}' \
     http://localhost:8080/admin/api/tokens/revoke_access
```

## 数据模型（简要）

**users**

* id BIGINT PK  
* username UNIQUE  
* email NULLABLE  
* password_hash  
* status TINYINT  
* created_at

**clients**

* client_id PK  
* name  
* secret_hash（为空表示公共客户端）  
* redirect_uris JSON  
* post_logout_uris JSON  
* scopes JSON  
* status TINYINT

**consents**

* id PK  
* user_id FK  
* client_id FK  
* scopes JSON  
* version INT  
* remember BOOL  
* updated_at  
* 唯一键：(user_id, client_id)

**auth_codes**

* code_hash CHAR(64) PK（SHA-256）  
* client_id  
* user_id  
* redirect_uri  
* scope JSON  
* nonce  
* code_challenge / method  
* auth_time  
* expire_at  
* used TINYINT

**jwks_keys**

* kid PK  
* alg（RS256/ES256）  
* use_key = "sig"  
* pub_pem TEXT  
* enc_priv TEXT（加密后的私钥）  
* not_before / not_after  
* status（active/grace/retired）

**sessions**

* sid PK  
* user_id  
* ua / ip  
* created_at / expire_at  
* revoked TINYINT

## 运行与可观测

* 健康：`/healthz` 直接 200；`/readyz` 检查 DB（必）与 Redis（可选）  
* 指标：`/metrics`（自带最小指标），`/debug/vars`（expvar）  
* 日志：zap（JSON）；gin 访问日志；启动阶段输出 DB/Redis/JWK/Admin 自检结果

---

## 安全说明

* **最小必要**：默认仅 sub，profile/email 通过同意页控制。  
* **用户告知**：登录/同意页展示《隐私政策》《用户协议》，说明处理目的、范围、留存周期与联系方式。  
* **用户权利**：后台支持撤销同意；删除用户能力按工单或后台管理实现。  
* **日志留存**：登录/授权/登出/密钥轮换等操作日志留存 ≥ 6 个月。  
* **密码学**：JWT 签名 RS256/ES256；TLS1.2+；HSTS 开启。  
* **Cookie**：Secure、HttpOnly、SameSite=Lax。  
* **抗攻击**：强制 PKCE + state + nonce；redirect_uri 完整匹配；登录与 /token 限流。

### 额外安全考量与未来规划

鉴于项目全自研且 MVP 阶段未实现某些 OIDC 规范功能，为保障生产环境安全，需额外关注以下几点：

* **Access Token 的时效性**：由于不实现 Refresh Token，Access Token 的过期时间需要权衡。建议**缩短 Access Token 的 TTL**（例如 5-10 分钟），以降低泄露风险。  
* **令牌撤销（Token Revocation）**：当前设计下，已签发的 Access Token 无法被强制失效。这意味着一旦令牌泄露，攻击者可在其有效期内（即使会话已登出）继续使用。生产环境应考虑**实现基于黑名单或数据库的令牌撤销机制**。  
* **JWT 算法安全**：项目支持 RS256/ES256。为防止“算法混淆攻击”，必须**严格限制并验证** JWT Header 中的 alg 字段，只接受白名单中的签名算法。

## 互操作与示例

### **发现配置**

RP 读取 /.well-known/openid-configuration 获取端点与 jwks_uri。

### **发起授权**
```shell
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
### **兑换 Token**
```shell
curl -u <client_id>:<client_secret>  -X POST [https://sso.example.com/token](https://sso.example.com/token)  -d grant_type=authorization_code  -d code=<code>  -d redirect_uri=<exact-uri>  -d code_verifier=<verifier>
```
### **验证 ID Token**

* 验签：按 kid 从 jwks_uri 获取公钥。  
* 校验：iss、aud、exp、nonce。  
* RP 内部建立自有会话，Access Token 不持久化到浏览器存储。

### **登出**
```shell
GET /logout?  
  id_token_hint=<last_id_token>&  
  post_logout_redirect_uri=<whitelisted>&  
  state=<random>
```
## 开发生产建议

- 关闭 `server.auto_migrate`，改用版本化迁移（goose/atlas）。
- 将 `jwk_enc_passphrase` 与 DB/Redis 凭据改为环境变量/Secret 管理。
- 明确 cookie 域与 `secure_cookies=true`（HTTPS）。
- 调小 `access_token_ttl`（5–10 分钟），并启用 Redis 限流与撤销。
- 备份：MySQL 快照 + binlog；定期导出 JWKS 历史与审计日志。

---

### **编码规范**

* 目录层次：controller → service → dao → model，禁止跨层越权调用。  
* dao 只做通用 CRUD；业务逻辑位于 service。  
* 密码哈希：推荐使用**argon2id**，因为它在抵抗 GPU 暴力破解和侧信道攻击方面比 bcrypt 更具优势；授权码与敏感令牌仅存 **哈希**。  
* JWT：使用 lestrrat-go/jwx/v2；所有签发都带 kid。  
* 配置：viper 读取 manifest/config/config.yaml；不可在代码中硬编码密钥。  
* 模板：登录/同意/后台使用 resource/ 下模板与静态资源。

### **Layui 前端安全指南**

Layui 是一个传统的 JavaScript 框架，不提供现代前端框架内置的防攻击功能。开发者需要**手动实现以下安全措施**：

1. **XSS 防御**：对所有用户输入的内容进行**输入验证**和**输出转义**。不要直接在页面上渲染未经处理的用户输入，应使用 JavaScript 对其进行 HTML 编码。  
2. **CSRF 防御**：在所有敏感操作的表单和 Ajax 请求中**加入 CSRF Token**，并在后端验证其有效性。确保敏感 API 只接受带有有效 CSRF Token 的 POST 请求。

### **错误码与返回体**

* OAuth/OIDC 端点遵循标准错误字段：error、error_description。  
* 管理后台 API 使用 HTTP 状态码 + JSON：  
  {"code":0,"message":"ok","data":{...}}

  失败：  
  {"code":1001,"message":"invalid_client"}

### **日志与可观测**

* 结构化日志（zap）：记录请求ID、用户ID、client_id、错误与耗时。  
* 关键事件：登录成功/失败、授权码签发、token 签发、登出、JWK 轮换、后台变更。  
* 保留期与导出：符合配置 security.log_retain_days。

## **待办**

### 安全加固

- CSRF 强化：为管理页增加单次性 Token（双重校验 + 过期时间 + 路径绑定），并在响应头附 `Set-Cookie: SameSite=Strict`；对跨域预检统一返回限制策略。  
- CORS 与安全头：统一下发 `X-Content-Type-Options: nosniff`、`Content-Security-Policy`（限制脚本来源）、`Referrer-Policy`、`X-Frame-Options: DENY`。  
- 输入校验：对 authorize/token/userinfo/admin API 使用结构化校验器（如 go-playground/validator）并统一错误码表。  
- 速率限制：将登录与 /token 的限流从固定窗口升级为滑动窗口/令牌桶，且按 IP+User/Client 多维度聚合；可选封禁窗口。  
- 会话安全：支持会话并发限制与踢出；增加 Session 固定（Session Fixation）防护；支持“在管理端注销某用户全部会话”。  
- JWT 安全：严格拒绝 `none/HS*` 算法；对 `kid` 做白名单校验；对 `aud/iss` 做固定匹配；Access Token 默认 5–10 分钟有效期。  
- Token 撤销：引入 `jti` 黑名单（Redis/DB），Admin 可单条/批量撤销；/userinfo 验证需检查黑名单。  
- 密钥托管：生产环境私钥推荐接入 KMS/HSM；本地仅用于开发的加密口令需以环境变量/Secret 管理，并提供轮换流程。  
- 登录策略：可配置密码复杂度、失败锁定与解锁流程；可选 MFA（TOTP/WebAuthn）。

### OIDC 规范与互操作

- Discovery 补充：`end_session_endpoint` 已支持；根据需求扩展 `introspection`/`revocation`/`device_authorization_endpoint`（如不需要可保持最小集）。  
- 前/后端登出：支持 RP 前通道/后通道登出通知；回调超时与重试策略；登出审计。  
- 错误页面：为 `login/authorize/callback` 提供统一错误展示与可观测 ID。  
- `userinfo` 性能：缓存用户基本 Claims（短 TTL）以降低 DB 压力；遵循最小暴露原则。  
- 兼容性测试：针对常见 RP SDK（oidc-client、Spring Security、NextAuth、Authlib 等）做互操作验证用例。

### 运维与高可用

- 运行模式：提供 `Readiness/Liveness` 探针；优雅关停时驱逐流量并等待中短期事务完成。  
- HA 架构：多副本 + 前置反向代理；Redis 用作会话与限流共享；MySQL 主从或云托管。  
- 迁移策略：禁用 `AutoMigrate` 于生产，改为版本化迁移（goose/atlas/migrate）；灰度/回滚脚本。  
- 备份与恢复：MySQL 持久化快照、binlog；JWKS 历史与审计日志定期归档；演练恢复。  
- 资源限额：生产镜像/容器设置 CPU/内存 requests/limits；ulimit 与文件句柄上限。  
- 时区与时间：服务强制使用 UTC，配置时区仅用于展示；NTP 对齐时钟漂移。  
- 健康告警：关键指标（5xx、授权失败率、登录失败率、签名耗时、DB/Redis 连接池）阈值告警。  
- 变更审计：Admin 所有操作写入审计日志（含操作者/对象/前后值/来源 IP/UA）。

### 观测与性能

- 指标：暴露 Prometheus 指标（QPS、p95/p99 延迟、error_rate、签名/验签耗时、限流/拒绝次数）。  
- Trace：接入 OpenTelemetry（/authorize→/token→/userinfo 全链路）；落地到云厂商 APM。  
- 性能优化：/token 签名池化（并发可控）；JWKS 响应缓存；DB/Redis 连接池参数调优。  
- 压测基线：授权码链路与 /userinfo 分别建立基准，给出并发-延迟曲线与容量建议。

### Admin 后台与 DevSecOps

- UI 体验：表格分页/搜索；编辑弹窗（JSON 校验与美化）；操作确认与 Toast 提示。  
- 权限模型：区分“审计员/运营/管理员”角色；最小权限。  
- CSRF 改进：CSRF Token 绑定会话与过期时间；对跨域请求校验 `Origin/Referer`。  
- 代码质量：补充单元测试（service/utility）与 e2e；引入 CI（lint/test/build），保护主干分支。  
- 发布流程：构建不可变镜像，按 `semver` 发布；灰度发布与回滚说明；镜像 SBOM 与漏洞扫描。

### 配置与文档

- 配置分层：dev/staging/prod 多环境；敏感信息仅来自环境变量/密钥管理系统。  
- 文档完善：
  - 运维手册：扩容、缩容、滚动/灰度发布、迁移、备份与恢复、密钥轮换步骤。  
  - 故障排查：常见 4xx/5xx 说明、日志查找、指标告警处置。  
  - RP 指南：各语言接入示例（Java/Python/Node/Go），错误与回调处理模板。

### 可选功能（按需）

- Refresh Token 流程（带旋转与撤销），或继续坚持短期 Access Token + 靠近资源服务的会话。  
- 细粒度同意：按 claim/属性维度显示与授权；同意变更通知 RP。  
- 自助账户管理：用户修改资料、改密、查看授权客户端并撤销、查看登录历史。  
- 风险控制：登录异常检测、IP/设备指纹、验证码/二次验证策略。


## 版本与发布

* 语义化版本：MAJOR.MINOR.PATCH。  
* 变更：CHANGELOG.md 记录协议或数据模型变更。  
* 发布产物：二进制、Docker 镜像、示例配置与迁移脚本。

## 许可证

待定
