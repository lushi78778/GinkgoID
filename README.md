# GinkgoID — OpenID Connect Provider (OIDC OP)

简洁、可自托管的 OpenID Provider，基于 Go + Gin。实现了 OIDC/OAuth2 常见端点与运维能力，适合本地开发、PoC 与逐步演进到生产的自托管场景。

注意：本 README 为开发 / 运维手册，包含部署、迁移、密钥加密、轮换、TLS 与备份等实务建议。

---

目录
- 概览
- 快速开始（本地开发）
- 配置说明（config.yaml）
- 数据库与迁移
- 密钥管理（本地对称加密、轮换、迁移）
- 部署与 TLS 建议
- 备份、恢复与审计
- OpenAPI / Swagger / Stoplight
- 日志与监控
- 测试与 CI
- 常用故障排查
- 开发指南（代码位置与扩展点）
- 许可证与贡献

---

概览
- 支持：Discovery、JWKS、/authorize、/token（authorization_code + refresh）、/userinfo、/revoke、/introspect、动态注册、back-channel / front-channel logout、pairwise subject。
- 存储：MySQL（持久化模型）、Redis（会话/授权码/刷新/黑名单）。
- 默认签名算法：RS256（可配置为 ES256）。
- 可选：本地对称私钥加密（AES-256-GCM），用于提升私钥存库安全性（非 KMS/HSM）。

---

快速开始（开发）
1. 准备环境
   - Go >= 1.22、MySQL 8+、Redis 6+
2. 克隆并准备配置
  - git clone ...
  - cp config.yaml.example config.yaml
  - 编辑 `config.yaml` 中的敏感项（例如数据库密码、`crypto.key_encryption_key`）或使用你的配置管理流程生成 `config.yaml`
3. 启动（开发）
   - go run ./cmd/server
   - 或：make run
4. 自检
   - 打开：http://127.0.0.1:8080/.well-known/openid-configuration
   - OpenAPI 文档： http://127.0.0.1:8080/docs

---

- 配置要点（config.yaml）
- 推荐：将敏感配置（DB 密码、`crypto.key_encryption_key`）通过安全的配置管理或秘密管理器注入到 `config.yaml`，避免在版本库中存储明文。
- 关键字段：
  - issuer（必须为部署后的对外地址，生产应为 https）
  - mysql.redis, redis.addr
  - crypto.id_token_alg（RS256/ES256）
  - crypto.key_encryption_key（可选，本地对称加密密钥）
- token、session、limits、registration 等详见 config.yaml 示例
- token.id_token_ttl 可单独配置 ID Token 有效期（默认 15m；为空时回落到 access_token_ttl）
- acr（可选）：
    - minimum：最低可接受 ACR（如 urn:op:auth:pwd / urn:op:auth:otp）
    - suggest_mfa：true 时在登录页提示建议开启多因素
示例：通过 `config.yaml` 设置 `crypto.key_encryption_key`
- 在 `config.yaml` 中添加：
  ```yaml
  crypto:
    id_token_alg: RS256
    key_encryption_key: "your-32-byte-random-string-here"
  ```
  - DPoP：
    - 可通过 `dpop.replay_window` 与 `dpop.clock_skew` 调整重放检测窗口与容忍的时钟偏移
    - 刷新令牌轮换时同样要求提供匹配的 DPoP-Proof
  - ACR 策略示例：
  ```yaml
  acr:
    minimum: urn:op:auth:pwd
    suggest_mfa: true
  ```
  - 生成随机密钥（macOS / Linux）：
    - `head -c 32 /dev/urandom | base64`

---

数据库与迁移
- 首次运行会自动执行 GORM 自动迁移，创建必要表。
- 建议：在生产环境前通过 SQL 备份并通过 CI 验证迁移脚本。
- 典型表：users, clients, jwk_keys, token_records, log_records, consents
- 初始化步骤（示例）：
  - CREATE DATABASE ginkgoid CHARACTER SET utf8mb4;
  - 配置 config.yaml 中的 mysql 数据库参数
  - 启动服务使自动迁移执行

---

密钥管理（推荐流程）
1. 本地对称加密（项目内置）
  - 在 `config.yaml` 设置 `crypto.key_encryption_key`
   - 项目使用 AES-256-GCM（Key 派生为 32 字节）对私钥进行加密后写入 DB
   - 运行时仅在内存中解密用于签名
   - 公钥保持 PEM 明文并通过 JWKS 暴露
   - 兼容提示：若 DB 中存在明文私钥，系统会在解密失败时尝试明文解析以兼容迁移
2. 密钥轮换
   - 提供管理命令或 API（示例）：
     - 本地管理 CLI（示例）：ginkgoid admin rotate-keys
     - 或：POST /dev/keys/rotate（仅 dev）
   - 轮换策略：
     - 新密钥写入并设为 active（短期并行期）
     - 在 JWKS 中保留历史公钥（使旧 Token 可以验证直到过期）
     - 清理策略：按时间或按 TTL 删除过旧私钥（在安全窗口后）
3. 迁移已明文私钥到加密存储（建议步骤）
   - 备份数据库
  - 在 `config.yaml` 设置 `crypto.key_encryption_key` 并启动服务（生成新 key 时将加密存储）
   - 提供脚本遍历 jwk_keys 表，将明文 private_key 加密并更新（谨慎操作）
   - 测试签名/验证流程在非生产环境先验证

---

TLS 与部署建议
- 生产必须使用 TLS（HTTPS），并在反向代理/负载均衡器处终止 TLS（推荐）。
- 建议架构：
  - 客户端 <-> 反向代理（Nginx/Traefik/Ingress）[TLS termination] <-> ginkgoid（内部 HTTP）
- 证书管理：使用 cert-manager / Let's Encrypt 或内网 PKI
- 配置要点：
  - issuer 指向 public https 地址（和反向代理一致）
  - session.cookie_secure=true，cookie_samesite=lax/strict 在生产启用
  - HSTS（security.hsts）建议开启

示例 Nginx (反向代理 snippet)
- 参考通用 Nginx TLS 配置，添加 proxy_set_header Host $host 等

---

备份、恢复与审计
- 备份策略
  - 定期备份 MySQL（mysqldump 或逻辑备份）
  - Redis 持久化（RDB/AOF）并备份快照
- 恢复演练
  - 在恢复后验证：clients, keys, users 数据一致性；尝试签发 token 并验证
- 审计日志
  - 关键事件写入审计表：登录、token 签发/撤销、key rotate、client 注册/修改
  - 日志保留策略与导出（建议接入集中化日志系统：ELK / Loki）

---

OpenAPI / Swagger / Stoplight
- 项目使用 swag 注释生成 OpenAPI，Stoplight Elements 渲染 UI（web/stoplight.html）。
- 生成命令（每次注释变更后执行）：
  - go run github.com/swaggo/swag/cmd/swag init --generalInfo cmd/server/main.go --output docs
- 生成后：docs/swagger.json 会被 web/stoplight.html 加载
- PR 要求：接口实现与注释同步，运行生成命令并提交 docs 变更

---

日志与监控
- Prometheus 指标：/metrics（包含请求与 token 指标）
- 日志：结构化 JSON 日志用于访问与审计
- 建议：
  - 接入 Prometheus + Grafana
  - 接入集中化日志（ELK / Grafana Loki）
  - 告警：token 验证错误、密钥轮换失败、数据库连接错误

---

测试与 CI
- 本地测试：go test ./...
- E2E：仓库含 cmd/e2e 示例脚本，用于模拟授权流程
- CI 建议：
  - 单元测试、fmt/vet/staticcheck、swag 生成校验、简单的集成测试（使用 Testcontainers 或本地 MySQL/Redis）
  - GitHub Actions 示例位于 .github/workflows/ci.yml（若存在）

---

常用故障排查
- 无法访问 /.well-known/openid-configuration
  - 检查 http_addr、issuer 配置与反向代理 host header
- Token 验证失败（kid 未找到）
  - 检查 JWKS 是否包含对应 kid，检查 key rotation 状态
- 登录/会话异常
  - 检查 Redis 连接、session cookie 设置（domain/secure/samesite）
- 私钥解密失败
  - 确认 `crypto.key_encryption_key` 是否正确并已配置

---

开发指南（代码与扩展点）
- 入口：cmd/server/main.go（路由与中间件）
- handler：internal/handlers（authorize/token/userinfo/register/revoke/introspect/logout）
- 服务：internal/services（keys/token/clients/session/refresh）
- 存储模型：internal/storage/migrate.go
- 工具与中间件：internal/middlewares、internal/utils
- 若需添加 OpenAPI 注释：在 handler 顶部添加 swag 注释并运行 swag init

---

贡献与许可
- 欢迎 Issue / PR
- 请在 PR 中包含测试或文档更新
- 许可信息见仓库 LICENSE 文件

---

附录：常用命令速查
- 运行服务（开发）：go run ./cmd/server
- 构建：go build -o server ./cmd/server
- 生成 OpenAPI：go run github.com/swaggo/swag/cmd/swag init --generalInfo cmd/server/main.go --output docs
- 生成随机 `crypto.key_encryption_key` 值：`head -c 32 /dev/urandom | base64`
- 备份 DB：mysqldump -u root -p ginkgoid > ginkgoid_$(date +%F).sql
