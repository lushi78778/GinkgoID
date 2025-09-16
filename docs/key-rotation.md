# Key Rotation & Migration

本文档说明如何在 GinkgoID 中安全地轮换签名密钥（JWK）并将已存的明文私钥迁移为加密存储（使用本项目的本地 AES-256-GCM 方案）。请在非生产环境充分演练并先做好数据库备份。

## 概念回顾
- 私钥（private_key）：用于签发 JWT 的 PEM，默认存储在 `jwk_keys` 表的 `private_key` 字段。
- 公钥（public_key）：以 PEM 或 JWK 形式公开到 JWKS。
- key_encryption_key：配置项 `crypto.key_encryption_key`（在 `config.yaml` 中设置），用于对私钥进行 AES-GCM 对称加密。

## 轮换总览
1. 生成新密钥对（RS256/ES256），将其写入数据库并标记为 active。
2. 新签发的 Token 使用新私钥签名；旧 Token 在其有效期内继续使用历史公钥验证。
3. 在安全窗口（例如 7 天 + 最长 token 有效期）后，清理历史私钥或降低其可见性。

## 本地迁移（将明文私钥加密）——策略
1. 备份数据库
2. 在运维主机的 `config.yaml` 中设置 `crypto.key_encryption_key`（生产建议使用秘密管理器来生成并注入配置文件）
3. 运行迁移命令或脚本（例如 `go run ./cmd/migrate-keys` 或 `scripts/migrate_keys.go`），它会：
   - 遍历 `jwk_keys` 表中 `private_key` 非空且看起来是 PEM（未加密） 的记录
   - 使用 `config.yaml` 中的 `crypto.key_encryption_key` 对私钥进行 AES-GCM 加密（可通过参数覆盖）
   - 替换数据库中的 `private_key` 字段为加密后的十六进制字符串（nonce||ciphertext）
4. 验证签名与 JWKS：尝试用数据库中某些 key 签名并验证 token
5. 如果验证成功，完成迁移；如失败，恢复数据库并排查原因

## 注意事项与回滚
- 迁移前务必备份数据库快照
- 迁移脚本应先在测试环境运行并验证
- 若迁移失败，可从备份中恢复并排查 `crypto.key_encryption_key` 是否正确

## 脚本示例
参见仓库 `scripts/migrate_keys.go` 或 `cmd/migrate-keys`，示例脚本/命令会使用 `config.yaml` 中的 `crypto.key_encryption_key`（或通过 `-key` 参数覆盖），并尝试把明文 private_key 加密替换。


---

如需我把该脚本运行在你的环境（或生成更严谨的迁移计划与回滚脚本），请先确认你允许我添加并提交该示例脚本。