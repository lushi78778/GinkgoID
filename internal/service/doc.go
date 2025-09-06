// @Title      service 包
// @Description 聚合领域服务（业务逻辑），对 controller 层提供清晰的用例方法。
// @Author     lushi  2025/09/06
// @Update     lushi  2025/09/06
//
// 子包职责：
// - oidc：JWT 签发与验签、令牌结构；
// - jwk：密钥生成/轮换/JWKS 导出（私钥加密存储）；
// - user/client/consent/session：基础域模型的读写与规则；
// - revocation：基于 Redis 的令牌撤销（jti 黑名单）。
package service
