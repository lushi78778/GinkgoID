// @Title      server 包
// @Description HTTP 路由初始化、页面渲染与开放端点的统一注册入口。
// @Author     lushi  2025/09/06
// @Update     lushi  2025/09/06
//
// 该包集中注册：
// 1) 标准 OIDC 端点（/authorize、/token、/userinfo、/jwks.json、/logout）；
// 2) 发现文档与指标（/.well-known/openid-configuration、/docs、/metrics、/readyz 等）；
// 3) 管理后台页面与 API；
// 4) 通用安全中间件（CSP/HSTS/限流/CSRF/来源校验）。
package server
