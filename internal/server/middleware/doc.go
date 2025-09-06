// @Title      middleware 包
// @Description 提供安全响应头、CSRF、防跨域来源校验、限流与管理员会话鉴权等中间件。
// @Author     lushi  2025/09/06
// @Update     lushi  2025/09/06
//
// - 安全响应头（CSP/XFO/Referrer-Policy/HSTS）；
// - CSRF（双提交 Cookie）；
// - 来源校验（Origin/Referer 严格/宽松模式）；
// - 速率限制（固定窗口/令牌桶）；
// - 管理员会话校验（页面与 API）。
package middleware
