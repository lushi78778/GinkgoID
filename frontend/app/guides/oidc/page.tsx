"use client";

import { useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

const coreScopes = ["openid", "profile", "email"];

const troubleshooting = [
  {
    title: "invalid_client",
    hint: "确认客户端审批通过且启用；机密客户端调用 /token 时需 Basic Auth 或 client_secret_post。",
  },
  {
    title: "invalid_grant",
    hint: "检查 redirect_uri 与注册值完全一致，授权码未重复使用，并确保 code_verifier 与 code_challenge 对应。",
  },
  {
    title: "invalid_scope",
    hint: "仅请求已注册 scope，避免额外空格；若需要 profile/email 以外的 scope，先在客户端管理中添加。",
  },
  {
    title: "access_denied",
    hint: "授权页被用户取消或策略阻断，查看客户端日志 / 应用日志页面确认详情。",
  },
];

export default function OidcQuickGuide() {
  const hostExample = useMemo(() => {
    if (typeof window === "undefined") return "your-op-domain";
    return window.location.host;
  }, []);

  return (
    <div className="container py-10 space-y-6">
      <Card>
        <CardHeader className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <CardTitle>OIDC 快速集成指引</CardTitle>
            <CardDescription>一步步完成 Discovery、授权码流程、Token 校验与用户信息获取</CardDescription>
          </div>
          <div className="flex gap-2 text-sm">
            <Button variant="outline" size="sm" asChild>
              <a href="/.well-known/openid-configuration" target="_blank" rel="noreferrer">
                查看 Discovery
              </a>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <a href="/openapi.json" target="_blank" rel="noreferrer">
                下载 OpenAPI JSON
              </a>
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4 text-sm text-muted-foreground">
          <p>
            在开始前，请确保已经在“客户端注册”中创建应用，并记录 client_id、client_secret（若为机密客户端）以及允许的 redirect_uri。
            以下步骤默认使用授权码 + PKCE 流程，是网页 / 移动端的首选方案。
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>1. 获取平台元数据</CardTitle>
          <CardDescription>所有关键端点与支持能力均可通过 Discovery 文档自动获得</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <p>
            请求 <code>/.well-known/openid-configuration</code>，得到授权端点、令牌端点、JWKS 等信息。示例：
          </p>
          <pre className="overflow-auto rounded-lg bg-slate-950/80 p-4 text-xs text-slate-200">
{`GET /.well-known/openid-configuration HTTP/1.1
Host: ${hostExample}`}
          </pre>
          <p>
            该文档可直接用于 OpenID Certified SDK 或工具（如 AppAuth、Auth.js、Keycloak adapter）。JWKS URL 通常为 <code>/jwks</code>，用于验证 ID Token。
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>2. 构造授权请求</CardTitle>
          <CardDescription>跳转用户浏览器到授权端点，携带 PKCE 参数和所需 scope</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <div>
            建议 scope 至少包含 {coreScopes.map((scope) => <code key={scope} className="mx-1">{scope}</code>)}。示例 URL：
          </div>
          <pre className="overflow-auto rounded-lg bg-slate-950/80 p-4 text-xs text-slate-200">
{`GET /authorize?response_type=code
  &client_id=YOUR_CLIENT_ID
  &redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb
  &scope=openid%20profile%20email
  &state=xyz123
  &code_challenge=pkce_challenge
  &code_challenge_method=S256 HTTP/1.1
Host: ${hostExample}`}
          </pre>
          <p>
            <strong>state</strong> 用于防止 CSRF，建议在回调时校验；<strong>code_challenge</strong> 来自 PKCE 过程，使用 S256 方法。若客户端被配置为机密，并使用自定义 login_hint、prompt、acr 等参数，也可在此处附加。
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>3. 使用授权码交换 Token</CardTitle>
          <CardDescription>后端或回调页面携带 code_verifier 调用 /token</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <p>PKCE 公共客户端示例：</p>
          <pre className="overflow-auto rounded-lg bg-slate-950/80 p-4 text-xs text-slate-200">
{`POST /token HTTP/1.1
Host: ${hostExample}
Content-Type: application/x-www-form-urlencoded

client_id=YOUR_CLIENT_ID&
authorization_code=CODE_FROM_CALLBACK&
code_verifier=ORIGINAL_PKCE_VERIFIER&
grant_type=authorization_code&
redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb`}
          </pre>
          <p>
            机密客户端需额外提供 <code>Authorization: Basic base64(client_id:client_secret)</code> 或在表单中附加 <code>client_secret</code>。返回的 <code>id_token</code>、<code>access_token</code>、<code>refresh_token</code> 请安全存储。
          </p>
          <p>
            可选：调用 <code>/token</code> 时附加 <code>code_verifier</code> 错误将导致 <code>invalid_grant</code>。若需要长期会话，请保存 refresh_token 并周期性调用 <code>grant_type=refresh_token</code> 以续约。
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>4. 校验 ID Token 与 UserInfo</CardTitle>
          <CardDescription>确保 Token 签名合法，且声明符合业务需求</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 text-sm text-muted-foreground">
          <p>使用 JWKS 验证 ID Token 示例（Node.js）：</p>
          <pre className="overflow-auto rounded-lg bg-slate-950/80 p-4 text-xs text-slate-200">
{`import { createRemoteJWKSet, jwtVerify } from 'jose';

const jwks = createRemoteJWKSet(new URL('https://${hostExample}/jwks'));
const { payload } = await jwtVerify(idToken, jwks, {
  issuer: 'https://${hostExample}',
  audience: 'YOUR_CLIENT_ID',
});
console.log(payload.sub, payload.email, payload.acr);
`}
          </pre>
          <p>
            使用 Access Token 调用 <code>/userinfo</code> 获取标准声明：
          </p>
          <pre className="overflow-auto rounded-lg bg-slate-950/80 p-4 text-xs text-slate-200">
{`curl https://${hostExample}/userinfo \
  -H "Authorization: Bearer ${'{ACCESS_TOKEN}'}"`}
          </pre>
          <p>
            返回 JSON 中应包含 <code>sub</code>、<code>name</code>、<code>email</code> 等字段。若需要组织信息，可在 scope 中加入自定义值，并在后端映射为额外 claim。
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>5. 常见排错清单</CardTitle>
          <CardDescription>结合前端调试器与“应用日志”定位问题</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm text-muted-foreground">
          <ul className="space-y-2">
            {troubleshooting.map((item) => (
              <li key={item.title}>
                <span className="font-medium text-foreground">{item.title}</span>
                <span className="mx-2">—</span>
                <span>{item.hint}</span>
              </li>
            ))}
          </ul>
          <p>
            进一步排查时，可打开“应用日志”页面筛选 request_id，与终端日志对照；或在“平台状态”中检查后端健康情况。
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
