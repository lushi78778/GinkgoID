import { useEffect, useState } from 'react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../components/ui/card'
import { Button } from '../components/ui/button'
import { Label } from '@/components/ui/label'
import { toast } from 'sonner'

type TokenSet = { access_token: string; id_token?: string; refresh_token?: string; token_type: string; expires_in: number }

export default function Callback() {
  const [params] = useState(() => {
    const hash = window.location.hash.startsWith('#') ? window.location.hash.slice(1) : ''
    const search = window.location.search.startsWith('?') ? window.location.search.slice(1) : ''
    const raw = hash || search
    return new URLSearchParams(raw)
  })
  const [code, setCode] = useState('')
  const [state, setState] = useState('')
  const [tokens, setTokens] = useState<TokenSet | null>(null)
  const [userinfo, setUserinfo] = useState<any>(null)
  const [error, setError] = useState('')
  const [idHeader, setIdHeader] = useState('')
  const [idPayload, setIdPayload] = useState('')

  useEffect(() => {
    setCode(params.get('code') || '')
    setState(params.get('state') || '')
  }, [])

  const exchange = async () => {
    setError('')
    try {
      const saved = JSON.parse(localStorage.getItem('ginkgo-pkce') || '{}') as { client_id: string; verifier: string; redirect_uri: string; publicClient?: boolean }
      const reg = JSON.parse(localStorage.getItem('ginkgo-client') || 'null') as null | { client_id: string; client_secret?: string; token_endpoint_auth_method?: string }
      if (!saved.client_id || !saved.verifier || !saved.redirect_uri) throw new Error('缺少 PKCE 上下文，请从客户端页面重新发起授权')
      const body = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: saved.redirect_uri, code_verifier: saved.verifier })
      let headers: Record<string,string> = { 'Content-Type': 'application/x-www-form-urlencoded' }
      // 客户端认证策略：机密客户端走 Basic；公共客户端仅带 client_id
      if (reg && reg.token_endpoint_auth_method === 'client_secret_basic' && reg.client_secret) {
        const basic = btoa(`${saved.client_id}:${reg.client_secret}`)
        headers['Authorization'] = `Basic ${basic}`
      } else {
        body.set('client_id', saved.client_id)
        if (reg && reg.token_endpoint_auth_method === 'client_secret_post' && reg.client_secret) {
          body.set('client_secret', reg.client_secret)
        }
      }
      const res = await fetch('/token', { method: 'POST', body, headers, credentials: 'include' })
      const text = await res.text()
      if (!res.ok) {
        // 友好提示
        let msg = text
        try {
          const j = JSON.parse(text)
          const err = j.error || ''
          const desc = j.error_description || ''
          if (err === 'invalid_client') {
            msg = 'invalid_client：令牌端点客户端认证失败。机密客户端须使用 Basic 携带 client_id/client_secret；公共客户端应配置 token_endpoint_auth_method=none 并仅带 client_id。'
          } else if (err === 'invalid_grant') {
            msg = 'invalid_grant：授权码不可用（已使用/过期）、redirect_uri 不一致、或 PKCE 校验失败。'
          } else if (err === 'unauthorized_client') {
            msg = 'unauthorized_client：客户端未获批准或不存在，请在客户端页面先检查“已批准”状态。'
          } else if (desc) {
            msg = desc
          }
        } catch {}
        throw new Error(msg)
      }
      const data = JSON.parse(text) as TokenSet
      setTokens(data)
      localStorage.setItem('ginkgo-tokens', text)
      if (data.id_token) {
        const d = decodeIdToken(data.id_token)
        setIdHeader(d.header)
        setIdPayload(d.payload)
      }
    } catch (e: any) {
      setError(e.message || '兑换令牌失败')
    }
  }

  const loadUserinfo = async () => {
    if (!tokens?.access_token) return
    const r = await fetch('/userinfo', { headers: { Authorization: `Bearer ${tokens.access_token}` } })
    const text = await r.text()
    try { setUserinfo(JSON.parse(text)) } catch { setUserinfo(text) }
  }

  return (
    <div className="container py-10 space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>回调结果</CardTitle>
          <CardDescription>从 /authorize 返回的参数</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 text-sm">
          <div>code: <code>{code || '-'}</code></div>
          <div>state: <code>{state || '-'}</code></div>
          {error && <div className="text-red-500">{error}</div>}
          <div className="mt-2"><Button onClick={exchange} disabled={!code}>兑换令牌</Button></div>
        </CardContent>
      </Card>
      {tokens && (
        <Card>
          <CardHeader>
            <CardTitle>令牌</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="text-xs whitespace-pre-wrap break-all">{JSON.stringify(tokens, null, 2)}</pre>
            <div className="mt-2"><Button onClick={loadUserinfo}>调用 /userinfo</Button></div>
            {userinfo && <pre className="text-xs whitespace-pre-wrap break-all mt-2">{JSON.stringify(userinfo, null, 2)}</pre>}
            {tokens.id_token && (
              <div className="mt-4 grid gap-2">
                <Label>ID Token 解码</Label>
                <div className="grid md:grid-cols-2 gap-3">
                  <div>
                    <div className="text-sm text-muted-foreground">Header</div>
                    <pre className="text-xs whitespace-pre-wrap break-all p-2 rounded-md border border-border">{idHeader}</pre>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground">Payload</div>
                    <pre className="text-xs whitespace-pre-wrap break-all p-2 rounded-md border border-border">{idPayload}</pre>
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button onClick={()=>copy(tokens.access_token!, 'access_token')}>复制 Access Token</Button>
                  <Button onClick={()=>copy(tokens.id_token!, 'id_token')}>复制 ID Token</Button>
                  {tokens.refresh_token && <Button onClick={()=>copy(tokens.refresh_token!, 'refresh_token')}>复制 Refresh Token</Button>}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}

function base64urlToString(b64url: string) {
  const pad = b64url.length % 4 === 0 ? '' : '='.repeat(4 - (b64url.length % 4))
  const b64 = b64url.replace(/-/g,'+').replace(/_/g,'/') + pad
  const str = atob(b64)
  try { return decodeURIComponent(Array.prototype.map.call(str, (c: string)=>'%'+('00'+c.charCodeAt(0).toString(16)).slice(-2)).join('')) } catch { return str }
}

function decodeIdToken(idt: string): { header: string; payload: string } {
  const parts = idt.split('.')
  if (parts.length < 2) return { header: '', payload: '' }
  const header = base64urlToString(parts[0])
  const payload = base64urlToString(parts[1])
  let h = header, p = payload
  try { h = JSON.stringify(JSON.parse(header), null, 2) } catch {}
  try { p = JSON.stringify(JSON.parse(payload), null, 2) } catch {}
  return { header: h, payload: p }
}

function copy(text: string, label: string) {
  navigator.clipboard.writeText(text).then(()=>toast.success(`已复制 ${label}`)).catch(()=>toast.error('复制失败'))
}
