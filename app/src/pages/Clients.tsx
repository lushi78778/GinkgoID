import { useEffect, useState } from 'react'
import { apiJSON } from '../lib/api'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../components/ui/card'
import { Label } from '../components/ui/label'
import { Input } from '../components/ui/input'
import { Button } from '../components/ui/button'
import { generatePKCE } from '../lib/pkce'
import { useAuth } from '@/lib/auth'
import { Card as SCard } from '@/components/ui/card'
import { Tooltip } from '@/components/ui/tooltip'

// Tooltip component shows explanation on hover

type RegisterResp = {
  client_id: string
  client_secret?: string
  registration_access_token: string
  registration_client_uri: string
  redirect_uris: string[]
  token_endpoint_auth_method: string
}

export default function Clients() {
  const { me } = useAuth()
  const defaultRedirect = `${window.location.origin}/app/cb`
  const [redirect, setRedirect] = useState(defaultRedirect)
  const [subjectType, setSubjectType] = useState<'public'|'pairwise'>('public')
  const [publicClient, setPublicClient] = useState(true)
  const [resp, setResp] = useState<RegisterResp | null>(null)
  const [error, setError] = useState('')
  const [detail, setDetail] = useState<any | null>(null)
  const [saving, setSaving] = useState(false)
  const [mine, setMine] = useState<any[]>([])

  useEffect(() => {
    const saved = localStorage.getItem('ginkgo-client')
    if (saved) setResp(JSON.parse(saved))
    refreshMine()
    const t = setInterval(refreshMine, 15000)
    return () => clearInterval(t)
  }, [])

  const refreshMine = async () => {
    try {
      const list = await fetch('/api/my/clients', { credentials:'include' }).then(r=>r.json())
      setMine(Array.isArray(list)? list : [])
    } catch { setMine([]) }
  }

  const register = async () => {
    setError('')
    try {
      // 基础校验：Redirect URI 必须是绝对 http(s) 地址
      let u: URL
      try { u = new URL(redirect) } catch { throw new Error('Redirect URI 无效：请填写以 http:// 或 https:// 开头的完整地址') }
      if (!/^https?:$/.test(u.protocol)) throw new Error('Redirect URI 仅支持 http/https')
      const body = {
        client_name: 'Ginkgo Console',
        redirect_uris: [redirect],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: publicClient ? 'none' : 'client_secret_basic',
        scope: 'openid profile email offline_access',
        subject_type: subjectType,
      }
      const r = await apiJSON<RegisterResp>('/register', body, {})
      // 最小持久化：只保存授权所需字段，隐藏 RAT/管理 URI
      const minimal: any = { client_id: r.client_id, token_endpoint_auth_method: r.token_endpoint_auth_method }
      if (r.client_secret) minimal.client_secret = r.client_secret
      setResp(minimal)
      localStorage.setItem('ginkgo-client', JSON.stringify(minimal))
      // 注册后刷新“我的应用”
      await refreshMine()
    } catch (e: any) {
      setError(e.message || '注册失败')
    }
  }

  const startAuth = async () => {
    if (!resp) { setError('请先完成注册'); return }
    // 发起授权前做预检查：确认客户端处于已批准状态，redirect 匹配
    try {
      const meta = await fetch(`${resp.registration_client_uri}&client_id=${encodeURIComponent(resp.client_id)}`, { headers:{ Authorization: `Bearer ${resp.registration_access_token}` }, credentials:'include' }).then(r=>r.json())
      if (meta && meta.approved === false) {
        setError('当前客户端尚未批准（unauthorized_client）。请联系管理员在服务端审核通过，或在配置中关闭 require_approval。')
        return
      }
      if (Array.isArray(meta?.redirect_uris) && !meta.redirect_uris.includes(redirect)) {
        setError('当前 Redirect URI 与已注册值不一致，请先在“客户端管理 > 获取信息/保存修改”里更新 redirect_uris。')
        return
      }
    } catch {}
    const { verifier, challenge, method } = await generatePKCE()
    const state = Math.random().toString(36).slice(2)
    // 保存到本地以便回调页使用
    localStorage.setItem('ginkgo-pkce', JSON.stringify({ client_id: resp.client_id, verifier, redirect_uri: redirect, publicClient }))
    const q = new URLSearchParams({
      response_type: 'code',
      client_id: resp.client_id,
      redirect_uri: redirect,
      scope: 'openid profile email offline_access',
      state,
      code_challenge: challenge,
      code_challenge_method: method,
    })
    window.location.href = `/authorize?${q.toString()}`
  }

  const loadClient = async () => {
    if (!resp) return
    const u = new URL(resp.registration_client_uri)
    u.searchParams.set('client_id', resp.client_id)
    const data = await fetch(u.toString(), { headers: { Authorization: `Bearer ${resp.registration_access_token}` }, credentials: 'include' }).then(r=>r.json())
    setDetail(data)
  }

  const updateClient = async () => {
    if (!resp || !detail) return
    setSaving(true)
    try {
      const u = new URL(resp.registration_client_uri)
      u.searchParams.set('client_id', resp.client_id)
      await fetch(u.toString(), { method:'PUT', headers: { 'Authorization': `Bearer ${resp.registration_access_token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({
        client_name: detail.client_name,
        redirect_uris: detail.redirect_uris,
        post_logout_redirect_uris: detail.post_logout_redirect_uris,
        frontchannel_logout_uri: detail.frontchannel_logout_uri,
        backchannel_logout_uri: detail.backchannel_logout_uri,
        subject_type: detail.subject_type,
        token_endpoint_auth_method: detail.token_endpoint_auth_method,
      }) })
      await loadClient()
    } finally { setSaving(false) }
  }

  const rotateRAT = async () => {
    if (!resp) return
    const url = `/register/rotate?client_id=${encodeURIComponent(resp.client_id)}`
    const r = await fetch(url, { method:'POST', headers: { Authorization: `Bearer ${resp.registration_access_token}` } })
    if (r.ok) {
      const data = await r.json()
      const updated = { ...resp, registration_access_token: data.registration_access_token }
      setResp(updated)
      localStorage.setItem('ginkgo-client', JSON.stringify(updated))
    }
  }

  const deleteClient = async () => {
    if (!resp) return
    const u = new URL(resp.registration_client_uri)
    u.searchParams.set('client_id', resp.client_id)
    const r = await fetch(u.toString(), { method:'DELETE', headers:{ Authorization: `Bearer ${resp.registration_access_token}` } })
    if (r.status === 204) { setResp(null); setDetail(null); localStorage.removeItem('ginkgo-client') }
  }

  if (!me || (!me.is_admin && !(me as any).is_dev)) {
    return (
      <div className="container py-10">
        <SCard>
          <CardHeader>
            <CardTitle>需要开发者权限</CardTitle>
            <CardDescription>请使用开发者或管理员账户登录</CardDescription>
          </CardHeader>
          <CardContent>
            <a className="btn" href={`/login?next=${encodeURIComponent('/app/clients')}`}>去登录</a>
          </CardContent>
        </SCard>
      </div>
    )
  }

  return (
    <div className="container py-10 space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>我的应用</CardTitle>
          <CardDescription>你拥有的已注册客户端</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-2">名称</th>
                  <th className="text-left py-2">client_id</th>
                  <th className="text-left py-2">类型</th>
                  <th className="text-left py-2">状态</th>
                  <th className="text-left py-2">创建时间</th>
                  <th className="text-left py-2">操作</th>
                </tr>
              </thead>
              <tbody>
                {mine.map((c:any)=>(
                  <tr key={c.client_id} className="border-b border-border/60">
                    <td className="py-2 align-middle">{c.client_name || '-'}</td>
                    <td className="py-2 align-middle"><code className="text-xs break-all">{c.client_id}</code></td>
                    <td className="py-2 align-middle">{c.token_endpoint_auth_method==='none' ? '公共' : '机密'}</td>
                    <td className="py-2 align-middle">{c.approved ? '已批准' : '待批准'}</td>
                    <td className="py-2 align-middle">{c.created_at ? new Date(c.created_at*1000).toLocaleString() : '-'}</td>
                    <td className="py-2 align-middle space-x-2">
                      <Button variant="outline" onClick={()=>{
                        // 尝试读取已保存的 secret（机密客户端需要）
                        let secret: string | undefined
                        const secrets = JSON.parse(localStorage.getItem('ginkgo-secrets')||'{}') as Record<string,string>
                        if (c.token_endpoint_auth_method !== 'none') {
                          secret = secrets[c.client_id]
                          if (!secret) {
                            const input = window.prompt('请输入该客户端的 client_secret（仅用于本地开发，保存在本地浏览器）')
                            if (!input) return
                            secret = input
                            secrets[c.client_id] = input
                            localStorage.setItem('ginkgo-secrets', JSON.stringify(secrets))
                          }
                          setPublicClient(false)
                        } else {
                          setPublicClient(true)
                        }
                        const obj:any = { client_id: c.client_id, registration_access_token:'', registration_client_uri:'', redirect_uris:[], token_endpoint_auth_method: c.token_endpoint_auth_method }
                        if (secret) obj.client_secret = secret
                        setResp(obj)
                        localStorage.setItem('ginkgo-client', JSON.stringify(obj))
                      }}>用于授权</Button>
                      <Button variant="ghost" onClick={()=>navigator.clipboard.writeText(c.client_id)}>复制ID</Button>
                      {c.approved ? (
                        <Button variant="outline" onClick={async()=>{
                          if (!confirm('确定要禁用该客户端吗？')) return
                          const r = await fetch(`/api/my/clients/${encodeURIComponent(c.client_id)}/disable`, { method:'PUT', credentials:'include' })
                          if (r.status===204) { await refreshMine() }
                        }}>禁用</Button>
                      ) : (
                        <Button variant="outline" onClick={async()=>{
                          const r = await fetch(`/api/my/clients/${encodeURIComponent(c.client_id)}/enable`, { method:'PUT', credentials:'include' })
                          if (r.status===204) { await refreshMine() }
                        }}>启用</Button>
                      )}
                      <Button variant="destructive" onClick={async()=>{
                        if (!confirm('确定要禁用该客户端吗？')) return
                        const r = await fetch(`/api/my/clients/${encodeURIComponent(c.client_id)}`, { method:'DELETE', credentials:'include' })
                        if (r.status===204) { await refreshMine() }
                      }}>删除</Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {mine.length===0 && <div className="text-sm text-muted-foreground">暂无应用</div>}
          </div>
          <div className="mt-2"><Button variant="outline" onClick={refreshMine}>刷新列表</Button></div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>注册新应用 (OIDC 客户端)</CardTitle>
          <CardDescription>用于授权跳转与令牌发放的 OIDC 客户端</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 max-w-2xl">
          <Label>Redirect URI<Tooltip text="必须与 /authorize 请求中的 redirect_uri 完全一致；授权成功后会重定向回该地址" /></Label>
          <Input value={redirect} onChange={e=>setRedirect(e.target.value)} placeholder="http://127.0.0.1:9999/cb" />
          <div className="text-sm text-slate-400">建议使用 {defaultRedirect} 以便回到本页面回显授权结果</div>
          <Label>Subject Type<Tooltip text="public：同一用户在所有客户端 sub 相同；pairwise：按 sector/domain 派生不同 sub 值，提升隐私" /></Label>
          <div className="flex items-center gap-3 text-sm">
            <label className="flex items-center gap-2"><input type="radio" checked={subjectType==='public'} onChange={()=>setSubjectType('public')} /> public</label>
            <label className="flex items-center gap-2"><input type="radio" checked={subjectType==='pairwise'} onChange={()=>setSubjectType('pairwise')} /> pairwise</label>
          </div>
          <Label>客户端类型<Tooltip text="公共客户端：配合 PKCE，token 端点无需 client_secret；机密客户端：需在服务端以 Basic 或表单方式携带 client_secret" /></Label>
          <div className="flex items-center gap-3 text-sm">
            <label className="flex items-center gap-2"><input type="radio" checked={publicClient} onChange={()=>setPublicClient(true)} /> 公共客户端（token 端点不需要密钥，配合 PKCE）</label>
            <label className="flex items-center gap-2"><input type="radio" checked={!publicClient} onChange={()=>setPublicClient(false)} /> 机密客户端（需要 client_secret）</label>
          </div>
          <div className="mt-2">
            <Button onClick={register}>注册客户端</Button>
          </div>
          {error && <p className="text-red-500 text-sm">{error}</p>}
        </CardContent>
      </Card>

      {resp && (
        <Card>
          <CardHeader>
            <CardTitle>注册成功</CardTitle>
            <CardDescription>请妥善保存以下凭据</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-2 text-sm">
            <div>client_id: <code>{resp.client_id}</code></div>
            {resp.client_secret && <div>client_secret: <code>{resp.client_secret}</code></div>}
            <div className="mt-3 grid gap-2">
              <div className="text-xs text-muted-foreground">发起授权前确保：客户端已批准、redirect_uri 与注册一致、公共客户端需携带 PKCE（本页自动生成）。如遇 {`{"error":"unauthorized_client"}`}，多半是未批准或 client_id 不存在。</div>
              <Button onClick={startAuth}>发起授权（Authorization Code + PKCE）</Button>
            </div>
          </CardContent>
        </Card>
      )}

      {resp && (
        <Card>
          <CardHeader>
            <CardTitle>客户端管理</CardTitle>
            <CardDescription>查询/修改/轮换/禁用 已注册客户端</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 text-sm">
            <div className="flex items-center gap-2">
              <Button onClick={loadClient}>获取信息</Button>
              <Button onClick={rotateRAT} variant="outline">轮换 RAT</Button>
              <Button onClick={deleteClient} variant="destructive">禁用客户端</Button>
            </div>
            {detail && (
              <div className="grid gap-3 max-w-3xl">
                <Label>client_name</Label>
                <Input value={detail.client_name || ''} onChange={e=>setDetail({ ...detail, client_name: e.target.value })} />
                <Label>redirect_uris</Label>
                <Input value={(detail.redirect_uris || []).join(', ')} onChange={e=>setDetail({ ...detail, redirect_uris: e.target.value.split(',').map((s:string)=>s.trim()).filter(Boolean) })} />
                <Label>post_logout_redirect_uris</Label>
                <Input value={(detail.post_logout_redirect_uris || []).join(', ')} onChange={e=>setDetail({ ...detail, post_logout_redirect_uris: e.target.value.split(',').map((s:string)=>s.trim()).filter(Boolean) })} />
                <Label>frontchannel_logout_uri</Label>
                <Input value={detail.frontchannel_logout_uri || ''} onChange={e=>setDetail({ ...detail, frontchannel_logout_uri: e.target.value })} />
                <Label>backchannel_logout_uri</Label>
                <Input value={detail.backchannel_logout_uri || ''} onChange={e=>setDetail({ ...detail, backchannel_logout_uri: e.target.value })} />
                <div className="flex justify-end">
                  <Button onClick={updateClient} disabled={saving}>{saving ? '保存中...' : '保存修改'}</Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
