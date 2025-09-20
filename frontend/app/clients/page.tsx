"use client";

import { useEffect, useState } from 'react'
import { apiJSON } from '@/lib/api'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { generatePKCE } from '@/lib/pkce'
import { useAuth } from '@/lib/auth'
import { Tooltip } from '@/components/ui/tooltip'

// Tooltip component shows explanation on hover

type RegisterResp = {
  client_id: string
  client_secret?: string
  registration_access_token?: string
  registration_client_uri?: string
  redirect_uris?: string[]
  token_endpoint_auth_method: string
}

export default function Clients() {
  const { me } = useAuth()
  const [redirect, setRedirect] = useState('')
  const [subjectType, setSubjectType] = useState<'public' | 'pairwise'>('public')
  const [publicClient, setPublicClient] = useState(true)
  const [resp, setResp] = useState<RegisterResp | null>(null)
  const [error, setError] = useState('')
  const [detail, setDetail] = useState<any | null>(null)
  const [saving, setSaving] = useState(false)
  const [mine, setMine] = useState<any[]>([])

  useEffect(() => {
    if (typeof window !== 'undefined') {
      setRedirect(`${window.location.origin}/cb`)
      const saved = window.localStorage.getItem('ginkgo-client')
      if (saved) {
        try {
          const parsed = JSON.parse(saved)
          setResp(parsed)
          if (parsed?.token_endpoint_auth_method === 'none') {
            setPublicClient(true)
          } else if (parsed?.token_endpoint_auth_method) {
            setPublicClient(false)
          }
        } catch {
          window.localStorage.removeItem('ginkgo-client')
        }
      }
    }
    refreshMine()
    const timer = setInterval(refreshMine, 15000)
    return () => clearInterval(timer)
  }, [])

  const refreshMine = async () => {
    try {
      const list = await fetch('/api/my/clients', { credentials: 'include' }).then(r => r.json())
      setMine(Array.isArray(list) ? list : [])
    } catch {
      setMine([])
    }
  }

  const register = async () => {
    setError('')
    try {
      let parsed: URL
      try {
        parsed = new URL(redirect)
      } catch {
        throw new Error('Redirect URI 无效：请填写以 http:// 或 https:// 开头的完整地址')
      }
      if (!/^https?:$/.test(parsed.protocol)) {
        throw new Error('Redirect URI 仅支持 http/https')
      }
      const body = {
        client_name: 'Ginkgo Console',
        redirect_uris: [redirect],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: publicClient ? 'none' : 'client_secret_basic',
        scope: 'openid profile email offline_access',
        subject_type: subjectType,
      }
      const data = await apiJSON<RegisterResp>('/register', body, {})
      setResp(data)
      if (typeof window !== 'undefined') {
        window.localStorage.setItem('ginkgo-client', JSON.stringify(data))
      }
      await refreshMine()
    } catch (e: any) {
      setError(e.message || '注册失败')
    }
  }

  const startAuth = async () => {
    if (!resp) {
      setError('请先完成注册')
      return
    }
    if (!resp.registration_client_uri || !resp.registration_access_token) {
      setError('缺少注册访问令牌信息，请重新注册或手动输入 RAT')
      return
    }
    try {
      const meta = await fetch(
        `${resp.registration_client_uri}&client_id=${encodeURIComponent(resp.client_id)}`,
        { headers: { Authorization: `Bearer ${resp.registration_access_token}` }, credentials: 'include' }
      ).then(r => r.json())
      if (meta && meta.approved === false) {
        setError('当前客户端尚未批准，请联系管理员在后台通过审核。')
        return
      }
      if (Array.isArray(meta?.redirect_uris) && !meta.redirect_uris.includes(redirect)) {
        setError('当前 Redirect URI 与已注册值不一致，请先在客户端管理中更新 redirect_uris。')
        return
      }
    } catch {
      /* 忽略元数据查询错误，仅作为提示 */
    }
    const { verifier, challenge, method } = await generatePKCE()
    const state = Math.random().toString(36).slice(2)
    if (typeof window !== 'undefined') {
      window.localStorage.setItem(
        'ginkgo-pkce',
        JSON.stringify({ client_id: resp.client_id, verifier, redirect_uri: redirect, publicClient })
      )
      const params = new URLSearchParams({
        response_type: 'code',
        client_id: resp.client_id,
        redirect_uri: redirect,
        scope: 'openid profile email offline_access',
        state,
        code_challenge: challenge,
        code_challenge_method: method,
      })
      window.location.href = `/authorize?${params.toString()}`
    }
  }

  const loadClient = async () => {
    if (!resp?.registration_client_uri || !resp.registration_access_token) return
    const url = new URL(resp.registration_client_uri)
    url.searchParams.set('client_id', resp.client_id)
    const data = await fetch(url.toString(), {
      headers: { Authorization: `Bearer ${resp.registration_access_token}` },
      credentials: 'include',
    }).then(r => r.json())
    setDetail(data)
  }

  const updateClient = async () => {
    if (!resp?.registration_client_uri || !resp.registration_access_token || !detail) return
    setSaving(true)
    try {
      const url = new URL(resp.registration_client_uri)
      url.searchParams.set('client_id', resp.client_id)
      await fetch(url.toString(), {
        method: 'PUT',
        headers: {
          Authorization: `Bearer ${resp.registration_access_token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          client_name: detail.client_name,
          redirect_uris: detail.redirect_uris,
          post_logout_redirect_uris: detail.post_logout_redirect_uris,
          frontchannel_logout_uri: detail.frontchannel_logout_uri,
          backchannel_logout_uri: detail.backchannel_logout_uri,
          subject_type: detail.subject_type,
          token_endpoint_auth_method: detail.token_endpoint_auth_method,
        }),
      })
      await loadClient()
    } finally {
      setSaving(false)
    }
  }

  const rotateRAT = async () => {
    if (!resp?.registration_access_token) return
    const url = `/register/rotate?client_id=${encodeURIComponent(resp.client_id)}`
    const r = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${resp.registration_access_token}` },
    })
    if (r.ok) {
      const data = await r.json()
      const updated = { ...resp, registration_access_token: data.registration_access_token }
      setResp(updated)
      if (typeof window !== 'undefined') {
        window.localStorage.setItem('ginkgo-client', JSON.stringify(updated))
      }
    }
  }

  const deleteClient = async () => {
    if (!resp?.registration_client_uri || !resp.registration_access_token) return
    const url = new URL(resp.registration_client_uri)
    url.searchParams.set('client_id', resp.client_id)
    const r = await fetch(url.toString(), {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${resp.registration_access_token}` },
    })
    if (r.status === 204) {
      setResp(null)
      setDetail(null)
      if (typeof window !== 'undefined') {
        window.localStorage.removeItem('ginkgo-client')
      }
    }
  }

  const handleUseForAuth = (client: any) => {
    let secret: string | undefined
    const store = typeof window !== 'undefined' ? window.localStorage : null
    if (!store) return
    const secrets = JSON.parse(store.getItem('ginkgo-secrets') || '{}') as Record<string, string>
    if (client.token_endpoint_auth_method !== 'none') {
      secret = secrets[client.client_id]
      if (!secret) {
        const input = window.prompt('请输入该客户端的 client_secret（仅用于本地开发，保存在本地浏览器）')
        if (!input) return
        secret = input
        secrets[client.client_id] = input
        store.setItem('ginkgo-secrets', JSON.stringify(secrets))
      }
      setPublicClient(false)
    } else {
      setPublicClient(true)
    }
    const obj: RegisterResp = {
      client_id: client.client_id,
      token_endpoint_auth_method: client.token_endpoint_auth_method,
    }
    if (secret) obj.client_secret = secret
    setResp(obj)
    store.setItem('ginkgo-client', JSON.stringify(obj))
  }

  if (!me || (!me.is_admin && !(me as any)?.is_dev)) {
    return (
      <div className="container py-10">
        <Card>
          <CardHeader>
            <CardTitle>需要开发者权限</CardTitle>
            <CardDescription>请使用开发者或管理员账户登录</CardDescription>
          </CardHeader>
          <CardContent>
            <a className="btn" href={`/login?next=${encodeURIComponent('/clients')}`}>去登录</a>
          </CardContent>
        </Card>
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
                {mine.map((c: any) => (
                  <tr key={c.client_id} className="border-b border-border/60">
                    <td className="py-2 align-middle">{c.client_name || '-'}</td>
                    <td className="py-2 align-middle"><code className="text-xs break-all">{c.client_id}</code></td>
                    <td className="py-2 align-middle">{c.token_endpoint_auth_method === 'none' ? '公共' : '机密'}</td>
                    <td className="py-2 align-middle">{c.approved ? '已批准' : '待批准'}</td>
                    <td className="py-2 align-middle">{c.created_at ? new Date(c.created_at * 1000).toLocaleString() : '-'}</td>
                    <td className="py-2 align-middle space-x-2">
                      <Button variant="outline" onClick={() => handleUseForAuth(c)}>用于授权</Button>
                      <Button variant="ghost" onClick={() => navigator.clipboard.writeText(c.client_id)}>复制ID</Button>
                      {c.approved ? (
                        <Button variant="outline" onClick={async () => {
                          if (!confirm('确定要禁用该客户端吗？')) return
                          const r = await fetch(`/api/my/clients/${encodeURIComponent(c.client_id)}/disable`, {
                            method: 'PUT',
                            credentials: 'include',
                          })
                          if (r.status === 204) await refreshMine()
                        }}>禁用</Button>
                      ) : (
                        <Button variant="outline" onClick={async () => {
                          const r = await fetch(`/api/my/clients/${encodeURIComponent(c.client_id)}/enable`, {
                            method: 'PUT',
                            credentials: 'include',
                          })
                          if (r.status === 204) await refreshMine()
                        }}>启用</Button>
                      )}
                      <Button variant="destructive" onClick={async () => {
                        if (!confirm('确定要禁用该客户端吗？')) return
                        const r = await fetch(`/api/my/clients/${encodeURIComponent(c.client_id)}`, {
                          method: 'DELETE',
                          credentials: 'include',
                        })
                        if (r.status === 204) await refreshMine()
                      }}>删除</Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {mine.length === 0 && <div className="text-sm text-muted-foreground">暂无应用</div>}
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
          <Input value={redirect} onChange={e => setRedirect(e.target.value)} placeholder="http://127.0.0.1:9999/cb" />
          <div className="text-sm text-slate-400">建议使用 {redirect || 'http://127.0.0.1:9999/cb'} 以便回到本页面回显授权结果</div>
          <Label>Subject Type<Tooltip text="public：同一用户在所有客户端 sub 相同；pairwise：按 sector/domain 派生不同 sub 值，提升隐私" /></Label>
          <div className="flex items-center gap-3 text-sm">
            <label className="flex items-center gap-2"><input type="radio" checked={subjectType === 'public'} onChange={() => setSubjectType('public')} /> public</label>
            <label className="flex items-center gap-2"><input type="radio" checked={subjectType === 'pairwise'} onChange={() => setSubjectType('pairwise')} /> pairwise</label>
          </div>
          <Label>客户端类型<Tooltip text="公共客户端：配合 PKCE，token 端点无需 client_secret；机密客户端：需在服务端以 Basic 或表单方式携带 client_secret" /></Label>
          <div className="flex items-center gap-3 text-sm">
            <label className="flex items-center gap-2"><input type="radio" checked={publicClient} onChange={() => setPublicClient(true)} /> 公共客户端（token 端点不需要密钥，配合 PKCE）</label>
            <label className="flex items-center gap-2"><input type="radio" checked={!publicClient} onChange={() => setPublicClient(false)} /> 机密客户端（需要 client_secret）</label>
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
              <div className="text-xs text-muted-foreground">发起授权前确保：客户端已批准、redirect_uri 与注册一致、公共客户端需配合 PKCE。如遇 {`{"error":"unauthorized_client"}`} 多半是未审批通过或 client_id 不存在。</div>
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
                <Input value={detail.client_name || ''} onChange={e => setDetail({ ...detail, client_name: e.target.value })} />
                <Label>redirect_uris</Label>
                <Input value={(detail.redirect_uris || []).join(', ')} onChange={e => setDetail({ ...detail, redirect_uris: e.target.value.split(',').map((s: string) => s.trim()).filter(Boolean) })} />
                <Label>post_logout_redirect_uris</Label>
                <Input value={(detail.post_logout_redirect_uris || []).join(', ')} onChange={e => setDetail({ ...detail, post_logout_redirect_uris: e.target.value.split(',').map((s: string) => s.trim()).filter(Boolean) })} />
                <Label>frontchannel_logout_uri</Label>
                <Input value={detail.frontchannel_logout_uri || ''} onChange={e => setDetail({ ...detail, frontchannel_logout_uri: e.target.value })} />
                <Label>backchannel_logout_uri</Label>
                <Input value={detail.backchannel_logout_uri || ''} onChange={e => setDetail({ ...detail, backchannel_logout_uri: e.target.value })} />
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
