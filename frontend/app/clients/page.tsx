"use client";

import { useEffect, useMemo, useState } from 'react'
import { apiJSON } from '@/lib/api'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { generatePKCE } from '@/lib/pkce'
import { useAuth } from '@/lib/auth'
import { Tooltip } from '@/components/ui/tooltip'
import { toast } from 'sonner'

type RegisterResp = {
  client_id: string
  client_secret?: string
  registration_access_token?: string
  registration_client_uri?: string
  redirect_uris?: string[]
  token_endpoint_auth_method: string
}

type OwnedClient = {
  client_id: string
  client_name?: string
  token_endpoint_auth_method: string
  approved: boolean
  enabled: boolean
  created_at?: number
}

const sanitizeList = (value: string) =>
  value
    .split(/[\s,\n]+/)
    .map((item) => item.trim())
    .filter(Boolean)

export default function Clients() {
  const { me } = useAuth()
  const [subjectType, setSubjectType] = useState<'public' | 'pairwise'>('public')
  const [publicClient, setPublicClient] = useState(true)
  const [form, setForm] = useState({
    clientName: '',
    redirect: '',
    scope: 'openid profile email offline_access',
    grantTypes: 'authorization_code,refresh_token',
    responseTypes: 'code',
    postLogoutRedirects: '',
    frontchannelLogout: '',
    backchannelLogout: '',
  })
  const [resp, setResp] = useState<RegisterResp | null>(null)
  const [error, setError] = useState('')
  const [detail, setDetail] = useState<any | null>(null)
  const [saving, setSaving] = useState(false)
  const [mine, setMine] = useState<OwnedClient[]>([])

  useEffect(() => {
    if (typeof window !== 'undefined') {
      setForm((prev) => ({
        ...prev,
        redirect: `${window.location.origin}/cb`,
        clientName: '我的应用',
      }))
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
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const refreshMine = async () => {
    try {
      const list = await fetch('/api/my/clients', { credentials: 'include' }).then((r) => r.json())
      if (Array.isArray(list)) {
        setMine(list)
      } else {
        setMine([])
      }
    } catch {
      setMine([])
    }
  }

  const register = async () => {
    setError('')
    try {
      const { clientName, redirect, scope, grantTypes, responseTypes, postLogoutRedirects, frontchannelLogout, backchannelLogout } = form
      const redirectList = sanitizeList(redirect)
      if (!redirectList.length) {
        throw new Error('请至少填写一个 Redirect URI')
      }
      const invalidRedirect = redirectList.find((uri) => {
        try {
          const parsed = new URL(uri)
          return !/^https?:$/.test(parsed.protocol)
        } catch {
          return true
        }
      })
      if (invalidRedirect) {
        throw new Error(`Redirect URI 无效：${invalidRedirect}`)
      }
      const grants = sanitizeList(grantTypes)
      const responses = sanitizeList(responseTypes)
      if (!grants.length) {
        throw new Error('请至少选择一个 Grant Type')
      }
      if (!responses.length) {
        throw new Error('请至少选择一个 Response Type')
      }
      const postLogout = sanitizeList(postLogoutRedirects)
      const body = {
        client_name: clientName.trim() || '新客户端',
        redirect_uris: redirectList,
        grant_types: grants,
        response_types: responses,
        token_endpoint_auth_method: publicClient ? 'none' : 'client_secret_basic',
        scope: scope.trim() || 'openid',
        subject_type: subjectType,
        post_logout_redirect_uris: postLogout.length ? postLogout : undefined,
        frontchannel_logout_uri: frontchannelLogout.trim() || undefined,
        backchannel_logout_uri: backchannelLogout.trim() || undefined,
      }
      const data = await apiJSON<RegisterResp>('/register', body, {})
      setResp(data)
      if (typeof window !== 'undefined') {
        window.localStorage.setItem('ginkgo-client', JSON.stringify(data))
      }
      await refreshMine()
      setDetail(null)
      toast.success('注册成功，已保存凭据')
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
    const candidateRedirects = sanitizeList(form.redirect)
    const registeredRedirects = resp.redirect_uris || []
    const redirectForAuth = candidateRedirects[0] || registeredRedirects[0]
    if (!redirectForAuth) {
      setError('缺少 redirect_uri，请在表单中填写')
      return
    }
    try {
      const meta = await fetch(
        `${resp.registration_client_uri}&client_id=${encodeURIComponent(resp.client_id)}`,
        { headers: { Authorization: `Bearer ${resp.registration_access_token}` }, credentials: 'include' }
      ).then((r) => r.json())
      if (meta && meta.approved === false) {
        setError('当前客户端尚未批准，请联系管理员在后台通过审核。')
        return
      }
      if (meta && meta.enabled === false) {
        setError('当前客户端已被禁用，请先启用后再尝试授权。')
        return
      }
      if (Array.isArray(meta?.redirect_uris) && !meta.redirect_uris.includes(redirectForAuth)) {
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
        JSON.stringify({ client_id: resp.client_id, verifier, redirect_uri: redirectForAuth, publicClient })
      )
      const params = new URLSearchParams({
        response_type: 'code',
        client_id: resp.client_id,
        redirect_uri: redirectForAuth,
        scope: form.scope.trim() || 'openid',
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
    }).then((r) => r.json())
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
      toast.success('客户端信息已更新')
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
      toast.success('注册访问令牌已轮换')
    }
  }

  const deleteClient = async () => {
    if (!resp?.registration_client_uri || !resp.registration_access_token) return
    if (!window.confirm('确定要删除该客户端吗？')) return
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
      toast.success('客户端已删除')
    }
  }

  const handleUseForAuth = (client: OwnedClient) => {
    if (!client.approved) {
      toast.error('客户端尚未通过审批，无法直接发起授权')
      return
    }
    if (!client.enabled) {
      toast.error('客户端当前处于禁用状态，请先启用')
      return
    }
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
    toast.success('已加载客户端凭据，可直接发起授权测试')
  }

  const toggleEnabled = async (client: OwnedClient) => {
    if (!client.approved) {
      toast.error('客户端尚未审批通过，无法切换启用状态')
      return
    }
    const action = client.enabled ? 'disable' : 'enable'
    if (client.enabled && !window.confirm('确定要禁用该客户端吗？')) {
      return
    }
    const r = await fetch(`/api/my/clients/${encodeURIComponent(client.client_id)}/${action}`, {
      method: 'PUT',
      credentials: 'include',
    })
    if (r.status === 204) {
      toast.success(client.enabled ? '已禁用客户端' : '已启用客户端')
      await refreshMine()
    } else {
      toast.error('操作失败')
    }
  }

  const mineSorted = useMemo(() => {
    return [...mine]
      .map((item) => ({ ...item, enabled: item.enabled ?? item.approved }))
      .sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0))
  }, [mine])

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
                  <th className="text-left py-2">审批</th>
                  <th className="text-left py-2">启用</th>
                  <th className="text-left py-2">创建时间</th>
                  <th className="text-left py-2">操作</th>
                </tr>
              </thead>
              <tbody>
                {mineSorted.map((c) => (
                  <tr key={c.client_id} className="border-b border-border/60">
                    <td className="py-2 align-middle">{c.client_name || '-'}</td>
                    <td className="py-2 align-middle"><code className="text-xs break-all">{c.client_id}</code></td>
                    <td className="py-2 align-middle">{c.token_endpoint_auth_method === 'none' ? '公共' : '机密'}</td>
                    <td className="py-2 align-middle">{c.approved ? '已批准' : '待审批'}</td>
                    <td className="py-2 align-middle">{c.enabled ? '启用' : '禁用'}</td>
                    <td className="py-2 align-middle">{c.created_at ? new Date(c.created_at * 1000).toLocaleString() : '-'}</td>
                    <td className="py-2 align-middle space-x-2">
                      <Button variant="outline" onClick={() => handleUseForAuth(c)}>用于授权</Button>
                      <Button variant="ghost" onClick={() => navigator.clipboard.writeText(c.client_id)}>复制ID</Button>
                      <Button variant="outline" onClick={() => toggleEnabled(c)} disabled={!c.approved}>
                        {c.enabled ? '禁用' : '启用'}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {mineSorted.length === 0 && <div className="text-sm text-muted-foreground">暂无应用</div>}
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
          <Label>客户端名称</Label>
          <Input value={form.clientName} onChange={(e) => setForm((prev) => ({ ...prev, clientName: e.target.value }))} placeholder="我的应用" />
          <Label>Redirect URI 列表<Tooltip text="支持逗号或换行分隔的多个回调地址" /></Label>
          <Input value={form.redirect} onChange={(e) => setForm((prev) => ({ ...prev, redirect: e.target.value }))} placeholder="http://127.0.0.1:9999/cb" />
          <div className="text-sm text-slate-400">必须与 /authorize 请求中的 redirect_uri 完全一致；多个地址请以逗号或换行分隔。</div>
          <Label>Scope</Label>
          <Input value={form.scope} onChange={(e) => setForm((prev) => ({ ...prev, scope: e.target.value }))} placeholder="openid profile email" />
          <Label>Grant Types</Label>
          <Input value={form.grantTypes} onChange={(e) => setForm((prev) => ({ ...prev, grantTypes: e.target.value }))} placeholder="authorization_code,refresh_token" />
          <Label>Response Types</Label>
          <Input value={form.responseTypes} onChange={(e) => setForm((prev) => ({ ...prev, responseTypes: e.target.value }))} placeholder="code" />
          <Label>Post Logout Redirect URIs</Label>
          <Input value={form.postLogoutRedirects} onChange={(e) => setForm((prev) => ({ ...prev, postLogoutRedirects: e.target.value }))} placeholder="可选，逗号或换行分隔" />
          <Label>Frontchannel Logout URI</Label>
          <Input value={form.frontchannelLogout} onChange={(e) => setForm((prev) => ({ ...prev, frontchannelLogout: e.target.value }))} placeholder="https://example.com/logout/front" />
          <Label>Backchannel Logout URI</Label>
          <Input value={form.backchannelLogout} onChange={(e) => setForm((prev) => ({ ...prev, backchannelLogout: e.target.value }))} placeholder="https://example.com/logout/back" />
          <Label>Subject Type<Tooltip text="public：所有客户端使用相同 sub；pairwise：按 sector/domain 生成不同 sub" /></Label>
          <div className="flex items-center gap-3 text-sm">
            <label className="flex items-center gap-2"><input type="radio" checked={subjectType === 'public'} onChange={() => setSubjectType('public')} /> public</label>
            <label className="flex items-center gap-2"><input type="radio" checked={subjectType === 'pairwise'} onChange={() => setSubjectType('pairwise')} /> pairwise</label>
          </div>
          <Label>客户端类型<Tooltip text="公共客户端：配合 PKCE，token 端点无需 client_secret；机密客户端：需携带 client_secret" /></Label>
          <div className="flex items-center gap-3 text-sm">
            <label className="flex items-center gap-2"><input type="radio" checked={publicClient} onChange={() => setPublicClient(true)} /> 公共客户端</label>
            <label className="flex items-center gap-2"><input type="radio" checked={!publicClient} onChange={() => setPublicClient(false)} /> 机密客户端</label>
          </div>
          <div className="mt-2 flex justify-end">
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
              <div className="text-xs text-muted-foreground">发起授权前确保：客户端已批准并处于启用状态，redirect_uri 与注册一致，公共客户端需配合 PKCE。如遇 {`{"error":"unauthorized_client"}`} 多半是未审批通过或客户端被禁用。</div>
              <Button onClick={startAuth}>发起授权（Authorization Code + PKCE）</Button>
            </div>
          </CardContent>
        </Card>
      )}

      {resp && (
        <Card>
          <CardHeader>
            <CardTitle>客户端管理</CardTitle>
            <CardDescription>查询 / 修改 / 轮换 / 删除 已注册客户端</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 text-sm">
            <div className="flex items-center gap-2">
              <Button onClick={loadClient}>获取信息</Button>
              <Button onClick={rotateRAT} variant="outline">轮换 RAT</Button>
              <Button onClick={deleteClient} variant="destructive">删除客户端</Button>
            </div>
            {detail && (
              <div className="grid gap-3 max-w-3xl">
                <Label>client_name</Label>
                <Input value={detail.client_name || ''} onChange={(e) => setDetail({ ...detail, client_name: e.target.value })} />
                <Label>redirect_uris</Label>
                <Input
                  value={(detail.redirect_uris || []).join(', ')}
                  onChange={(e) =>
                    setDetail({
                      ...detail,
                      redirect_uris: e.target.value
                        .split(',')
                        .map((s: string) => s.trim())
                        .filter(Boolean),
                    })
                  }
                />
                <Label>post_logout_redirect_uris</Label>
                <Input
                  value={(detail.post_logout_redirect_uris || []).join(', ')}
                  onChange={(e) =>
                    setDetail({
                      ...detail,
                      post_logout_redirect_uris: e.target.value
                        .split(',')
                        .map((s: string) => s.trim())
                        .filter(Boolean),
                    })
                  }
                />
                <Label>frontchannel_logout_uri</Label>
                <Input value={detail.frontchannel_logout_uri || ''} onChange={(e) => setDetail({ ...detail, frontchannel_logout_uri: e.target.value })} />
                <Label>backchannel_logout_uri</Label>
                <Input value={detail.backchannel_logout_uri || ''} onChange={(e) => setDetail({ ...detail, backchannel_logout_uri: e.target.value })} />
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
