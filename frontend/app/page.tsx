"use client";

import { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { useAuth } from '@/lib/auth'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'

type Consent = { client_id: string; client_name?: string; scope?: string; created_at?: number }

export default function Dashboard() {
  const { me, loading } = useAuth()
  const [consents, setConsents] = useState<Consent[]>([])
  const [consentLoading, setConsentLoading] = useState(false)

  useEffect(() => {
    let aborted = false
    const load = async () => {
      if (!me) {
        setConsents([])
        return
      }
      setConsentLoading(true)
      try {
        const res = await fetch('/api/consents', { credentials: 'include' })
        if (!res.ok) return
        const data = await res.json()
        if (!aborted && Array.isArray(data)) {
          setConsents(data)
        }
      } finally {
        if (!aborted) setConsentLoading(false)
      }
    }
    load()
    return () => { aborted = true }
  }, [me])

  const sortedConsents = useMemo(() => {
    return [...consents].sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0))
  }, [consents])

  const roleChips = useMemo(() => {
    if (!me) return [] as string[]
    const chips: string[] = ['用户']
    if (me.is_dev) chips.push('开发者')
    if (me.is_admin) chips.push('管理员')
    return chips
  }, [me])

  const quickLinks = useMemo(() => {
    if (!me) {
      return [
        { label: '前往登录', href: '/login?next=%2F', external: false },
        { label: '了解 OIDC', href: '/docs', external: false },
      ]
    }
    const links: { label: string; href: string; external?: boolean }[] = [
      { label: '个人资料', href: '/profile' },
      { label: '安全中心', href: '/security' },
      { label: '安全日志', href: '/logs' },
      { label: '隐私与数据', href: '/privacy' },
      { label: '授权应用', href: '/authorized' },
    ]
    if (me.is_dev) {
      links.push({ label: '客户端注册', href: '/clients' })
      links.push({ label: '应用日志', href: '/clients/logs' })
      links.push({ label: '授权用户', href: '/clients/users' })
      links.push({ label: '应用分析', href: '/clients/analytics' })
      links.push({ label: '平台状态', href: '/status' })
    }
    links.push({ label: 'OIDC 文档', href: '/docs' })
    if (me.is_admin) {
      links.push({ label: '全局仪表盘', href: '/admin/dashboard' })
      links.push({ label: '系统策略', href: '/admin/settings' })
      links.push({ label: '品牌定制', href: '/admin/branding' })
    }
    return links
  }, [me])

  return (
    <div className="container py-10 space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>欢迎使用 GinkgoID 控制台</CardTitle>
          <CardDescription>集中管理个人资料、授权记录与平台功能</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 text-sm">
          {loading ? (
            <span className="text-muted-foreground">加载中...</span>
          ) : me ? (
            <>
              <div className="grid gap-2 md:grid-cols-2">
                <InfoRow label="用户名" value={me.username} bold />
                <InfoRow label="用户 ID" value={String(me.id)} mono />
                <InfoRow label="姓名" value={me.name || '-'} />
                <InfoRow label="邮箱" value={me.email || '-'} />
              </div>
              <div className="flex flex-wrap gap-2">
                {roleChips.map((chip) => (
                  <span
                    key={chip}
                    className="rounded-full bg-emerald-500/10 px-3 py-1 text-xs font-semibold text-emerald-600 dark:text-emerald-300"
                  >
                    {chip}
                  </span>
                ))}
              </div>
            </>
          ) : (
            <div className="flex flex-col gap-3">
              <span>尚未登录，请先完成身份认证。</span>
              <a className="btn w-fit" href="/login?next=%2F">立即登录</a>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>快速入口</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 text-sm md:grid-cols-3">
          {quickLinks.map((link) => (
            link.external ? (
              <a key={link.label} className="btn" href={link.href} target="_self">
                {link.label}
              </a>
            ) : (
              <Link key={link.label} className="btn" href={link.href}>
                {link.label}
              </Link>
            )
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex items-center justify-between">
          <div>
            <CardTitle>最近授权的应用</CardTitle>
            <CardDescription>展示最近授权的客户端，方便快速管理</CardDescription>
          </div>
          <Button variant="outline" size="sm" asChild>
            <Link href="/authorized">查看全部</Link>
          </Button>
        </CardHeader>
        <CardContent>
          {consentLoading ? (
            <div className="py-6 text-sm text-muted-foreground">正在加载授权信息...</div>
          ) : sortedConsents.length ? (
            <div className="grid gap-3 md:grid-cols-2">
              {sortedConsents.slice(0, 6).map((item) => (
                <Link
                  key={item.client_id}
                  href={`/clients?focus=${encodeURIComponent(item.client_id)}`}
                  className="rounded-xl border border-border/60 bg-background/80 p-4 transition hover:border-primary/60 hover:shadow-sm"
                >
                  <div className="text-sm font-semibold text-foreground">
                    {item.client_name || item.client_id}
                  </div>
                  <div className="mt-2 text-xs text-muted-foreground">
                    授权时间：{item.created_at ? new Date(item.created_at * 1000).toLocaleString() : '未知'}
                  </div>
                  {item.scope && (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {item.scope.split(/\s+/).filter(Boolean).map((scope) => (
                        <span key={scope} className="rounded-full bg-primary/10 px-2 py-1 text-[11px] text-primary">
                          {scope}
                        </span>
                      ))}
                    </div>
                  )}
                </Link>
              ))}
            </div>
          ) : (
            <div className="py-6 text-sm text-muted-foreground">暂无授权记录，完成授权后将展示在此处。</div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

function InfoRow({ label, value, bold, mono }: { label: string; value: string; bold?: boolean; mono?: boolean }) {
  return (
    <div className="flex flex-col">
      <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
      <span className={`${bold ? 'font-semibold' : ''} ${mono ? 'font-mono text-[13px]' : ''}`}>{value}</span>
    </div>
  )
}
