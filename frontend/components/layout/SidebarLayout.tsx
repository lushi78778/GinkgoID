"use client";

import React, { useEffect, useMemo, useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useAuth } from '@/lib/auth'
import { Button } from '@/components/ui/button'
import { getTheme, setTheme } from '@/lib/theme'
import type { ThemeMode } from '@/lib/theme'

type NavItem = {
  section: string
  label: string
  to?: string
  dev?: boolean
  admin?: boolean
  external?: boolean
}

const navItems: NavItem[] = [
  { section: '我的账户', label: '概览', to: '/' },
  { section: '我的账户', label: '个人资料', to: '/profile' },
  { section: '我的账户', label: '安全中心', to: '/security' },
  { section: '我的账户', label: '安全日志', to: '/logs' },
  { section: '我的账户', label: '隐私与数据', to: '/privacy' },
  { section: '我的账户', label: '授权应用', to: '/authorized' },
  { section: '开发者', label: '客户端注册', to: '/clients', dev: true },
  { section: '开发者', label: '应用日志', to: '/clients/logs', dev: true },
  { section: '开发者', label: '授权用户', to: '/clients/users', dev: true },
  { section: '开发者', label: '应用分析', to: '/clients/analytics', dev: true },
  { section: '开发者', label: '平台状态', to: '/status', dev: true },
  { section: '开发者', label: 'OIDC 文档', to: '/docs', dev: true },
  { section: '管理员', label: '全局仪表盘', to: '/admin/dashboard', admin: true },
  { section: '管理员', label: '用户管理', to: '/admin/users', admin: true },
  { section: '管理员', label: '客户端审批', to: '/admin/approvals', admin: true },
  { section: '管理员', label: '审计日志', to: '/admin/logs', admin: true },
  { section: '管理员', label: '系统策略', to: '/admin/settings', admin: true },
  { section: '管理员', label: '品牌定制', to: '/admin/branding', admin: true },
]

export function SidebarLayout({ children }: { children: React.ReactNode }) {
  const { me } = useAuth()
  const [theme, setThemeState] = useState<ThemeMode>('system')
  useEffect(() => {
    setThemeState(getTheme())
  }, [])
  const cycleTheme = () => {
    const next: ThemeMode = theme === 'light' ? 'dark' : theme === 'dark' ? 'system' : 'light'
    setTheme(next)
    setThemeState(next)
  }
  const pathname = usePathname()
  const [current, setCurrent] = useState('')
  useEffect(() => {
    if (typeof window !== 'undefined') {
      setCurrent(encodeURIComponent(window.location.pathname + window.location.search))
    }
  }, [])

  const groupedItems = useMemo(() => {
    const allowed = navItems.filter((item) => {
      if (item.admin && !me?.is_admin) return false
      if (item.dev && !(me?.is_admin || (me as any)?.is_dev)) return false
      return true
    })
    const map = new Map<string, NavItem[]>()
    for (const item of allowed) {
      if (!map.has(item.section)) map.set(item.section, [])
      map.get(item.section)!.push(item)
    }
    return Array.from(map.entries())
  }, [me])

  return (
    <div className="min-h-screen grid grid-cols-12">
      <aside className="col-span-12 md:col-span-2 border-r border-border bg-background/60">
        <div className="h-14 flex items-center px-4 text-base font-semibold">GinkgoID</div>
        <nav className="px-3 py-3 space-y-4 text-sm">
          {groupedItems.map(([section, items]) => (
            <div key={section} className="space-y-2">
              <div className="px-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground/80">
                {section}
              </div>
              <div className="space-y-1">
                {items.map((item) => {
                  if (!item.to) {
                    return (
                      <div key={item.label} className="px-3 py-2 text-muted-foreground/80">
                        {item.label}
                      </div>
                    )
                  }
                  const active = pathname === item.to || (pathname?.startsWith(item.to + '/') ?? false)
                  if (item.external) {
                    return (
                      <a
                        key={item.to}
                        href={item.to}
                        className="block rounded-md px-3 py-2 hover:bg-secondary"
                        target="_blank"
                        rel="noreferrer"
                      >
                        {item.label}
                      </a>
                    )
                  }
                  return (
                    <Link
                      key={item.to}
                      href={item.to}
                      className={`block rounded-md px-3 py-2 ${
                        active ? 'bg-primary text-primary-foreground' : 'hover:bg-secondary'
                      }`}
                    >
                      {item.label}
                    </Link>
                  )
                })}
              </div>
            </div>
          ))}
        </nav>
      </aside>
      <div className="col-span-12 md:col-span-10 flex flex-col">
        <header className="h-14 border-b border-border flex items-center justify-between px-4 bg-background/60 backdrop-blur">
          <div className="text-sm text-muted-foreground">{`${me ? (me.is_admin ? '管理员' : '用户') : ''} 控制台`}</div>
          <div className="flex items-center gap-3">
            <Button variant="outline" onClick={cycleTheme} title={`主题：${theme}`}>
              {theme === 'dark' ? '深色' : theme === 'light' ? '浅色' : '跟随系统'}
            </Button>
            {me ? (
              <>
                <span className="text-sm text-muted-foreground">{me.username}</span>
                <Button
                  variant="ghost"
                  onClick={async () => {
                    const back = window.location.pathname + window.location.search
                    await fetch('/logout', { credentials: 'include' })
                    window.location.href = back || '/'
                  }}
                >
                  退出
                </Button>
              </>
            ) : (
              <a className="btn" href={`/login?next=${current}`}>
                登录
              </a>
            )}
          </div>
        </header>
        <main className="flex-1">{children}</main>
      </div>
    </div>
  )
}
