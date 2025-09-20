"use client";

import React, { useEffect, useState } from 'react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useAuth } from '@/lib/auth'
import { Button } from '@/components/ui/button'
import { getTheme, setTheme } from '@/lib/theme'
import type { ThemeMode } from '@/lib/theme'

export function SidebarLayout({ children }: { children: React.ReactNode }) {
  const { me } = useAuth()
  const [theme, setThemeState] = useState<ThemeMode>('system')
  useEffect(()=>{ setThemeState(getTheme()) },[])
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
  const items: { to: string; label: string; dev?: boolean; admin?: boolean; external?: boolean }[] = [
    { to: '/', label: '概览' },
    { to: '/profile', label: '个人资料' },
    { to: '/authorized', label: '授权应用' },
    { to: '/clients', label: '客户端', dev: true },
    { to: '/docs', label: '文档', dev: true, external: true },
    { to: '/admin/approvals', label: '客户端审批', admin: true },
    { to: '/admin/logs', label: '审计日志', admin: true },
    { to: '/admin/users', label: '用户管理', admin: true },
  ]

  return (
    <div className="min-h-screen grid grid-cols-12">
      <aside className="col-span-12 md:col-span-2 border-r border-border bg-background/60">
        <div className="h-14 flex items-center px-4 text-base font-semibold">GinkgoID</div>
        <nav className="px-2 py-2 space-y-1 text-sm">
          {items
            .filter(it => !it.admin || me?.is_admin)
            .filter(it => !it.dev || me?.is_admin || (me as any)?.is_dev)
            .map(it => {
              if (it.external) {
                return (
                  <a key={it.to} href={it.to} className="block rounded-md px-3 py-2 hover:bg-secondary" target="_self">
                    {it.label}
                  </a>
                )
              }
              const active = pathname === it.to || (pathname?.startsWith(it.to + '/') ?? false)
              return (
                <Link
                  key={it.to}
                  href={it.to}
                  className={`block rounded-md px-3 py-2 ${active ? 'bg-primary text-primary-foreground' : 'hover:bg-secondary'}`}
                >
                  {it.label}
                </Link>
              )
            })}
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
                <Button variant="ghost" onClick={async ()=>{ const back = window.location.pathname + window.location.search; await fetch('/logout', { credentials:'include' }); window.location.href = back || '/' }}>退出</Button>
              </>
            ) : (
              <a className="btn" href={`/login?next=${current}`}>登录</a>
            )}
          </div>
        </header>
        <main className="flex-1">{children}</main>
      </div>
    </div>
  )
}
