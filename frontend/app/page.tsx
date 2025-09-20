"use client";

import Link from 'next/link'
import { useAuth } from '@/lib/auth'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'

export default function Dashboard() {
  const { me } = useAuth()
  return (
    <div className="container py-10 space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>欢迎使用 GinkgoID 控制台</CardTitle>
          <CardDescription>在这里管理您的个人资料与管理员功能</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 text-sm">
          {me ? (
            <>
              <div>当前用户：<b>{me.username}</b> {me.is_admin ? <span className="text-emerald-400">(管理员)</span> : null}</div>
              <div>姓名：{me.name || '-'}</div>
              <div>邮箱：{me.email || '-'}</div>
            </>
          ) : (
            <div>未登录，请先登录。</div>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>快速入口</CardTitle>
        </CardHeader>
        <CardContent className="grid md:grid-cols-3 gap-3 text-sm">
          <Link className="btn" href="/profile">个人资料</Link>
          {me?.is_admin && <Link className="btn" href="/admin/users">用户管理</Link>}
          <a className="btn" href="/docs">API 文档</a>
        </CardContent>
      </Card>
    </div>
  )
}
