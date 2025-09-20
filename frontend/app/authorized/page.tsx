"use client";

import { useEffect, useMemo, useState } from 'react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Button } from '@/components/ui/button'
import { toast } from 'sonner'
import { confirm } from '@/components/ui/confirm'

type Consent = { client_id: string; client_name: string; scope: string; created_at: number }

export default function AuthorizedApps() {
  const [list, setList] = useState<Consent[]>([])
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const r = await fetch('/api/consents', { credentials:'include' })
      if (r.ok) {
        const data = await r.json()
        setList(Array.isArray(data) ? data : [])
      }
    } finally {
      setLoading(false)
    }
  }

  useEffect(()=>{ load() }, [])

  const sorted = useMemo(() => [...list].sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0)), [list])

  const revoke = async (cid: string) => {
    const ok = await confirm({ title: '撤销授权', content: `确定要移除客户端 ${cid} 的授权吗？` })
    if (!ok) return
    const r = await fetch(`/api/consents/${cid}`, { method:'DELETE', credentials:'include' })
    if (r.status === 204) { toast.success('已撤销授权'); await load() } else { toast.error('撤销失败') }
  }

  return (
    <div className="container py-10">
      <Card>
        <CardHeader>
          <CardTitle>已授权的应用</CardTitle>
          <CardDescription>你已授权访问的客户端列表</CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="py-8 text-sm text-muted-foreground">正在加载授权数据...</div>
          ) : sorted.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>名称</TableHead>
                  <TableHead>Client ID</TableHead>
                  <TableHead>Scope</TableHead>
                  <TableHead>授权时间</TableHead>
                  <TableHead>操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sorted.map(it => (
                  <TableRow key={it.client_id}>
                    <TableCell className="font-medium text-foreground">{it.client_name || '-'}</TableCell>
                    <TableCell className="font-mono text-xs">{it.client_id}</TableCell>
                    <TableCell>
                      {it.scope ? (
                        <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                          {it.scope.split(/\s+/).filter(Boolean).map(scope => (
                            <span key={scope} className="rounded-md bg-secondary px-2 py-1">
                              {scope}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell>{it.created_at ? new Date(it.created_at*1000).toLocaleString() : '-'}</TableCell>
                    <TableCell>
                      <Button variant="destructive" onClick={()=>revoke(it.client_id)}>撤销授权</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="py-8 text-sm text-muted-foreground">暂无授权记录。</div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
