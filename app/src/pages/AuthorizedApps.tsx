import { useEffect, useState } from 'react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Button } from '@/components/ui/button'
import { toast } from 'sonner'

type Consent = { client_id: string; client_name: string; scope: string; created_at: number }

export default function AuthorizedApps() {
  const [list, setList] = useState<Consent[]>([])
  const load = async () => {
    const r = await fetch('/api/consents', { credentials:'include' })
    if (r.ok) setList(await r.json())
  }
  useEffect(()=>{ load() }, [])

  const revoke = async (cid: string) => {
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
              {list.map(it => (
                <TableRow key={it.client_id}>
                  <TableCell>{it.client_name || '-'}</TableCell>
                  <TableCell>{it.client_id}</TableCell>
                  <TableCell>{it.scope}</TableCell>
                  <TableCell>{new Date(it.created_at*1000).toLocaleString()}</TableCell>
                  <TableCell><Button variant="destructive" onClick={()=>revoke(it.client_id)}>撤销授权</Button></TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}

