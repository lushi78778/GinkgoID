import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog'
import { Switch } from '@/components/ui/switch'
import { toast } from 'sonner'
import { useEffect, useState } from 'react'

type User = { id: number; username: string; name?: string; email?: string; is_admin?: boolean; is_dev?: boolean }

export default function AdminUsers() {
  const [meAdmin, setMeAdmin] = useState<boolean>(false)
  const [users, setUsers] = useState<User[]>([])
  const [open, setOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ username:'', password:'', email:'', name:'', is_admin:false, is_dev:false })

  const load = async () => {
    const me = await fetch('/api/me', { credentials:'include' }).then(r=>r.json()).catch(()=>null)
    if (!me?.is_admin) { setMeAdmin(false); return }
    setMeAdmin(true)
    const list = await fetch('/api/users', { credentials:'include' }).then(r=>r.json()).catch(()=>[])
    setUsers(list)
  }

  useEffect(() => { load() }, [])

  const create = async () => {
    setCreating(true)
    const r = await fetch('/api/users', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'include', body: JSON.stringify(form) })
    setCreating(false)
    if (r.ok) {
      toast.success('创建成功')
      setForm({ username:'', password:'', email:'', name:'', is_admin:false, is_dev:false })
      setOpen(false)
      await load()
    } else {
      const t = await r.text(); toast.error('创建失败: '+t)
    }
  }

  const toggleAdmin = async (u: User) => {
    const r = await fetch(`/api/users/${u.id}`, { method:'PUT', headers:{'Content-Type':'application/json'}, credentials:'include', body: JSON.stringify({ is_admin: !u.is_admin }) })
    if (r.ok) { toast.success('已更新'); await load() } else { toast.error('操作失败') }
  }

  const toggleDev = async (u: User) => {
    const r = await fetch(`/api/users/${u.id}`, { method:'PUT', headers:{'Content-Type':'application/json'}, credentials:'include', body: JSON.stringify({ is_dev: !u.is_dev }) })
    if (r.ok) { toast.success('已更新'); await load() } else { toast.error('操作失败') }
  }

  if (!meAdmin) {
    return (
      <div className="container py-10">
        <div className="card">
          <h2 className="text-xl font-semibold">用户管理</h2>
          <p className="text-slate-400 mt-2">需要管理员权限</p>
          <div className="mt-3">
            <a className="btn" href={`/login?next=${encodeURIComponent('/app/admin/users')}`}>管理员登录</a>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="container py-10 space-y-6">
      <div className="card">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-semibold">用户列表</h2>
          <Dialog open={open} onOpenChange={setOpen}>
            <DialogTrigger asChild>
              <Button>创建用户</Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>创建用户</DialogTitle>
              </DialogHeader>
              <div className="grid gap-3">
                <div>
                  <Label>用户名</Label>
                  <Input value={form.username} onChange={e=>setForm({...form, username:e.target.value})} />
                </div>
                <div>
                  <Label>口令</Label>
                  <Input type="password" value={form.password} onChange={e=>setForm({...form, password:e.target.value})} />
                </div>
                <div>
                  <Label>邮箱</Label>
                  <Input value={form.email} onChange={e=>setForm({...form, email:e.target.value})} />
                </div>
                <div>
                  <Label>姓名</Label>
                  <Input value={form.name} onChange={e=>setForm({...form, name:e.target.value})} />
                </div>
                <div className="flex items-center justify-between">
                  <Label>管理员</Label>
                  <Switch checked={form.is_admin} onCheckedChange={v=>setForm({...form, is_admin: v})} />
                </div>
                <div className="flex items-center justify-between">
                  <Label>开发者</Label>
                  <Switch checked={form.is_dev} onCheckedChange={v=>setForm({...form, is_dev: v})} />
                </div>
                <div className="flex justify-end gap-3 mt-2">
                  <Button onClick={create} disabled={creating}>{creating? '创建中...' : '创建'}</Button>
                </div>
              </div>
            </DialogContent>
          </Dialog>
        </div>
        <div className="overflow-x-auto mt-4">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>用户名</TableHead>
                <TableHead>姓名</TableHead>
                <TableHead>邮箱</TableHead>
                <TableHead>管理员</TableHead>
                <TableHead>开发者</TableHead>
                <TableHead>操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map(u => (
                <TableRow key={u.id}>
                  <TableCell>{u.id}</TableCell>
                  <TableCell>{u.username}</TableCell>
                  <TableCell>{u.name}</TableCell>
                  <TableCell>{u.email}</TableCell>
                  <TableCell>{u.is_admin ? '是' : '否'}</TableCell>
                  <TableCell>{u.is_dev ? '是' : '否'}</TableCell>
                  <TableCell className="space-x-2">
                    <Button onClick={()=>toggleAdmin(u)} variant={u.is_admin ? 'destructive' : 'default'}>
                      {u.is_admin ? '取消管理员' : '设为管理员'}
                    </Button>
                    <Button onClick={()=>toggleDev(u)} variant={u.is_dev ? 'destructive' : 'outline'}>
                      {u.is_dev ? '取消开发者' : '设为开发者'}
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
    </div>
  )
}
