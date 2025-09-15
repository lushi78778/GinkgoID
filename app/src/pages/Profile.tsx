import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { zodResolver } from '@hookform/resolvers/zod'
import { Label } from '@/components/ui/label'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from '@/components/ui/card'
import { toast } from 'sonner'

type Me = { id: number; username: string; name: string; email: string; is_admin?: boolean }

export default function Profile() {
  const [me, setMe] = useState<Me | null>(null)
  const [msg, setMsg] = useState('')
  const schema = z.object({ name: z.string().min(1, '姓名必填'), email: z.string().email('邮箱格式不正确') })
  const { register, handleSubmit, reset, formState: { errors, isSubmitting } } = useForm<{name:string; email:string}>({ resolver: zodResolver(schema) })

  useEffect(() => {
    fetch('/api/me', { credentials: 'include' })
      .then(r => r.ok ? r.json() : Promise.reject(r))
      .then(d => { setMe(d); reset({ name: d.name || '', email: d.email || '' }) })
      .catch(() => setMsg('未登录，请先登录'))
  }, [])

  const onSubmit = async (data: {name:string; email:string}) => {
    const r = await fetch('/api/me', { method:'PUT', headers:{'Content-Type':'application/json'}, credentials:'include', body: JSON.stringify(data) })
    if (r.ok) { const d = await r.json(); setMe(d); toast.success('已保存') } else { const t = await r.text(); toast.error('保存失败: '+t) }
  }

  const changePwd = async () => {
    const oldPassword = (document.getElementById('oldpwd') as HTMLInputElement)?.value
    const newPassword = (document.getElementById('newpwd') as HTMLInputElement)?.value
    setMsg('')
    const r = await fetch('/api/me/password', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'include', body: JSON.stringify({ oldPassword, newPassword }) })
    if (r.status === 204) setMsg('口令已更新')
    else setMsg('更新失败')
  }

  if (!me) {
    return (
      <div className="container py-10">
        <div className="card">
          <h2 className="text-xl font-semibold">个人资料</h2>
          <p className="text-slate-400 mt-2">{msg || '加载中...'}</p>
          <div className="mt-3">
            <a className="btn" href={`/login?next=${encodeURIComponent('/app/profile')}`}>去登录</a>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="container py-10 space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>个人资料</CardTitle>
          <CardDescription>登录账户：{me.username} {me.is_admin ? '(管理员)' : ''}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="mt-2 grid gap-3 max-w-md">
            <Label>姓名</Label>
            <Input placeholder="姓名" {...register('name')} />
            {errors.name && <p className="text-red-500 text-xs">{errors.name.message}</p>}
            <Label className="mt-2">邮箱</Label>
            <Input placeholder="邮箱" {...register('email')} />
            {errors.email && <p className="text-red-500 text-xs">{errors.email.message}</p>}
            <div className="mt-3 flex justify-end">
              <Button type="submit" disabled={isSubmitting}>{isSubmitting? '保存中...' : '保存'}</Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card className="max-w-md">
        <CardHeader>
          <CardTitle>修改口令</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3">
            <Label>旧口令</Label>
            <Input id="oldpwd" type="password" placeholder="旧口令" />
            <Label>新口令</Label>
            <Input id="newpwd" type="password" placeholder="新口令 (>=6位)" />
            <div className="mt-2 flex justify-end"><Button onClick={changePwd}>更新</Button></div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
