import { useEffect, useState } from 'react'
import { Card } from '@/components/ui/card'
import { Table } from '@/components/ui/table'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'

interface LogItem {
  ts: number
  level: string
  event: string
  user_id?: number
  client_id?: string
  desc: string
  ip: string
  request_id?: string
  session_id?: string
  method?: string
  path?: string
  status?: number
  ua?: string
  outcome?: string
  error_code?: string
  extra?: any
}

export default function AdminLogs() {
  const [items, setItems] = useState<LogItem[]>([])
  const [level, setLevel] = useState('')
  const [event, setEvent] = useState('')
  const [user, setUser] = useState('')
  const [client, setClient] = useState('')
  const [requestId, setRequestId] = useState('')
  const [outcome, setOutcome] = useState('')
  const [errorCode, setErrorCode] = useState('')
  const [method, setMethod] = useState('')
  const [path, setPath] = useState('')
  const [ua, setUa] = useState('')
  const [status, setStatus] = useState('')

  const fetchLogs = async () => {
    const qs = new URLSearchParams()
    if (level) qs.set('level', level)
    if (event) qs.set('event', event)
    if (user) qs.set('user', user)
    if (client) qs.set('client', client)
    if (requestId) qs.set('request_id', requestId)
    if (outcome) qs.set('outcome', outcome)
    if (errorCode) qs.set('error_code', errorCode)
    if (method) qs.set('method', method)
    if (path) qs.set('path', path)
    if (ua) qs.set('ua', ua)
    if (status) qs.set('status', status)
    const res = await fetch(`/api/logs?${qs.toString()}`, { credentials: 'include' })
    if (!res.ok) { alert('加载失败'); return }
    const data = await res.json()
    setItems(data)
  }

  useEffect(()=>{ fetchLogs() },[])

  return (
    <Card className="w-full max-w-5xl mx-auto mt-8 p-4">
      <h2 className="text-xl font-bold mb-4">审计日志</h2>
      <div className="flex flex-wrap gap-2 mb-3">
        <Input placeholder="级别" value={level} onChange={e=>setLevel(e.target.value)} className="w-28"/>
        <Input placeholder="事件" value={event} onChange={e=>setEvent(e.target.value)} className="w-44"/>
        <Input placeholder="用户ID" value={user} onChange={e=>setUser(e.target.value)} className="w-28"/>
        <Input placeholder="客户端ID" value={client} onChange={e=>setClient(e.target.value)} className="w-44"/>
        <Input placeholder="request_id" value={requestId} onChange={e=>setRequestId(e.target.value)} className="w-48"/>
        <Input placeholder="outcome" value={outcome} onChange={e=>setOutcome(e.target.value)} className="w-32"/>
        <Input placeholder="error_code" value={errorCode} onChange={e=>setErrorCode(e.target.value)} className="w-40"/>
        <Input placeholder="method" value={method} onChange={e=>setMethod(e.target.value)} className="w-24"/>
        <Input placeholder="path" value={path} onChange={e=>setPath(e.target.value)} className="w-56"/>
  <Input placeholder="UA" value={ua} onChange={e=>setUa(e.target.value)} className="w-64"/>
        <Input placeholder="status" value={status} onChange={e=>setStatus(e.target.value)} className="w-24"/>
        <Button onClick={fetchLogs}>查询</Button>
      </div>
      <Table>
        <thead>
          <tr>
            <th>时间</th>
            <th>级别</th>
            <th>事件</th>
            <th>request_id</th>
            <th>outcome</th>
            <th>error_code</th>
            <th>method</th>
            <th>path</th>
            <th>status</th>
            <th>UA</th>
            <th>用户</th>
            <th>客户端</th>
            <th>描述</th>
            <th>Extra</th>
            <th>IP</th>
          </tr>
        </thead>
        <tbody>
          {items.map((it, idx)=> (
            <tr key={idx}>
              <td>{new Date(it.ts * 1000).toLocaleString()}</td>
              <td>{it.level}</td>
              <td>{it.event}</td>
              <td>
                {it.request_id ? (
                  <button
                    className="underline text-blue-600 hover:text-blue-800"
                    onClick={()=> navigator.clipboard.writeText(it.request_id!)}
                    title="点击复制"
                  >{it.request_id}</button>
                ) : ''}
              </td>
              <td>{it.outcome ?? ''}</td>
              <td>{it.error_code ?? ''}</td>
              <td>{it.method ?? ''}</td>
              <td className="max-w-[260px] truncate" title={it.path}>{it.path ?? ''}</td>
              <td>{it.status ?? ''}</td>
              <td className="max-w-[260px] truncate" title={it.ua}>{it.ua ?? ''}</td>
              <td>{it.user_id ?? ''}</td>
              <td>{it.client_id ?? ''}</td>
              <td className="max-w-[320px] truncate" title={it.desc}>{it.desc}</td>
              <td className="max-w-[320px] text-xs text-slate-400 truncate" title={JSON.stringify(it.extra)}>
                {it.extra ? (()=>{
                  try {
                    const e = typeof it.extra === 'string' ? JSON.parse(it.extra) : it.extra
                    const req = e.required ? `req:${Array.isArray(e.required)?e.required.join('|'):e.required}`:''
                    const sac = e.session_acr?`acr:${e.session_acr}`:''
                    const min = e.min_acr?`min:${e.min_acr}`:''
                    const parts = [req,sac,min].filter(Boolean)
                    return parts.length? parts.join(' '): ''
                  } catch { return '' }
                })():''}
              </td>
              <td>{it.ip}</td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  )
}
