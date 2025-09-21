"use client";

import { useCallback, useEffect, useState } from 'react'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { DataTable } from '@/components/ui/data-table'
import type { ColumnDef } from '@tanstack/react-table'

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

  const fetchLogs = useCallback(async () => {
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
  }, [level, event, user, client, requestId, outcome, errorCode, method, path, ua, status])

  useEffect(()=>{ fetchLogs() },[fetchLogs])

  const columns: ColumnDef<LogItem>[] = [
    { header: '时间', accessorKey: 'ts', cell: ({ getValue }) => new Date((getValue<number>()||0)*1000).toLocaleString() },
    { header: '级别', accessorKey: 'level' },
    { header: '事件', accessorKey: 'event' },
    { header: 'request_id', accessorKey: 'request_id', cell: ({ row }) => row.original.request_id ? (
      <button
        className="underline text-blue-600 hover:text-blue-800"
        onClick={()=> navigator.clipboard.writeText(row.original.request_id!)}
        title="点击复制"
      >{row.original.request_id}</button>
    ) : '' },
    { header: 'outcome', accessorKey: 'outcome' },
    { header: 'error_code', accessorKey: 'error_code' },
    { header: 'method', accessorKey: 'method' },
    { header: 'path', accessorKey: 'path', cell: ({ row }) => (
      <span className="max-w-[260px] truncate inline-block" title={row.original.path}>{row.original.path ?? ''}</span>
    ) },
    { header: 'status', accessorKey: 'status' },
    { header: 'UA', accessorKey: 'ua', cell: ({ row }) => (
      <span className="max-w-[260px] truncate inline-block" title={row.original.ua}>{row.original.ua ?? ''}</span>
    ) },
    { header: '用户', accessorKey: 'user_id' },
    { header: '客户端', accessorKey: 'client_id' },
    { header: '描述', accessorKey: 'desc', cell: ({ row }) => (
      <span className="max-w-[320px] truncate inline-block" title={row.original.desc}>{row.original.desc}</span>
    ) },
    { header: 'Extra', accessorKey: 'extra', cell: ({ row }) => {
      const it = row.original
      try {
        const e = typeof it.extra === 'string' ? JSON.parse(it.extra) : it.extra
        const req = e?.required ? `req:${Array.isArray(e.required)?e.required.join('|'):e.required}`:''
        const sac = e?.session_acr?`acr:${e.session_acr}`:''
        const min = e?.min_acr?`min:${e.min_acr}`:''
        const parts = [req,sac,min].filter(Boolean)
        const text = parts.length? parts.join(' '): ''
        return <span className="max-w-[320px] text-xs text-slate-400 truncate inline-block" title={JSON.stringify(it.extra)}>{text}</span>
      } catch { return <span className="text-xs text-slate-400"></span> }
    } },
    { header: 'IP', accessorKey: 'ip' },
  ]

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
      <DataTable<LogItem>
        columns={columns}
        data={items}
        rowKey={(r, i)=> `${r.ts}-${i}`}
        searchable
        searchPlaceholder="搜索事件/路径/UA/描述"
      />
    </Card>
  )
}
