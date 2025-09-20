"use client";

import { useCallback, useEffect, useMemo, useState } from 'react'
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

interface HealthResponse {
  status?: string
  [key: string]: any
}

export default function PlatformStatus() {
  const [data, setData] = useState<HealthResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [latency, setLatency] = useState<number | null>(null)
  const [checkedAt, setCheckedAt] = useState<number | null>(null)
  const [metrics, setMetrics] = useState<string | null>(null)
  const [metricsError, setMetricsError] = useState<string | null>(null)
  const [metricsCheckedAt, setMetricsCheckedAt] = useState<number | null>(null)
  const [loading, setLoading] = useState(false)
  const [metricsFilter, setMetricsFilter] = useState('')

  const runCheck = useCallback(async () => {
    setLoading(true)
    setError(null)
    setMetricsError(null)
    setMetrics(null)
    try {
      const started = performance.now()
      const res = await fetch('/healthz', { credentials: 'include' })
      const elapsed = performance.now() - started
      setLatency(elapsed)
      setCheckedAt(Date.now())
      if (!res.ok) {
        setError(`健康检查接口返回 ${res.status}`)
        setData(null)
        setMetricsError('健康检查失败，未尝试读取指标')
        return
      }
      const json = await res.json()
      setData(json)

      try {
        const metricsRes = await fetch('/metrics', { credentials: 'include' })
        setMetricsCheckedAt(Date.now())
        if (!metricsRes.ok) {
          setMetricsError(`指标接口返回 ${metricsRes.status}`)
          setMetrics(null)
        } else {
          const text = await metricsRes.text()
          setMetrics(text)
        }
      } catch (err: any) {
        setMetricsError(err?.message || '无法获取指标数据')
        setMetrics(null)
      }
    } catch (e: any) {
      setError(e?.message || '无法连接到健康检查接口')
      setData(null)
      setMetricsError('健康检查失败，未尝试读取指标')
      setMetrics(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { runCheck() }, [runCheck])

  const statusColor = useMemo(() => {
    if (error) return 'bg-rose-500'
    if (data?.status && data.status.toLowerCase() !== 'ok') return 'bg-amber-500'
    return 'bg-emerald-500'
  }, [data?.status, error])

  const statusText = error ? '不可用' : (data?.status?.toUpperCase() || 'UNKNOWN')

  const metricsSummary = useMemo(() => {
    if (!metrics) return '-'
    const lines = metrics.split('\n')
    const series = lines.filter((line) => line && !line.startsWith('#'))
    return `${series.length} 条样本`
  }, [metrics])

  const structuredMetrics = useMemo(() => {
    if (!metrics) return [] as MetricEntry[]
    return parsePrometheus(metrics)
  }, [metrics])

  const filteredMetrics = useMemo(() => {
    const q = metricsFilter.trim().toLowerCase()
    if (!q) return structuredMetrics
    return structuredMetrics.filter((entry) => {
      if (entry.name.toLowerCase().includes(q)) return true
      if (entry.help?.toLowerCase().includes(q)) return true
      return entry.samples.some((sample) =>
        Object.entries(sample.labels)
          .some(([k, v]) => `${k}=${v}`.toLowerCase().includes(q))
      )
    })
  }, [metricsFilter, structuredMetrics])

  const copyMetrics = async () => {
    if (!metrics) return
    try {
      await navigator.clipboard.writeText(metrics)
      alert('指标内容已复制到剪贴板')
    } catch {
      alert('复制失败，请手动复制')
    }
  }

  return (
    <div className="container py-10">
      <Card className="max-w-3xl">
        <CardHeader>
          <CardTitle>平台状态</CardTitle>
          <CardDescription>调用后端 /healthz 接口获取核心服务运行情况</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="flex items-center gap-3">
            <span className={`h-3 w-3 rounded-full ${statusColor}`} aria-hidden />
            <span className="text-lg font-semibold text-foreground">{statusText}</span>
            <Button variant="outline" size="sm" onClick={runCheck} disabled={loading}>
              {loading ? '检测中...' : '重新检测'}
            </Button>
          </div>

          <div className="grid gap-4 rounded-xl border border-border/60 bg-background/80 p-4 text-sm text-muted-foreground md:grid-cols-3">
            <InfoBlock label="最近检测时间" value={checkedAt ? new Date(checkedAt).toLocaleString() : '尚未检测'} />
            <InfoBlock label="响应耗时" value={latency !== null ? `${latency.toFixed(1)} ms` : '-'} />
            <InfoBlock label="健康响应字段" value={data ? Object.keys(data).join(', ') || '-' : '-'} />
          </div>

          <div>
            <h3 className="text-sm font-semibold text-foreground">原始响应</h3>
            <pre className="mt-2 max-h-64 overflow-auto rounded-lg bg-slate-950/90 p-4 text-xs text-slate-200 dark:bg-slate-900">
              {JSON.stringify(error ? { error } : (data || {}), null, 2)}
            </pre>
          </div>

          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <h3 className="text-sm font-semibold text-foreground">Prometheus 指标 (/metrics)</h3>
              <Button variant="outline" size="sm" onClick={copyMetrics} disabled={!metrics}>
                复制全部
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  const blob = new Blob([metrics ?? metricsError ?? ''], { type: 'text/plain;charset=utf-8' })
                  const url = URL.createObjectURL(blob)
                  const link = document.createElement('a')
                  link.href = url
                  link.download = 'metrics.txt'
                  document.body.appendChild(link)
                  link.click()
                  document.body.removeChild(link)
                  URL.revokeObjectURL(url)
                }}
                disabled={!metrics && !metricsError}
              >
                下载文本
              </Button>
            </div>
            <div className="grid gap-4 rounded-xl border border-border/60 bg-background/80 p-4 text-sm text-muted-foreground md:grid-cols-3">
              <InfoBlock label="指标刷新时间" value={metricsCheckedAt ? new Date(metricsCheckedAt).toLocaleString() : '-'} />
              <InfoBlock label="指标摘要" value={metricsSummary} />
              <InfoBlock label="状态" value={metricsError ? `错误: ${metricsError}` : '获取成功'} />
            </div>
            {metrics && (
              <div className="space-y-3">
                <Input
                  value={metricsFilter}
                  onChange={(e) => setMetricsFilter(e.target.value)}
                  placeholder="过滤指标名称或标签，例如 gc 或 http_request"
                  className="max-w-xl"
                />
                <div className="max-h-72 overflow-auto rounded-lg border border-border/60 bg-background/80 p-3 text-xs text-foreground">
                  {filteredMetrics.length ? (
                    <div className="space-y-3">
                      {filteredMetrics.map((entry) => (
                        <div key={entry.name} className="space-y-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-semibold text-sm text-foreground">{entry.name}</span>
                            {entry.type && <span className="rounded bg-secondary px-2 py-0.5 text-[11px] uppercase text-secondary-foreground">{entry.type}</span>}
                            <span className="text-[11px] text-muted-foreground">{entry.samples.length} samples</span>
                          </div>
                          {entry.help && <div className="text-[11px] text-muted-foreground">{entry.help}</div>}
                          <div className="rounded-lg border border-border/40">
                            <table className="w-full border-collapse text-[11px]">
                              <thead className="bg-muted/40 text-muted-foreground">
                                <tr>
                                  <th className="p-2 text-left">Labels</th>
                                  <th className="p-2 text-left">Value</th>
                                </tr>
                              </thead>
                              <tbody>
                                {entry.samples.map((sample, idx) => (
                                  <tr key={idx} className="border-t border-border/30">
                                    <td className="p-2 align-top font-mono text-[11px]">
                                      {Object.keys(sample.labels).length
                                        ? Object.entries(sample.labels)
                                            .map(([k, v]) => `${k}="${v}"`)
                                            .join(', ')
                                        : '(no labels)'}
                                    </td>
                                    <td className="p-2 font-mono text-[11px] text-primary">{sample.value}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-muted-foreground">未匹配到指标。</div>
                  )}
                </div>
              </div>
            )}
            <pre className="mt-2 max-h-72 overflow-auto rounded-lg bg-slate-950/90 p-4 text-xs text-slate-200 dark:bg-slate-900">
              {metricsError ? metricsError : metrics ?? ''}
            </pre>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

function InfoBlock({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs uppercase tracking-wide text-muted-foreground/80">{label}</span>
      <span className="text-sm text-foreground">{value}</span>
    </div>
  )
}

type MetricSample = { labels: Record<string, string>; value: string }
type MetricEntry = { name: string; help?: string; type?: string; samples: MetricSample[] }

function parsePrometheus(text: string): MetricEntry[] {
  const lines = text.split(/\r?\n/)
  const map = new Map<string, MetricEntry>()
  let currentHelp: Record<string, string> = {}
  let currentType: Record<string, string> = {}

  for (const raw of lines) {
    const line = raw.trim()
    if (!line) continue
    if (line.startsWith('# HELP ')) {
      const rest = line.slice('# HELP '.length)
      const spaceIdx = rest.indexOf(' ')
      if (spaceIdx > 0) {
        const name = rest.slice(0, spaceIdx)
        const help = rest.slice(spaceIdx + 1)
        currentHelp[name] = help
      }
      continue
    }
    if (line.startsWith('# TYPE ')) {
      const rest = line.slice('# TYPE '.length)
      const spaceIdx = rest.indexOf(' ')
      if (spaceIdx > 0) {
        const name = rest.slice(0, spaceIdx)
        const type = rest.slice(spaceIdx + 1)
        currentType[name] = type
      }
      continue
    }
    if (line.startsWith('#')) continue

    const match = line.match(/^([^\s{]+)(\{[^}]*\})?\s+([^\s]+)(?:\s+[^\s]+)?$/)
    if (!match) continue
    const name = match[1]
    const labelPart = match[2]
    const value = match[3]
    const labels: Record<string, string> = {}

    if (labelPart) {
      const inner = labelPart.slice(1, -1)
      const pairs = inner.split(/,(?=(?:[^"\\]|\\.|"[^"]*")*$)/)
      for (const pair of pairs) {
        if (!pair) continue
        const eqIdx = pair.indexOf('=')
        if (eqIdx === -1) continue
        const key = pair.slice(0, eqIdx).trim()
        let val = pair.slice(eqIdx + 1).trim()
        if (val.startsWith('"') && val.endsWith('"')) {
          val = val.slice(1, -1).replace(/\\"/g, '"')
        }
        labels[key] = val
      }
    }

    if (!map.has(name)) {
      map.set(name, {
        name,
        help: currentHelp[name],
        type: currentType[name],
        samples: [],
      })
    }
    map.get(name)!.samples.push({ labels, value })
  }

  return Array.from(map.values()).sort((a, b) => a.name.localeCompare(b.name))
}
