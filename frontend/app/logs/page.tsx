"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

interface UserLogItem {
  ts: number;
  level: "INFO" | "WARN" | "ERROR" | "DEBUG";
  event: string;
  description: string;
  ip?: string;
  client_id?: string;
  user_agent?: string;
  session_id?: string;
  request_id?: string;
  outcome?: string;
  location?: string;
}

const fallbackLogs: UserLogItem[] = [
  {
    ts: Math.floor(Date.now() / 1000) - 120,
    level: "INFO",
    event: "USER_LOGIN",
    description: "从 Chrome 浏览器登录成功",
    ip: "203.0.113.5",
    outcome: "success",
    user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    location: "Shanghai",
  },
  {
    ts: Math.floor(Date.now() / 1000) - 86400,
    level: "WARN",
    event: "CONSENT_REVOKED",
    description: "撤销对 demo-client 的授权",
    ip: "198.51.100.42",
    client_id: "demo-client",
    outcome: "revoked",
  },
  {
    ts: Math.floor(Date.now() / 1000) - 172800,
    level: "ERROR",
    event: "PASSWORD_CHANGE_FAILED",
    description: "由于旧口令错误，修改口令失败",
    ip: "192.0.2.8",
    outcome: "failure",
  },
];

const levelStyles: Record<UserLogItem["level"], string> = {
  INFO: "bg-emerald-500/10 text-emerald-600",
  WARN: "bg-amber-500/10 text-amber-600",
  ERROR: "bg-rose-500/10 text-rose-600",
  DEBUG: "bg-slate-500/10 text-slate-600",
};

async function raiseForStatus(res: Response): Promise<Response> {
  if (res.ok) {
    return res;
  }
  const text = await res.text();
  const error: any = new Error(text || res.statusText);
  error.status = res.status;
  throw error;
}

export default function UserLogs() {
  const [logs, setLogs] = useState<UserLogItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [fallbackMessage, setFallbackMessage] = useState<string | null>(null);
  const [level, setLevel] = useState<string>("");
  const [keyword, setKeyword] = useState("");
  const [dateFrom, setDateFrom] = useState<string>("");
  const [dateTo, setDateTo] = useState<string>("");

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (level) params.set("level", level);
      if (keyword) params.set("search", keyword);
      if (dateFrom) params.set("from", String(Math.floor(new Date(dateFrom).getTime() / 1000)));
      if (dateTo) params.set("to", String(Math.floor(new Date(dateTo).getTime() / 1000)));
      const res = await raiseForStatus(await fetch(`/api/self/logs?${params.toString()}`, { credentials: "include" }));
      const data = await res.json();
      if (!Array.isArray(data)) throw new Error("响应格式不正确");
      const mapped: UserLogItem[] = data.map((item: any) => ({
        ts: Number(item.ts || item.timestamp || Date.now() / 1000),
        level: (item.level || "INFO").toUpperCase(),
        event: item.event || item.type || "UNKNOWN",
        description: item.desc || item.description || "",
        ip: item.ip,
        client_id: item.client_id,
        user_agent: item.ua || item.user_agent,
        session_id: item.session_id,
        request_id: item.request_id,
        outcome: item.outcome,
        location: item.location,
      }));
      setLogs(mapped);
      setFallbackMessage(null);
    } catch (err: any) {
      const status = err?.status ?? 0;
      if (status === 501) {
        toast.error("后端尚未提供安全日志接口，展示示例数据");
        setFallbackMessage("安全日志接口尚未实现，以下列表为示例数据。");
      } else {
        toast.error(err?.message || "无法加载日志，暂以示例数据展示");
        setFallbackMessage("暂时无法获取安全日志，以下为示例数据，稍后再试。");
      }
      setLogs(fallbackLogs);
    } finally {
      setLoading(false);
    }
  }, [level, keyword, dateFrom, dateTo]);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  const filtered = useMemo(() => {
    const q = keyword.trim().toLowerCase();
    return logs.filter((item) => {
      if (level && item.level !== level) return false;
      if (dateFrom) {
        const fromTs = Math.floor(new Date(dateFrom).getTime() / 1000);
        if (item.ts < fromTs) return false;
      }
      if (dateTo) {
        const toTs = Math.floor(new Date(dateTo).getTime() / 1000);
        if (item.ts > toTs) return false;
      }
      if (!q) return true;
      return [
        item.event,
        item.description,
        item.client_id,
        item.ip,
        item.outcome,
        item.user_agent,
      ]
        .join(" ")
        .toLowerCase()
        .includes(q);
    });
  }, [logs, keyword, level, dateFrom, dateTo]);

  const downloadJson = () => {
    const payload = JSON.stringify(filtered, null, 2);
    const blob = new Blob([payload], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `ginkgoid-logs-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="container py-10 space-y-6">
      <Card>
        <CardHeader className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
          <div>
            <CardTitle>安全日志</CardTitle>
            <CardDescription>仅展示与当前账户相关的活动记录，保留最近 90 天数据</CardDescription>
          </div>
          <div className="flex items-center gap-2 text-sm">
            <Button variant="outline" size="sm" onClick={downloadJson} disabled={!filtered.length}>
              导出 JSON
            </Button>
            <Button variant="outline" size="sm" onClick={fetchLogs} disabled={loading}>
              {loading ? "加载中..." : "刷新"}
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {fallbackMessage && (
            <div className="rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-800">
              {fallbackMessage}
            </div>
          )}
          <div className="grid gap-3 md:grid-cols-4">
            <div className="grid gap-1">
              <label className="text-xs font-semibold uppercase text-muted-foreground">级别</label>
              <select
                value={level}
                onChange={(e) => setLevel(e.target.value)}
                className="h-9 w-full rounded-md border border-border bg-background px-2 text-sm"
              >
                <option value="">全部</option>
                <option value="INFO">INFO</option>
                <option value="WARN">WARN</option>
                <option value="ERROR">ERROR</option>
                <option value="DEBUG">DEBUG</option>
              </select>
            </div>
            <div className="grid gap-1">
              <label className="text-xs font-semibold uppercase text-muted-foreground">关键词</label>
              <Input value={keyword} onChange={(e) => setKeyword(e.target.value)} placeholder="事件、IP、客户端" />
            </div>
            <div className="grid gap-1">
              <label className="text-xs font-semibold uppercase text-muted-foreground">开始日期</label>
              <Input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} />
            </div>
            <div className="grid gap-1">
              <label className="text-xs font-semibold uppercase text-muted-foreground">结束日期</label>
              <Input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)} />
            </div>
          </div>

          <div className="rounded-xl border border-border/60 bg-background/70">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[160px]">时间</TableHead>
                  <TableHead className="w-[80px]">级别</TableHead>
                  <TableHead>事件</TableHead>
                  <TableHead>描述</TableHead>
                  <TableHead className="w-[140px]">IP / 位置</TableHead>
                  <TableHead className="w-[120px]">结果</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((item) => (
                  <TableRow key={`${item.ts}-${item.event}-${item.ip}`} className="align-top">
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(item.ts * 1000).toLocaleString()}
                      {item.request_id && (
                        <div className="mt-1 truncate text-[10px] text-muted-foreground">RID: {item.request_id}</div>
                      )}
                    </TableCell>
                    <TableCell>
                      <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${levelStyles[item.level] || levelStyles.INFO}`}>
                        {item.level}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="font-medium text-sm text-foreground">{item.event}</div>
                      {item.client_id && (
                        <div className="text-xs text-muted-foreground">client_id: {item.client_id}</div>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="text-sm text-foreground">{item.description}</div>
                      {item.user_agent && (
                        <div className="mt-1 text-[11px] text-muted-foreground">UA: {item.user_agent}</div>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="text-sm text-foreground">{item.ip || "-"}</div>
                      {item.location && (
                        <div className="text-xs text-muted-foreground">{item.location}</div>
                      )}
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">
                        {item.outcome ? item.outcome : "-"}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
                {!filtered.length && !loading && (
                  <TableRow>
                    <TableCell colSpan={6} className="py-8 text-center text-sm text-muted-foreground">
                      暂无日志记录。
                    </TableCell>
                  </TableRow>
                )}
                {loading && (
                  <TableRow>
                    <TableCell colSpan={6} className="py-8 text-center text-sm text-muted-foreground">
                      正在加载...
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
