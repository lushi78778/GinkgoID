"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth } from "@/lib/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";

interface ClientItem {
  client_id: string;
  client_name?: string;
  token_endpoint_auth_method?: string;
}

interface ClientLogItem {
  ts: number;
  level: string;
  event: string;
  desc?: string;
  request_id?: string;
  user_id?: number;
  outcome?: string;
}

const fallbackLogItems: ClientLogItem[] = [
  {
    ts: Math.floor(Date.now() / 1000) - 3600,
    level: "INFO",
    event: "TOKEN_ISSUED",
    desc: "授权码兑换成功 (code -> token)",
    outcome: "success",
  },
  {
    ts: Math.floor(Date.now() / 1000) - 4000,
    level: "ERROR",
    event: "TOKEN_INTROSPECTION_FAILED",
    desc: "client_secret_basic 鉴权失败",
    outcome: "invalid_client",
  },
  {
    ts: Math.floor(Date.now() / 1000) - 7200,
    level: "WARN",
    event: "USER_REVOKED_CONSENT",
    desc: "用户 24 撤销授权",
    outcome: "revoked",
  },
];

const levelColor: Record<string, string> = {
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

export default function ClientLogsPage() {
  const { me } = useAuth();
  const [clients, setClients] = useState<ClientItem[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [logs, setLogs] = useState<ClientLogItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [fallbackMessage, setFallbackMessage] = useState<string | null>(null);
  const [keyword, setKeyword] = useState("");
  const [level, setLevel] = useState<string>("");

  const canAccess = me?.is_admin || (me as any)?.is_dev;

  const loadClients = useCallback(async () => {
    try {
      const res = await raiseForStatus(await fetch("/api/my/clients", { credentials: "include" }));
      const data = await res.json();
      if (!Array.isArray(data)) throw new Error("响应格式不正确");
      setClients(data);
      if (data.length && !selected) {
        setSelected(data[0].client_id);
      }
    } catch (err: any) {
      toast.error(err?.message || "无法加载客户端列表");
    }
  }, [selected]);

  const loadLogs = useCallback(async () => {
    if (!selected) return;
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (level) params.set("level", level);
      if (keyword) params.set("q", keyword);
      const res = await raiseForStatus(
        await fetch(`/api/my/clients/${encodeURIComponent(selected)}/logs?${params.toString()}`, {
          credentials: "include",
        }),
      );
      const data = await res.json();
      if (!Array.isArray(data)) throw new Error("响应格式不正确");
      const mapped: ClientLogItem[] = data.map((item: any) => ({
        ts: Number(item.ts ?? item.timestamp ?? Date.now() / 1000),
        level: (item.level || "INFO").toUpperCase(),
        event: item.event || item.type || "UNKNOWN",
        desc: item.desc || item.description,
        request_id: item.request_id,
        user_id: item.user_id,
        outcome: item.outcome,
      }));
      setLogs(mapped);
      setFallbackMessage(null);
    } catch (err: any) {
      const status = err?.status ?? 0;
      if (status === 501) {
        toast.error("后端尚未提供应用日志接口，展示示例数据");
        setFallbackMessage("应用日志接口尚未实现，以下数据仅用于演示界面。");
      } else {
        toast.error(err?.message || "无法获取日志，暂以示例数据展示");
        setFallbackMessage("暂时无法获取应用日志，以下为示例数据，稍后可重试。");
      }
      setLogs(fallbackLogItems);
    } finally {
      setLoading(false);
    }
  }, [selected, level, keyword]);

  useEffect(() => {
    if (canAccess) loadClients();
  }, [canAccess, loadClients]);

  useEffect(() => {
    if (canAccess && selected) loadLogs();
  }, [canAccess, selected, loadLogs]);

  const filteredLogs = useMemo(() => {
    const q = keyword.trim().toLowerCase();
    return logs.filter((item) => {
      if (level && item.level !== level) return false;
      if (!q) return true;
      return [item.event, item.desc, item.outcome, item.request_id].join(" ").toLowerCase().includes(q);
    });
  }, [logs, keyword, level]);

  if (!canAccess) {
    return (
      <div className="container py-10">
        <Card>
          <CardHeader>
            <CardTitle>应用日志</CardTitle>
            <CardDescription>需要开发者或管理员权限</CardDescription>
          </CardHeader>
          <CardContent>
            <a className="btn" href={`/login?next=${encodeURIComponent("/clients/logs")}`}>
              使用开发者账户登录
            </a>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container py-10 space-y-6">
      <Card>
        <CardHeader className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <CardTitle>应用日志</CardTitle>
            <CardDescription>监控授权、令牌、错误等核心事件，便于快速定位问题</CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <select
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
              className="h-9 min-w-[200px] rounded-md border border-border bg-background px-2 text-sm"
            >
              {clients.map((client) => (
                <option key={client.client_id} value={client.client_id}>
                  {(client.client_name || client.client_id) + (client.token_endpoint_auth_method === "none" ? " · 公共" : " · 机密")}
                </option>
              ))}
            </select>
            <Button variant="outline" size="sm" onClick={loadLogs} disabled={loading}>
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
          <div className="grid gap-3 md:grid-cols-3">
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
              <Input value={keyword} onChange={(e) => setKeyword(e.target.value)} placeholder="事件、RID、用户" />
            </div>
          </div>

          <div className="rounded-xl border border-border/60 bg-background/70">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[160px]">时间</TableHead>
                  <TableHead className="w-[80px]">级别</TableHead>
                  <TableHead>事件</TableHead>
                  <TableHead>详情</TableHead>
                  <TableHead className="w-[120px]">结果</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredLogs.map((log, idx) => (
                  <TableRow key={`${log.ts}-${idx}`} className="align-top">
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(log.ts * 1000).toLocaleString()}
                      {log.request_id && (
                        <div className="mt-1 text-[10px] text-muted-foreground">RID: {log.request_id}</div>
                      )}
                    </TableCell>
                    <TableCell className="text-xs">
                      <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${levelColor[log.level] || levelColor.INFO}`}>
                        {log.level}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="text-sm text-foreground font-medium">{log.event}</div>
                      {typeof log.user_id === "number" && (
                        <div className="text-xs text-muted-foreground">用户 #{log.user_id}</div>
                      )}
                    </TableCell>
                    <TableCell className="text-sm text-foreground">
                      {log.desc || "-"}
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{log.outcome || "-"}</TableCell>
                  </TableRow>
                ))}
                {!filteredLogs.length && !loading && (
                  <TableRow>
                    <TableCell colSpan={5} className="py-8 text-center text-sm text-muted-foreground">
                      暂无日志记录。
                    </TableCell>
                  </TableRow>
                )}
                {loading && (
                  <TableRow>
                    <TableCell colSpan={5} className="py-8 text-center text-sm text-muted-foreground">
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
