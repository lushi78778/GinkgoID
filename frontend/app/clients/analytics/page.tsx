"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth } from "@/lib/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";

interface ClientItem {
  client_id: string;
  client_name?: string;
}

interface AnalyticsPoint {
  date: string;
  logins: number;
  new_users: number;
  success: number;
  failed: number;
}

interface AnalyticsData {
  total_logins: number;
  new_users: number;
  success_rate: number;
  failure_rate: number;
  period: string;
  points: AnalyticsPoint[];
  top_errors: { code: string; count: number; description?: string }[];
}

const fallbackAnalytics: AnalyticsData = {
  total_logins: 482,
  new_users: 36,
  success_rate: 0.93,
  failure_rate: 0.07,
  period: "最近 7 天",
  points: [
    { date: "周一", logins: 60, new_users: 5, success: 56, failed: 4 },
    { date: "周二", logins: 72, new_users: 6, success: 66, failed: 6 },
    { date: "周三", logins: 80, new_users: 7, success: 75, failed: 5 },
    { date: "周四", logins: 69, new_users: 4, success: 63, failed: 6 },
    { date: "周五", logins: 90, new_users: 8, success: 82, failed: 8 },
    { date: "周六", logins: 55, new_users: 3, success: 52, failed: 3 },
    { date: "周日", logins: 56, new_users: 3, success: 52, failed: 4 },
  ],
  top_errors: [
    { code: "invalid_client", count: 5, description: "Client secret 无效" },
    { code: "invalid_grant", count: 4, description: "授权码过期" },
    { code: "login_failed", count: 3, description: "用户名或密码错误" },
  ],
};

export default function AnalyticsPage() {
  const { me } = useAuth();
  const [clients, setClients] = useState<ClientItem[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(false);

  const canAccess = me?.is_admin || (me as any)?.is_dev;

  const loadClients = useCallback(async () => {
    try {
      const res = await fetch("/api/my/clients", { credentials: "include" });
      if (!res.ok) throw new Error(await res.text());
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

  const loadAnalytics = useCallback(async () => {
    if (!selected) return;
    setLoading(true);
    try {
      const res = await fetch(`/api/my/clients/${encodeURIComponent(selected)}/analytics?period=7d`, {
        credentials: "include",
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setAnalytics({
        total_logins: Number(data.total_logins ?? data.login_count ?? 0),
        new_users: Number(data.new_users ?? data.new_user_count ?? 0),
        success_rate: Number(data.success_rate ?? 0),
        failure_rate: Number(data.failure_rate ?? 0),
        period: data.period ?? "最近 7 天",
        points: Array.isArray(data.points)
          ? data.points
          : Array.isArray(data.daily)
          ? data.daily
          : fallbackAnalytics.points,
        top_errors: Array.isArray(data.top_errors) ? data.top_errors : fallbackAnalytics.top_errors,
      });
    } catch (err: any) {
      toast.error(err?.message || "无法获取统计，展示示例数据");
      setAnalytics(fallbackAnalytics);
    } finally {
      setLoading(false);
    }
  }, [selected]);

  useEffect(() => {
    if (canAccess) loadClients();
  }, [canAccess, loadClients]);

  useEffect(() => {
    if (canAccess && selected) loadAnalytics();
  }, [canAccess, selected, loadAnalytics]);

  const maxLogins = useMemo(() => {
    if (!analytics) return 1;
    return Math.max(...analytics.points.map((p) => p.logins), 1);
  }, [analytics]);

  if (!canAccess) {
    return (
      <div className="container py-10">
        <Card>
          <CardHeader>
            <CardTitle>应用分析</CardTitle>
            <CardDescription>需要开发者或管理员权限</CardDescription>
          </CardHeader>
          <CardContent>
            <a className="btn" href={`/login?next=${encodeURIComponent("/clients/analytics")}`}>
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
            <CardTitle>应用分析</CardTitle>
            <CardDescription>观察登录趋势、成功率和错误分布，指导容量规划与优化</CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <select
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
              className="h-9 min-w-[200px] rounded-md border border-border bg-background px-2 text-sm"
            >
              {clients.map((client) => (
                <option key={client.client_id} value={client.client_id}>
                  {client.client_name || client.client_id}
                </option>
              ))}
            </select>
            <Button variant="outline" size="sm" onClick={loadAnalytics} disabled={loading}>
              {loading ? "加载中..." : "刷新"}
            </Button>
          </div>
        </CardHeader>
        {analytics && (
          <CardContent className="space-y-6">
            <div className="grid gap-4 md:grid-cols-4">
              <MetricCard title="登录总数" value={analytics.total_logins.toLocaleString()} hint={analytics.period} />
              <MetricCard title="新增授权用户" value={analytics.new_users.toLocaleString()} hint={analytics.period} />
              <MetricCard
                title="成功率"
                value={`${Math.round(analytics.success_rate * 100)}%`}
                hint="成功登录次数 / 总登录次数"
              />
              <MetricCard
                title="失败率"
                value={`${Math.round(analytics.failure_rate * 100)}%`}
                hint="按错误响应统计"
              />
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-foreground">每日趋势</h3>
                <span className="text-xs text-muted-foreground">基于最近 7 天成功/失败请求</span>
              </div>
              <div className="grid gap-3 md:grid-cols-7">
                {analytics.points.map((point) => {
                  const successHeight = Math.round((point.success / maxLogins) * 140);
                  const failedHeight = Math.round((point.failed / maxLogins) * 140);
                  return (
                    <div key={point.date} className="flex flex-col items-center gap-2">
                      <div className="flex h-40 w-12 flex-col justify-end gap-1">
                        <div
                          className="w-full rounded-sm bg-emerald-500/70"
                          style={{ height: `${successHeight}px` }}
                          title={`成功 ${point.success}`}
                        />
                        <div
                          className="w-full rounded-sm bg-rose-400/70"
                          style={{ height: `${failedHeight}px` }}
                          title={`失败 ${point.failed}`}
                        />
                      </div>
                      <div className="text-xs text-muted-foreground">{point.date}</div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-foreground">常见错误</h3>
              <div className="rounded-xl border border-border/60 bg-background/70">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[160px]">错误码</TableHead>
                      <TableHead>说明</TableHead>
                      <TableHead className="w-[120px]">次数</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {analytics.top_errors.map((err) => (
                      <TableRow key={err.code}>
                        <TableCell className="font-mono text-xs">{err.code}</TableCell>
                        <TableCell className="text-sm text-foreground">{err.description || "-"}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">{err.count}</TableCell>
                      </TableRow>
                    ))}
                    {!analytics.top_errors.length && (
                      <TableRow>
                        <TableCell colSpan={3} className="py-8 text-center text-sm text-muted-foreground">
                          暂无错误数据。
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </div>
            </div>
          </CardContent>
        )}
      </Card>
    </div>
  );
}

function MetricCard({ title, value, hint }: { title: string; value: string; hint?: string }) {
  return (
    <div className="rounded-xl border border-border/60 bg-background/70 p-4">
      <div className="text-xs uppercase tracking-wide text-muted-foreground">{title}</div>
      <div className="mt-2 text-2xl font-semibold text-foreground">{value}</div>
      {hint && <div className="text-xs text-muted-foreground mt-1">{hint}</div>}
    </div>
  );
}
