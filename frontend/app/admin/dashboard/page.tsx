"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth } from "@/lib/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";

interface DashboardMetrics {
  total_users: number;
  active_users_7d: number;
  total_clients: number;
  logins_today: number;
  mfa_enabled: number;
  pending_clients: number;
  login_success_rate: number;
}

interface TrendPoint {
  label: string;
  value: number;
}

interface TopClient {
  client_id: string;
  name?: string;
  weekly_logins: number;
  approval_status: string;
}

const fallbackMetrics: DashboardMetrics = {
  total_users: 1843,
  active_users_7d: 612,
  total_clients: 62,
  logins_today: 214,
  mfa_enabled: 388,
  pending_clients: 4,
  login_success_rate: 0.948,
};

const fallbackTrend: TrendPoint[] = [
  { label: "Mon", value: 180 },
  { label: "Tue", value: 220 },
  { label: "Wed", value: 260 },
  { label: "Thu", value: 240 },
  { label: "Fri", value: 310 },
  { label: "Sat", value: 160 },
  { label: "Sun", value: 150 },
];

const fallbackClients: TopClient[] = [
  { client_id: "dashboard-app", name: "管理后台", weekly_logins: 680, approval_status: "approved" },
  { client_id: "sales-portal", name: "销售门户", weekly_logins: 420, approval_status: "approved" },
  { client_id: "partner-api", name: "合作伙伴 API", weekly_logins: 320, approval_status: "pending" },
];

export default function AdminDashboard() {
  const { me } = useAuth();
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [trend, setTrend] = useState<TrendPoint[]>([]);
  const [topClients, setTopClients] = useState<TopClient[]>([]);
  const [loading, setLoading] = useState(false);

  const isAdmin = Boolean(me?.is_admin);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/admin/metrics", { credentials: "include" });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setMetrics({
        total_users: Number(data.total_users ?? 0),
        active_users_7d: Number(data.active_users_7d ?? data.active_users ?? 0),
        total_clients: Number(data.total_clients ?? 0),
        logins_today: Number(data.logins_today ?? data.logins_24h ?? 0),
        mfa_enabled: Number(data.mfa_enabled ?? data.users_with_mfa ?? 0),
        pending_clients: Number(data.pending_clients ?? 0),
        login_success_rate: Number(data.login_success_rate ?? 0),
      });
      setTrend(
        Array.isArray(data.daily_logins)
          ? data.daily_logins
          : Array.isArray(data.trend)
          ? data.trend
          : fallbackTrend,
      );
      setTopClients(Array.isArray(data.top_clients) ? data.top_clients : fallbackClients);
    } catch (err: any) {
      toast.error(err?.message || "无法获取指标，展示示例数据");
      setMetrics(fallbackMetrics);
      setTrend(fallbackTrend);
      setTopClients(fallbackClients);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (isAdmin) {
      loadData();
    }
  }, [isAdmin, loadData]);

  const maxTrend = useMemo(() => Math.max(...(trend.length ? trend.map((item) => item.value) : [1])), [trend]);

  if (!isAdmin) {
    return (
      <div className="container py-10">
        <Card>
          <CardHeader>
            <CardTitle>全局仪表盘</CardTitle>
            <CardDescription>需要管理员权限</CardDescription>
          </CardHeader>
          <CardContent>
            <a className="btn" href={`/login?next=${encodeURIComponent("/admin/dashboard")}`}>
              管理员登录
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
            <CardTitle>平台运行概览</CardTitle>
            <CardDescription>实时掌握用户增长、登录情况、客户端审批及 MFA 启用情况</CardDescription>
          </div>
          <Button variant="outline" size="sm" onClick={loadData} disabled={loading}>
            {loading ? "刷新中..." : "刷新"}
          </Button>
        </CardHeader>
        {metrics && (
          <CardContent className="space-y-6">
            <div className="grid gap-4 md:grid-cols-3 lg:grid-cols-6">
              <Metric title="用户总数" value={metrics.total_users.toLocaleString()} />
              <Metric title="7 日活跃" value={metrics.active_users_7d.toLocaleString()} />
              <Metric title="应用数量" value={metrics.total_clients.toLocaleString()} />
              <Metric title="今日登录" value={metrics.logins_today.toLocaleString()} />
              <Metric title="启用 MFA" value={metrics.mfa_enabled.toLocaleString()} />
              <Metric
                title="登录成功率"
                value={`${Math.round(metrics.login_success_rate * 100)}%`}
                highlight={metrics.login_success_rate < 0.9 ? "warning" : undefined}
              />
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-foreground">过去 7 天登录趋势</h3>
                <span className="text-xs text-muted-foreground">成功登录次数统计</span>
              </div>
              <div className="flex gap-4">
                {trend.map((item) => (
                  <div key={item.label} className="flex flex-1 flex-col items-center gap-2">
                    <div
                      className="w-full rounded-lg bg-gradient-to-t from-primary/10 via-primary/50 to-primary"
                      style={{ height: `${Math.max((item.value / maxTrend) * 180, 12)}px` }}
                      title={`${item.label}: ${item.value}`}
                    />
                    <span className="text-xs text-muted-foreground">{item.label}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <div className="rounded-xl border border-border/60 bg-background/70 p-4">
                <div className="text-sm font-semibold text-foreground">待办事项</div>
                <div className="mt-3 space-y-3 text-sm">
                  <TodoItem done={metrics.pending_clients === 0} text={`待审批客户端 ${metrics.pending_clients} 个`} />
                  <TodoItem done={metrics.login_success_rate > 0.9} text="登录成功率 ≥ 90%" />
                  <TodoItem done={metrics.mfa_enabled / Math.max(metrics.total_users, 1) > 0.3} text="至少 30% 用户启用 MFA" />
                </div>
              </div>
              <div className="rounded-xl border border-border/60 bg-background/70 p-4">
                <div className="text-sm font-semibold text-foreground">策略提醒</div>
                <ul className="mt-3 list-disc space-y-2 pl-5 text-sm text-muted-foreground">
                  <li>建议启用“强制新用户绑定 MFA”策略</li>
                  <li>建议将 Token 默认有效期从 7200s 减少至 3600s</li>
                  <li>考虑为销售门户配置基于 IP 的访问限制</li>
                </ul>
              </div>
            </div>

            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-foreground">高活跃客户端</h3>
                <a className="text-xs text-primary" href="/admin/approvals">
                  管理客户端审批
                </a>
              </div>
              <div className="rounded-xl border border-border/60 bg-background/70">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>客户端</TableHead>
                      <TableHead>近 7 天登录</TableHead>
                      <TableHead>审批状态</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {topClients.map((client) => (
                      <TableRow key={client.client_id}>
                        <TableCell>
                          <div className="text-sm text-foreground font-medium">{client.name || client.client_id}</div>
                          <div className="text-xs text-muted-foreground">{client.client_id}</div>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {client.weekly_logins.toLocaleString()}
                        </TableCell>
                        <TableCell>
                          <span
                            className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                              client.approval_status === "approved"
                                ? "bg-emerald-500/10 text-emerald-600"
                                : client.approval_status === "pending"
                                ? "bg-amber-500/10 text-amber-600"
                                : "bg-slate-500/10 text-slate-600"
                            }`}
                          >
                            {client.approval_status === "approved"
                              ? "已批准"
                              : client.approval_status === "pending"
                              ? "待审批"
                              : client.approval_status}
                          </span>
                        </TableCell>
                      </TableRow>
                    ))}
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

function Metric({ title, value, highlight }: { title: string; value: string; highlight?: "warning" }) {
  return (
    <div
      className={`rounded-xl border border-border/60 bg-background/70 p-4 ${
        highlight === "warning" ? "border-amber-500/60" : ""
      }`}
    >
      <div className="text-xs uppercase tracking-wide text-muted-foreground">{title}</div>
      <div className="mt-2 text-2xl font-semibold text-foreground">{value}</div>
    </div>
  );
}

function TodoItem({ done, text }: { done: boolean; text: string }) {
  return (
    <div className="flex items-center gap-2 text-sm">
      <span
        className={`h-2.5 w-2.5 rounded-full ${done ? "bg-emerald-500" : "bg-amber-500"}`}
        aria-hidden
      />
      <span className={done ? "text-muted-foreground" : "text-foreground"}>{text}</span>
    </div>
  );
}
