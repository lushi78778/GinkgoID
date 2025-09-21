"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";

interface ClientItem {
  client_id: string;
  client_name?: string;
}

interface AuthorizedUser {
  user_id: number;
  username: string;
  name?: string;
  email?: string;
  last_login?: number;
  granted_at?: number;
  scopes?: string[];
}

const fallbackUsers: AuthorizedUser[] = [
  {
    user_id: 42,
    username: "alice",
    name: "Alice",
    email: "alice@example.com",
    granted_at: Math.floor(Date.now() / 1000) - 86400,
    last_login: Math.floor(Date.now() / 1000) - 600,
    scopes: ["openid", "profile", "email"],
  },
  {
    user_id: 77,
    username: "bob",
    email: "bob@example.com",
    granted_at: Math.floor(Date.now() / 1000) - 3600 * 72,
    scopes: ["openid"],
  },
];

async function raiseForStatus(res: Response): Promise<Response> {
  if (res.ok) {
    return res;
  }
  const text = await res.text();
  const error: any = new Error(text || res.statusText);
  error.status = res.status;
  throw error;
}

export default function ClientUsersPage() {
  const { me } = useAuth();
  const [clients, setClients] = useState<ClientItem[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [users, setUsers] = useState<AuthorizedUser[]>([]);
  const [loading, setLoading] = useState(false);
  const [fallbackMessage, setFallbackMessage] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

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

  const loadUsers = useCallback(async () => {
    if (!selected) return;
    setLoading(true);
    try {
      const res = await raiseForStatus(
        await fetch(`/api/my/clients/${encodeURIComponent(selected)}/users`, { credentials: "include" }),
      );
      const data = await res.json();
      if (!Array.isArray(data)) throw new Error("响应格式不正确");
      const mapped: AuthorizedUser[] = data.map((item: any) => ({
        user_id: Number(item.user_id ?? item.id ?? 0),
        username: item.username ?? "",
        name: item.name,
        email: item.email,
        last_login: item.last_login,
        granted_at: item.granted_at,
        scopes: Array.isArray(item.scopes) ? item.scopes : String(item.scope ?? "").split(/\s+/).filter(Boolean),
      }));
      setUsers(mapped);
      setFallbackMessage(null);
    } catch (err: any) {
      const status = err?.status ?? 0;
      if (status === 501) {
        toast.error("后端尚未提供授权用户列表，展示示例数据");
        setFallbackMessage("授权用户列表接口尚未实现，以下为示例数据。");
      } else {
        toast.error(err?.message || "无法获取用户列表，暂以示例数据展示");
        setFallbackMessage("暂时无法获取授权用户列表，以下内容为示例数据，稍后可重试。");
      }
      setUsers(fallbackUsers);
    } finally {
      setLoading(false);
    }
  }, [selected]);

  useEffect(() => {
    if (canAccess) loadClients();
  }, [canAccess, loadClients]);

  useEffect(() => {
    if (canAccess && selected) loadUsers();
  }, [canAccess, selected, loadUsers]);

  const revokeUser = async (userId: number) => {
    if (!window.confirm("确定要解除该用户的授权吗？")) return;
    try {
      await raiseForStatus(
        await fetch(`/api/my/clients/${encodeURIComponent(selected)}/users/${userId}`, {
          method: "DELETE",
          credentials: "include",
        }),
      );
      toast.success("已解除授权");
      await loadUsers();
    } catch (err: any) {
      toast.error(err?.message || "操作失败 (后端可能未实现)");
    }
  };

  const filteredUsers = users.filter((user) => {
    const q = filter.trim().toLowerCase();
    if (!q) return true;
    return [user.username, user.name, user.email, user.scopes?.join(" ")].join(" ").toLowerCase().includes(q);
  });

  if (!canAccess) {
    return (
      <div className="container py-10">
        <Card>
          <CardHeader>
            <CardTitle>应用授权用户</CardTitle>
            <CardDescription>需要开发者或管理员权限</CardDescription>
          </CardHeader>
          <CardContent>
            <a className="btn" href={`/login?next=${encodeURIComponent("/clients/users")}`}>
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
            <CardTitle>授权用户</CardTitle>
            <CardDescription>查看和管理授权了当前客户端的终端用户，支持解除授权</CardDescription>
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
            <Button variant="outline" size="sm" onClick={loadUsers} disabled={loading}>
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
          <div className="grid gap-1">
            <label className="text-xs font-semibold uppercase text-muted-foreground">搜索</label>
            <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="用户名、邮箱或 Scope" />
          </div>
          <div className="rounded-xl border border-border/60 bg-background/70">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[80px]">用户 ID</TableHead>
                  <TableHead>账户</TableHead>
                  <TableHead>授权 Scope</TableHead>
                  <TableHead className="w-[160px]">授权时间</TableHead>
                  <TableHead className="w-[160px]">最近登录</TableHead>
                  <TableHead className="w-[100px]">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredUsers.map((user) => (
                  <TableRow key={user.user_id}>
                    <TableCell className="font-mono text-xs">{user.user_id}</TableCell>
                    <TableCell>
                      <div className="text-sm text-foreground font-medium">{user.username}</div>
                      <div className="text-xs text-muted-foreground">{user.email || "-"}</div>
                    </TableCell>
                    <TableCell>
                      {user.scopes?.length ? (
                        <div className="flex flex-wrap gap-1">
                          {user.scopes.map((scope) => (
                            <span key={scope} className="rounded-md bg-secondary px-2 py-0.5 text-[11px]">
                              {scope}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground">-</span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {user.granted_at ? new Date(user.granted_at * 1000).toLocaleString() : "-"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {user.last_login ? new Date(user.last_login * 1000).toLocaleString() : "-"}
                    </TableCell>
                    <TableCell>
                      <Button variant="destructive" size="sm" onClick={() => revokeUser(user.user_id)} disabled={Boolean(fallbackMessage)}>
                        解除授权
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
                {!filteredUsers.length && !loading && (
                  <TableRow>
                    <TableCell colSpan={6} className="py-8 text-center text-sm text-muted-foreground">
                      暂无授权用户。
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
