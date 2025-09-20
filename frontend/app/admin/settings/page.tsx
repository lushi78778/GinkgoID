"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";

interface ScopeItem {
  name: string;
  description?: string;
  claims: string[];
}

interface RoleItem {
  name: string;
  description?: string;
  permissions: string[];
}

interface PolicySettings {
  password_min_length: number;
  password_require_number: boolean;
  password_require_symbol: boolean;
  token_ttl_seconds: number;
  refresh_token_ttl_days: number;
  require_mfa: boolean;
}

const fallbackScopes: ScopeItem[] = [
  { name: "openid", description: "基础身份标识", claims: ["sub"] },
  { name: "profile", description: "姓名与头像等公开信息", claims: ["name", "preferred_username", "picture"] },
  { name: "email", description: "邮箱地址与验证状态", claims: ["email", "email_verified"] },
];

const fallbackRoles: RoleItem[] = [
  { name: "admin", description: "平台管理员", permissions: ["users:manage", "logs:view", "clients:approve", "settings:write"] },
  { name: "support", description: "客服支持", permissions: ["users:view", "logs:view"] },
];

const fallbackPolicies: PolicySettings = {
  password_min_length: 10,
  password_require_number: true,
  password_require_symbol: true,
  token_ttl_seconds: 3600,
  refresh_token_ttl_days: 14,
  require_mfa: false,
};

export default function AdminSettings() {
  const { me } = useAuth();
  const isAdmin = Boolean(me?.is_admin);

  const [scopes, setScopes] = useState<ScopeItem[]>(fallbackScopes);
  const [newScope, setNewScope] = useState({ name: "", description: "", claims: "" });
  const [roles, setRoles] = useState<RoleItem[]>(fallbackRoles);
  const [policies, setPolicies] = useState<PolicySettings>(fallbackPolicies);
  const [savingPolicies, setSavingPolicies] = useState(false);

  useEffect(() => {
    if (!isAdmin) return;
    (async () => {
      try {
        const res = await fetch("/api/admin/settings", { credentials: "include" });
        if (!res.ok) throw new Error(await res.text());
        const data = await res.json();
        if (Array.isArray(data.scopes)) setScopes(data.scopes);
        if (Array.isArray(data.roles)) setRoles(data.roles);
        if (data.policies) setPolicies({ ...fallbackPolicies, ...data.policies });
      } catch (err: any) {
        toast.error(err?.message || "无法加载设置，展示示例数据");
      }
    })();
  }, [isAdmin]);

  if (!isAdmin) {
    return (
      <div className="container py-10">
        <Card>
          <CardHeader>
            <CardTitle>系统级管理</CardTitle>
            <CardDescription>需要管理员权限</CardDescription>
          </CardHeader>
          <CardContent>
            <a className="btn" href={`/login?next=${encodeURIComponent("/admin/settings")}`}>
              管理员登录
            </a>
          </CardContent>
        </Card>
      </div>
    );
  }

  const addScope = () => {
    if (!newScope.name.trim()) {
      toast.error("请输入 scope 名称");
      return;
    }
    const scope: ScopeItem = {
      name: newScope.name.trim(),
      description: newScope.description.trim(),
      claims: newScope.claims
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    };
    setScopes((prev) => [...prev, scope]);
    setNewScope({ name: "", description: "", claims: "" });
    toast.success("已添加 scope (尚未保存到后端)");
  };

  const removeScope = (name: string) => {
    if (!window.confirm(`确定要移除 scope ${name} 吗？`)) return;
    setScopes((prev) => prev.filter((item) => item.name !== name));
  };

  const saveScopes = async () => {
    try {
      const res = await fetch("/api/admin/scopes", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(scopes),
      });
      if (!res.ok) throw new Error(await res.text());
      toast.success("Scope 配置已保存");
    } catch (err: any) {
      toast.error(err?.message || "保存失败 (后端可能未实现)");
    }
  };

  const toggleRolePermission = (roleName: string, perm: string) => {
    setRoles((prev) =>
      prev.map((r) =>
        r.name === roleName
          ? {
              ...r,
              permissions: r.permissions.includes(perm)
                ? r.permissions.filter((p) => p !== perm)
                : [...r.permissions, perm],
            }
          : r,
      ),
    );
  };

  const saveRoles = async () => {
    try {
      const res = await fetch("/api/admin/roles", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(roles),
      });
      if (!res.ok) throw new Error(await res.text());
      toast.success("角色权限配置已保存");
    } catch (err: any) {
      toast.error(err?.message || "保存失败 (后端可能未实现)");
    }
  };

  const savePolicies = async () => {
    setSavingPolicies(true);
    try {
      const res = await fetch("/api/admin/policies", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(policies),
      });
      if (!res.ok) throw new Error(await res.text());
      toast.success("安全策略已保存");
    } catch (err: any) {
      toast.error(err?.message || "保存失败 (后端可能未实现)");
    } finally {
      setSavingPolicies(false);
    }
  };

  return (
    <div className="container py-10 space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Scope 管理</CardTitle>
          <CardDescription>定义平台支持的 scope 以及对应返回的用户 Claim 集合</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2 md:grid-cols-4">
            <div className="grid gap-1">
              <Label>Scope 名称</Label>
              <Input value={newScope.name} onChange={(e) => setNewScope({ ...newScope, name: e.target.value })} />
            </div>
            <div className="grid gap-1 md:col-span-2">
              <Label>说明</Label>
              <Input value={newScope.description} onChange={(e) => setNewScope({ ...newScope, description: e.target.value })} />
            </div>
            <div className="grid gap-1">
              <Label>Claims (逗号分隔)</Label>
              <Input value={newScope.claims} onChange={(e) => setNewScope({ ...newScope, claims: e.target.value })} />
            </div>
          </div>
          <div className="flex gap-2">
            <Button onClick={addScope}>添加 Scope</Button>
            <Button variant="outline" onClick={saveScopes}>
              保存到后端
            </Button>
          </div>
          <div className="rounded-xl border border-border/60 bg-background/70">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Scope</TableHead>
                  <TableHead>说明</TableHead>
                  <TableHead>Claims</TableHead>
                  <TableHead className="w-[80px]">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scopes.map((scope) => (
                  <TableRow key={scope.name}>
                    <TableCell className="font-mono text-xs">{scope.name}</TableCell>
                    <TableCell className="text-sm text-foreground">{scope.description || "-"}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {scope.claims.map((claim) => (
                          <span key={claim} className="rounded-md bg-secondary px-2 py-0.5 text-[11px]">
                            {claim}
                          </span>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Button variant="destructive" size="sm" onClick={() => removeScope(scope.name)}>
                        移除
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>管理后台角色权限</CardTitle>
          <CardDescription>通过 RBAC 控制不同管理角色的访问权限，可为客服、审计等创建精细化角色</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-xl border border-border/60 bg-background/70">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>角色</TableHead>
                  <TableHead>权限</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {roles.map((role) => (
                  <TableRow key={role.name}>
                    <TableCell>
                      <div className="text-sm text-foreground font-medium">{role.name}</div>
                      <div className="text-xs text-muted-foreground">{role.description || "-"}</div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-2">
                        {["users:view", "users:manage", "logs:view", "clients:approve", "settings:write"].map((perm) => (
                          <label key={perm} className="flex items-center gap-2 text-xs bg-muted/40 px-2 py-1 rounded-md">
                            <input
                              type="checkbox"
                              checked={role.permissions.includes(perm)}
                              onChange={() => toggleRolePermission(role.name, perm)}
                            />
                            {perm}
                          </label>
                        ))}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <Button variant="outline" onClick={saveRoles}>
            保存角色配置
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>全局安全策略</CardTitle>
          <CardDescription>为所有用户统一配置密码复杂度、令牌有效期和 MFA 要求</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="grid gap-1">
              <Label>密码最小长度</Label>
              <Input
                type="number"
                min={8}
                value={policies.password_min_length}
                onChange={(e) => setPolicies({ ...policies, password_min_length: Number(e.target.value) })}
              />
            </div>
            <div className="grid gap-1">
              <Label>访问令牌默认有效期 (秒)</Label>
              <Input
                type="number"
                min={600}
                value={policies.token_ttl_seconds}
                onChange={(e) => setPolicies({ ...policies, token_ttl_seconds: Number(e.target.value) })}
              />
            </div>
            <div className="grid gap-1">
              <Label>刷新令牌有效期 (天)</Label>
              <Input
                type="number"
                min={1}
                value={policies.refresh_token_ttl_days}
                onChange={(e) => setPolicies({ ...policies, refresh_token_ttl_days: Number(e.target.value) })}
              />
            </div>
            <div className="grid gap-1">
              <Label>密码必须包含</Label>
              <div className="flex items-center gap-6 text-sm">
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={policies.password_require_number}
                    onChange={(e) => setPolicies({ ...policies, password_require_number: e.target.checked })}
                  />
                  数字
                </label>
                <label className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={policies.password_require_symbol}
                    onChange={(e) => setPolicies({ ...policies, password_require_symbol: e.target.checked })}
                  />
                  特殊字符
                </label>
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between rounded-xl border border-border/60 bg-muted/30 px-4 py-3">
            <div>
              <div className="text-sm font-medium text-foreground">强制所有用户启用 MFA</div>
              <div className="text-xs text-muted-foreground">
                开启后，用户下次登录将被要求绑定 MFA，管理员可豁免特定角色。
              </div>
            </div>
            <Switch checked={policies.require_mfa} onCheckedChange={(checked) => setPolicies({ ...policies, require_mfa: checked })} />
          </div>

          <Button onClick={savePolicies} disabled={savingPolicies}>
            {savingPolicies ? "保存中..." : "保存安全策略"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
