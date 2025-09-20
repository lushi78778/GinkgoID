"use client";

import Image from "next/image";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { toast } from "sonner";

interface SessionItem {
  id: string;
  created_at: number;
  last_seen_at: number;
  ip?: string;
  user_agent?: string;
  location?: string;
  current?: boolean;
}

interface MfaState {
  enabled: boolean;
  secret?: string;
  otpauth_url?: string;
  otpauth_qr?: string;
  recovery_codes?: string[];
  last_used_at?: number | null;
  enrolled_at?: number | null;
}

const fallbackMfa: MfaState = {
  enabled: false,
  secret: "JBSWY3DPEHPK3PXP",
  otpauth_url: "otpauth://totp/GinkgoID:demo%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GinkgoID",
  recovery_codes: ["9K3D-G7PT", "F2LM-1QZC", "AZ3R-JX99", "5MNC-QWER", "4SDF-PLKM"],
  otpauth_qr: "",
};

const fallbackSessions: SessionItem[] = [
  {
    id: "current",
    created_at: Math.floor(Date.now() / 1000) - 7200,
    last_seen_at: Math.floor(Date.now() / 1000),
    ip: "203.0.113.42",
    user_agent: "Mac · Chrome 126",
    location: "Shanghai, CN",
    current: true,
  },
  {
    id: "old-1",
    created_at: Math.floor(Date.now() / 1000) - 86400,
    last_seen_at: Math.floor(Date.now() / 1000) - 3600,
    ip: "198.51.100.10",
    user_agent: "Windows · Edge",
    location: "Beijing, CN",
  },
];

export default function SecurityCenter() {
  const [mfa, setMfa] = useState<MfaState | null>(null);
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [loadingMfa, setLoadingMfa] = useState(false);
  const [loadingSessions, setLoadingSessions] = useState(false);
  const [verifyCode, setVerifyCode] = useState("");
  const [showRecovery, setShowRecovery] = useState(false);

  const loadMfa = useCallback(async () => {
    setLoadingMfa(true);
    try {
      const res = await fetch("/api/security/mfa", { credentials: "include" });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setMfa({
        enabled: Boolean(data.enabled),
        secret: data.secret,
        otpauth_url: data.otpauth_url,
        otpauth_qr: data.otpauth_qr,
        recovery_codes: data.recovery_codes,
        last_used_at: data.last_used_at,
        enrolled_at: data.enrolled_at,
      });
    } catch (err: any) {
      toast.error(err?.message || "无法获取 MFA 状态，显示示例数据");
      setMfa(fallbackMfa);
    } finally {
      setLoadingMfa(false);
    }
  }, []);

  const loadSessions = useCallback(async () => {
    setLoadingSessions(true);
    try {
      const res = await fetch("/api/security/sessions", { credentials: "include" });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      if (!Array.isArray(data)) throw new Error("响应格式不正确");
      const mapped: SessionItem[] = data.map((item: any) => ({
        id: String(item.id ?? item.session_id ?? crypto.randomUUID()),
        created_at: Number(item.created_at ?? item.issued_at ?? Date.now() / 1000),
        last_seen_at: Number(item.last_seen_at ?? item.last_active_at ?? Date.now() / 1000),
        ip: item.ip,
        user_agent: item.user_agent ?? item.ua,
        location: item.location,
        current: Boolean(item.current ?? item.is_current),
      }));
      setSessions(mapped);
    } catch (err: any) {
      toast.error(err?.message || "无法加载会话，显示示例数据");
      setSessions(fallbackSessions);
    } finally {
      setLoadingSessions(false);
    }
  }, []);

  useEffect(() => {
    loadMfa();
    loadSessions();
  }, [loadMfa, loadSessions]);

  const hasPendingSetup = useMemo(() => {
    return Boolean(mfa && !mfa.enabled && (mfa.secret || mfa.otpauth_url));
  }, [mfa]);

  const startSetup = async () => {
    setLoadingMfa(true);
    try {
      const res = await fetch("/api/security/mfa/setup", { method: "POST", credentials: "include" });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setMfa({
        enabled: false,
        secret: data.secret,
        otpauth_url: data.otpauth_url,
        otpauth_qr: data.otpauth_qr,
        recovery_codes: data.recovery_codes,
      });
      toast.success("已生成密钥，请使用 TOTP 应用扫描");
    } catch (err: any) {
      toast.error(err?.message || "无法生成 TOTP 密钥，已使用示例数据");
      setMfa(fallbackMfa);
    } finally {
      setLoadingMfa(false);
    }
  };

  const confirmSetup = async () => {
    if (!verifyCode.trim()) {
      toast.error("请输入动态验证码");
      return;
    }
    setLoadingMfa(true);
    try {
      const res = await fetch("/api/security/mfa/activate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ code: verifyCode }),
      });
      if (!res.ok) throw new Error(await res.text());
      toast.success("已开启多因素认证");
      setVerifyCode("");
      await loadMfa();
    } catch (err: any) {
      toast.error(err?.message || "验证失败，功能可能待后端实现");
    } finally {
      setLoadingMfa(false);
    }
  };

  const disableMfa = async () => {
    if (!window.confirm("确定要关闭多因素认证吗？")) return;
    setLoadingMfa(true);
    try {
      const res = await fetch("/api/security/mfa", { method: "DELETE", credentials: "include" });
      if (!res.ok) throw new Error(await res.text());
      toast.success("已关闭 MFA");
      await loadMfa();
    } catch (err: any) {
      toast.error(err?.message || "关闭失败，功能可能待后端实现");
    } finally {
      setLoadingMfa(false);
    }
  };

  const revokeSession = async (id: string) => {
    if (!window.confirm("确定要退出该会话吗？")) return;
    try {
      const res = await fetch(`/api/security/sessions/${encodeURIComponent(id)}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (!res.ok) throw new Error(await res.text());
      toast.success("已注销指定会话");
      await loadSessions();
    } catch (err: any) {
      toast.error(err?.message || "无法注销会话 (可能待后端实现)");
    }
  };

  const revokeAll = async () => {
    if (!window.confirm("确定要退出除当前设备外的所有会话？")) return;
    try {
      const res = await fetch("/api/security/sessions", { method: "DELETE", credentials: "include" });
      if (!res.ok) throw new Error(await res.text());
      toast.success("已注销其他会话");
      await loadSessions();
    } catch (err: any) {
      toast.error(err?.message || "操作失败，功能可能待后端实现");
    }
  };

  const copyToClipboard = (value: string, label: string) => {
    navigator.clipboard
      .writeText(value)
      .then(() => toast.success(`${label} 已复制`))
      .catch(() => toast.error("复制失败"));
  };

  return (
    <div className="container py-10 space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>多因素认证 (MFA)</CardTitle>
          <CardDescription>为账户绑定基于时间的一次性密码 (TOTP)，推荐使用 Google Authenticator 或 1Password</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <div className="space-y-4">
            <div className="rounded-xl border border-border/60 bg-background/70 p-4">
              <div className="flex items-center gap-2 text-sm">
                <span className="font-semibold text-foreground">当前状态</span>
                <span
                  className={`rounded-full px-2 py-0.5 text-xs ${
                    mfa?.enabled ? "bg-emerald-500/10 text-emerald-600" : "bg-amber-500/10 text-amber-600"
                  }`}
                >
                  {mfa?.enabled ? "已开启" : hasPendingSetup ? "待激活" : "未开启"}
                </span>
              </div>
              {mfa?.enrolled_at && (
                <div className="mt-2 text-xs text-muted-foreground">
                  启用时间：{new Date(mfa.enrolled_at * 1000).toLocaleString()}
                </div>
              )}
              {mfa?.last_used_at && (
                <div className="text-xs text-muted-foreground">
                  最近使用：{new Date(mfa.last_used_at * 1000).toLocaleString()}
                </div>
              )}
            </div>

            {!mfa?.enabled && !hasPendingSetup && (
              <Button onClick={startSetup} disabled={loadingMfa}>
                {loadingMfa ? "处理中..." : "开始绑定 MFA"}
              </Button>
            )}

            {hasPendingSetup && (
              <div className="space-y-3">
                {mfa?.otpauth_qr && (
                  <div className="rounded-lg border border-border/60 bg-white p-3">
                    <Image
                      src={mfa.otpauth_qr}
                      alt="MFA QR 代码"
                      width={192}
                      height={192}
                      className="mx-auto h-48 w-48"
                      unoptimized
                    />
                  </div>
                )}
                <div className="text-sm text-foreground font-medium">步骤 1：在认证应用中添加账户</div>
                <div className="rounded-lg border border-dashed border-primary/40 bg-primary/5 p-3 text-xs font-mono text-primary">
                  {mfa?.otpauth_url}
                </div>
                {mfa?.secret && (
                  <div className="flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => copyToClipboard(mfa.secret!, "密钥")}>复制密钥</Button>
                    <Button variant="outline" size="sm" onClick={() => copyToClipboard(mfa.otpauth_url || "", "otpauth url")}>
                      复制 otpauth URL
                    </Button>
                  </div>
                )}
                <div className="space-y-2">
                  <div className="text-sm text-foreground font-medium">步骤 2：输入应用生成的 6 位动态码</div>
                  <div className="flex gap-2">
                    <Input
                      value={verifyCode}
                      onChange={(e) => setVerifyCode(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
                      placeholder="123456"
                      className="max-w-[160px] text-center text-lg tracking-[0.4em]"
                    />
                    <Button onClick={confirmSetup} disabled={loadingMfa}>
                      验证并开启
                    </Button>
                  </div>
                </div>
              </div>
            )}

            {mfa?.enabled && (
              <Button variant="destructive" onClick={disableMfa} disabled={loadingMfa}>
                关闭多因素认证
              </Button>
            )}
          </div>

          <div className="space-y-4">
            <div>
              <div className="text-sm font-semibold text-foreground">恢复代码</div>
              <div className="text-xs text-muted-foreground mt-1">
                当无法访问 TOTP 应用时，可使用恢复代码登录。每个代码仅能使用一次。
              </div>
            </div>
            <div className="rounded-xl border border-border/60 bg-background/70 p-4 text-sm">
              {mfa?.recovery_codes?.length ? (
                <div className="grid gap-2 text-center font-mono text-sm">
                  {(showRecovery ? mfa.recovery_codes : mfa.recovery_codes.map(() => "••••-••••")).map((code, idx) => (
                    <span key={idx}>{code}</span>
                  ))}
                </div>
              ) : (
                <div className="text-muted-foreground text-sm">启用 MFA 后将会生成恢复码。</div>
              )}
              {mfa?.recovery_codes?.length && (
                <div className="mt-3 flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => setShowRecovery((v) => !v)}>
                    {showRecovery ? "隐藏" : "显示"}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => copyToClipboard((mfa.recovery_codes || []).join("\n"), "恢复代码")}
                  >
                    导出
                  </Button>
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
          <div>
            <CardTitle>活跃会话</CardTitle>
            <CardDescription>监控所有已登录的设备、浏览器和 IP 地址，及时锁定可疑登录</CardDescription>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={loadSessions} disabled={loadingSessions}>
              {loadingSessions ? "加载中..." : "刷新"}
            </Button>
            <Button variant="destructive" size="sm" onClick={revokeAll}>
              退出其他会话
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-xl border border-border/60 bg-background/70">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[160px]">创建时间</TableHead>
                  <TableHead className="w-[160px]">最近活动</TableHead>
                  <TableHead>设备 / 浏览器</TableHead>
                  <TableHead className="w-[180px]">IP / 位置</TableHead>
                  <TableHead className="w-[120px]">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((session) => (
                  <TableRow key={session.id} className={session.current ? "bg-primary/5" : undefined}>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(session.created_at * 1000).toLocaleString()}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(session.last_seen_at * 1000).toLocaleString()}
                    </TableCell>
                    <TableCell>
                      <div className="text-sm text-foreground">{session.user_agent || "未知设备"}</div>
                      {session.current && <div className="text-xs text-emerald-600">当前设备</div>}
                    </TableCell>
                    <TableCell>
                      <div className="text-sm text-foreground">{session.ip || "-"}</div>
                      {session.location && (
                        <div className="text-xs text-muted-foreground">{session.location}</div>
                      )}
                    </TableCell>
                    <TableCell>
                      {!session.current && (
                        <Button variant="outline" size="sm" onClick={() => revokeSession(session.id)}>
                          退出
                        </Button>
                      )}
                      {session.current && <span className="text-xs text-muted-foreground">当前会话</span>}
                    </TableCell>
                  </TableRow>
                ))}
                {!sessions.length && !loadingSessions && (
                  <TableRow>
                    <TableCell colSpan={5} className="py-8 text-center text-sm text-muted-foreground">
                      暂无会话记录。
                    </TableCell>
                  </TableRow>
                )}
                {loadingSessions && (
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
