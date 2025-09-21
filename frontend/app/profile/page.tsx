"use client";

import { useEffect, useMemo, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useAuth } from "@/lib/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";

const profileSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, "姓名必填")
    .max(60, "姓名长度不能超过 60 字"),
  email: z
    .string()
    .trim()
    .email("邮箱格式不正确")
    .max(120, "邮箱长度不能超过 120 字"),
  marketing: z.boolean().optional(),
});

const passwordSchema = z
  .object({
    oldPassword: z.string().min(1, "请填写旧口令"),
    newPassword: z
      .string()
      .min(8, "新口令至少 8 位")
      .regex(/[a-z]/i, "需包含字母")
      .regex(/[0-9]/, "需包含数字"),
    confirmPassword: z.string().min(1, "请再次输入新口令"),
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    path: ["confirmPassword"],
    message: "两次输入的口令不一致",
  });

export default function Profile() {
  const { me, refresh } = useAuth();
  const [loading, setLoading] = useState(true);
  const [emailVerified, setEmailVerified] = useState<boolean | null>(null);
  const [emailStatus, setEmailStatus] = useState<string>("");
  const [pendingEmail, setPendingEmail] = useState<string | null>(null);
  const [mfaEnabled, setMfaEnabled] = useState<boolean | null>(null);
  const [marketingOptIn, setMarketingOptIn] = useState(false);
  const [savingMarketing, setSavingMarketing] = useState(false);
  const [sendingVerification, setSendingVerification] = useState(false);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting, isDirty },
  } = useForm<z.infer<typeof profileSchema>>({ resolver: zodResolver(profileSchema) });

  const {
    register: registerPwd,
    handleSubmit: handlePasswordSubmit,
    reset: resetPassword,
    formState: { errors: passwordErrors, isSubmitting: passwordSaving },
  } = useForm<z.infer<typeof passwordSchema>>({ resolver: zodResolver(passwordSchema) });

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const res = await fetch("/api/me", { credentials: "include" });
        if (!res.ok) throw new Error(await res.text());
        const data = await res.json();
        reset({
          name: data.name || "",
          email: data.email || "",
          marketing: Boolean(data.marketing_opt_in),
        });
        setEmailVerified(
          typeof data.email_verified === "boolean"
            ? data.email_verified
            : data.email_verified === "1"
        );
        setPendingEmail(data.pending_email ?? null);
        setMfaEnabled(typeof data.mfa_enabled === "boolean" ? data.mfa_enabled : null);
        setMarketingOptIn(Boolean(data.marketing_opt_in));
        setEmailStatus(data.email_status_message || "");
      } catch (err: any) {
        toast.error(err?.message || "无法加载个人资料");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [reset]);

  const emailBadge = useMemo(() => {
    if (emailVerified === true) return { label: "已验证", tone: "bg-emerald-500/10 text-emerald-600" };
    if (emailVerified === false) return { label: "未验证", tone: "bg-amber-500/10 text-amber-600" };
    return { label: "未知", tone: "bg-slate-500/10 text-slate-600" };
  }, [emailVerified]);

  const onSubmit = handleSubmit(async (values) => {
    try {
      const res = await fetch("/api/me", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ name: values.name, email: values.email }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      reset({ name: data.name || "", email: data.email || "", marketing: marketingOptIn });
      toast.success("个人资料已保存");
      if (refresh) await refresh();
    } catch (err: any) {
      toast.error(err?.message || "保存失败");
    }
  });

  const onPasswordSubmit = handlePasswordSubmit(async (values) => {
    try {
      const res = await fetch("/api/me/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ oldPassword: values.oldPassword, newPassword: values.newPassword }),
      });
      if (res.status !== 204) throw new Error(await res.text());
      toast.success("口令已更新");
      resetPassword({ oldPassword: "", newPassword: "", confirmPassword: "" });
    } catch (err: any) {
      toast.error(err?.message || "口令更新失败");
    }
  });

  const sendVerification = async () => {
    setSendingVerification(true);
    try {
      const res = await fetch("/api/me/email/verify", { method: "POST", credentials: "include" });
      if (res.status === 501) {
        let message = "系统未启用邮箱发送，请联系管理员";
        try {
          const data = await res.json();
          message = data?.message || data?.error || message;
        } catch (_) {
          // ignore json parse failure
        }
        setEmailStatus(message);
        toast.error(message);
        return;
      }
      if (!res.ok) throw new Error(await res.text());
      toast.success("验证邮件已发送，请查看收件箱");
      setEmailStatus("已发送验证邮件");
    } catch (err: any) {
      toast.error(err?.message || "无法发送验证邮件 (可能尚未实现后端接口) ");
    } finally {
      setSendingVerification(false);
    }
  };

  const refreshEmailStatus = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/me", { credentials: "include" });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setEmailVerified(
        typeof data.email_verified === "boolean" ? data.email_verified : data.email_verified === "1"
      );
      setPendingEmail(data.pending_email ?? null);
      setEmailStatus(data.email_status_message || "");
    } catch (err: any) {
      toast.error(err?.message || "无法刷新邮箱状态");
    } finally {
      setLoading(false);
    }
  };

  const toggleMarketing = async (checked: boolean) => {
    setMarketingOptIn(checked);
    setSavingMarketing(true);
    try {
      const res = await fetch("/api/me/preferences", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ marketing_opt_in: checked }),
      });
      if (!res.ok) throw new Error(await res.text());
      toast.success("偏好设置已更新");
    } catch (err: any) {
      toast.error(err?.message || "无法更新偏好 (后端可能尚未支持)");
      setMarketingOptIn(!checked);
    } finally {
      setSavingMarketing(false);
    }
  };

  if (!me) {
    return (
      <div className="container py-10">
        <Card>
          <CardHeader>
            <CardTitle>个人资料</CardTitle>
            <CardDescription>请先登录以查看和管理个人资料</CardDescription>
          </CardHeader>
          <CardContent>
            <a className="btn" href={`/login?next=${encodeURIComponent("/profile")}`}>
              去登录
            </a>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container py-10 space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>基础信息</CardTitle>
          <CardDescription>
            管理您的姓名与联系人邮箱。用户 ID：<span className="font-mono">{me.id}</span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={onSubmit} className="grid gap-4 max-w-xl">
            <div className="grid gap-2">
              <Label htmlFor="name">显示名称</Label>
              <Input id="name" placeholder="姓名" {...register("name")} />
              {errors.name && <span className="text-xs text-red-500">{errors.name.message}</span>}
            </div>
            <div className="grid gap-2">
              <Label htmlFor="email">邮箱</Label>
              <Input id="email" type="email" placeholder="name@example.com" {...register("email")} />
              {errors.email && <span className="text-xs text-red-500">{errors.email.message}</span>}
            </div>
            <div className="flex items-center gap-3 text-sm text-muted-foreground">
              <span className={`rounded-full px-2 py-0.5 text-xs ${emailBadge.tone}`}>{emailBadge.label}</span>
              {pendingEmail && <span>新邮箱待验证：{pendingEmail}</span>}
            </div>
            <div className="flex gap-3">
              <Button type="submit" disabled={isSubmitting || !isDirty}>
                {isSubmitting ? "保存中..." : "保存修改"}
              </Button>
              <Button type="button" variant="outline" onClick={refreshEmailStatus} disabled={loading}>
                刷新状态
              </Button>
              <Button type="button" variant="ghost" onClick={sendVerification} disabled={sendingVerification}>
                {sendingVerification ? "发送中..." : "发送验证邮件"}
              </Button>
            </div>
            {emailStatus && <p className="text-xs text-muted-foreground">{emailStatus}</p>}
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>密码与安全</CardTitle>
          <CardDescription>修改登录口令，建议开启 MFA 以提升安全性</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-6 md:grid-cols-2">
          <form onSubmit={onPasswordSubmit} className="grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="oldPassword">旧口令</Label>
              <Input id="oldPassword" type="password" autoComplete="current-password" {...registerPwd("oldPassword")} />
              {passwordErrors.oldPassword && (
                <span className="text-xs text-red-500">{passwordErrors.oldPassword.message}</span>
              )}
            </div>
            <div className="grid gap-2">
              <Label htmlFor="newPassword">新口令</Label>
              <Input id="newPassword" type="password" autoComplete="new-password" {...registerPwd("newPassword")} />
              {passwordErrors.newPassword && (
                <span className="text-xs text-red-500">{passwordErrors.newPassword.message}</span>
              )}
            </div>
            <div className="grid gap-2">
              <Label htmlFor="confirmPassword">确认新口令</Label>
              <Input id="confirmPassword" type="password" autoComplete="new-password" {...registerPwd("confirmPassword")} />
              {passwordErrors.confirmPassword && (
                <span className="text-xs text-red-500">{passwordErrors.confirmPassword.message}</span>
              )}
            </div>
            <Button type="submit" disabled={passwordSaving}>
              {passwordSaving ? "保存中..." : "更新口令"}
            </Button>
          </form>
          <div className="rounded-xl border border-border/60 bg-background/70 p-4 text-sm text-muted-foreground">
            <div className="flex items-center gap-2 text-foreground">
              <span className="font-semibold">多因素认证</span>
              <span className={`rounded-full px-2 py-0.5 text-xs ${mfaEnabled ? "bg-emerald-500/10 text-emerald-600" : "bg-amber-500/10 text-amber-600"}`}>
                {mfaEnabled ? "已开启" : "未开启"}
              </span>
            </div>
            <p className="mt-2">
              MFA 管理入口已移动至“安全中心”。请前往该页面绑定 TOTP 应用、下载恢复码，并管理活跃会话。
            </p>
            <a className="btn mt-3 w-fit" href="/security">
              前往安全中心
            </a>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>通知偏好</CardTitle>
          <CardDescription>订阅安全提醒、登录通知以及产品公告</CardDescription>
        </CardHeader>
        <CardContent className="flex items-center justify-between rounded-lg border border-border/60 bg-muted/20 px-4 py-3">
          <div>
            <div className="font-medium">接收产品与安全更新</div>
            <div className="text-sm text-muted-foreground">
              包含登录安全提醒、重要策略变更与产品能力更新。
            </div>
          </div>
          <Switch checked={marketingOptIn} disabled={savingMarketing} onCheckedChange={toggleMarketing} />
        </CardContent>
      </Card>
    </div>
  );
}
