"use client";

import { useEffect, useState } from "react";
import Image from "next/image";
import { useAuth } from "@/lib/auth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";

interface BrandingSettings {
  primary_color: string;
  accent_color: string;
  background_color: string;
  logo_url?: string;
  dark_mode_logo_url?: string;
  email_subject?: string;
  email_body?: string;
}

const fallbackBranding: BrandingSettings = {
  primary_color: "#6366F1",
  accent_color: "#10B981",
  background_color: "#F6F7FB",
  email_subject: "欢迎加入 GinkgoID 平台",
  email_body: "您好 {{user.name}}，欢迎使用 GinkgoID。点击下方按钮完成设置。",
};

export default function BrandingPage() {
  const { me } = useAuth();
  const isAdmin = Boolean(me?.is_admin);

  const [branding, setBranding] = useState<BrandingSettings>(fallbackBranding);
  const [previewLogo, setPreviewLogo] = useState<string | null>(null);
  const [previewDarkLogo, setPreviewDarkLogo] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!isAdmin) return;
    (async () => {
      try {
        const res = await fetch("/api/admin/branding", { credentials: "include" });
        if (!res.ok) throw new Error(await res.text());
        const data = await res.json();
        setBranding({ ...fallbackBranding, ...data });
        setPreviewLogo(data.logo_url || null);
        setPreviewDarkLogo(data.dark_mode_logo_url || null);
      } catch (err: any) {
        toast.error(err?.message || "无法加载品牌配置，展示示例数据");
      }
    })();
  }, [isAdmin]);

  const handleLogoUpload = (file: File, setter: (value: string | null) => void, key: "logo_url" | "dark_mode_logo_url") => {
    const reader = new FileReader();
    reader.onload = () => {
      const url = reader.result as string;
      setter(url);
      setBranding((prev) => ({ ...prev, [key]: url }));
    };
    reader.readAsDataURL(file);
  };

  const saveBranding = async () => {
    setSaving(true);
    try {
      const res = await fetch("/api/admin/branding", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(branding),
      });
      if (!res.ok) throw new Error(await res.text());
      toast.success("品牌设置已保存");
    } catch (err: any) {
      toast.error(err?.message || "保存失败 (后端可能未实现) ");
    } finally {
      setSaving(false);
    }
  };

  if (!isAdmin) {
    return (
      <div className="container py-10">
        <Card>
          <CardHeader>
            <CardTitle>品牌与外观</CardTitle>
            <CardDescription>需要管理员权限</CardDescription>
          </CardHeader>
          <CardContent>
            <a className="btn" href={`/login?next=${encodeURIComponent("/admin/branding")}`}>
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
        <CardHeader>
          <CardTitle>主题色与 Logo</CardTitle>
          <CardDescription>定制控制台的品牌色和 Logo，所有终端用户与开发者入口将应用该配置</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-3">
            <div className="grid gap-2">
              <Label>主色 (按钮/高亮)</Label>
              <Input
                type="color"
                value={branding.primary_color}
                onChange={(e) => setBranding({ ...branding, primary_color: e.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label>强调色 (成功/状态)</Label>
              <Input
                type="color"
                value={branding.accent_color}
                onChange={(e) => setBranding({ ...branding, accent_color: e.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label>背景色</Label>
              <Input
                type="color"
                value={branding.background_color}
                onChange={(e) => setBranding({ ...branding, background_color: e.target.value })}
              />
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>浅色模式 Logo</Label>
              <Input
                type="file"
                accept="image/png,image/svg+xml"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) handleLogoUpload(file, setPreviewLogo, "logo_url");
                }}
              />
              {previewLogo && (
                <Image
                  src={previewLogo}
                  alt="Light Logo"
                  className="h-16 w-auto rounded border"
                  height={64}
                  width={200}
                  unoptimized
                />
              )}
            </div>
            <div className="space-y-2">
              <Label>深色模式 Logo</Label>
              <Input
                type="file"
                accept="image/png,image/svg+xml"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) handleLogoUpload(file, setPreviewDarkLogo, "dark_mode_logo_url");
                }}
              />
              {previewDarkLogo && (
                <Image
                  src={previewDarkLogo}
                  alt="Dark Logo"
                  className="h-16 w-auto rounded border bg-slate-900 p-2"
                  height={64}
                  width={200}
                  unoptimized
                />
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>邮件模板</CardTitle>
          <CardDescription>自定义平台发送的欢迎邮件、密码重置邮件等模板内容，支持 Handlebars 变量</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2">
            <Label>默认主题</Label>
            <Input
              value={branding.email_subject}
              onChange={(e) => setBranding({ ...branding, email_subject: e.target.value })}
            />
          </div>
          <div className="grid gap-2">
            <Label>正文</Label>
            <textarea
              value={branding.email_body}
              onChange={(e) => setBranding({ ...branding, email_body: e.target.value })}
              className="min-h-[180px] w-full rounded-md border border-border bg-background px-3 py-2 text-sm leading-relaxed"
              placeholder="使用 {{user.name}}、{{action_url}} 等变量"
            />
          </div>
          <div className="rounded-xl border border-border/60 bg-muted/30 p-4 text-sm">
            <div className="text-xs uppercase text-muted-foreground">实时预览</div>
            <div
              className="mt-2 rounded-md border border-border bg-white p-4 text-sm text-slate-800"
              style={{ borderTopColor: branding.primary_color, borderTopWidth: 3 }}
            >
              <div className="text-lg font-semibold" style={{ color: branding.primary_color }}>
                {branding.email_subject}
              </div>
              <p className="mt-3 whitespace-pre-line">
                {branding.email_body?.replace(/\{\{user.name\}\}/g, "张三").replace(/\{\{action_url\}\}/g, "https://example.com/verify")}
              </p>
              <Button className="mt-4" style={{ backgroundColor: branding.primary_color }}>
                前往设置
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button onClick={saveBranding} disabled={saving}>
          {saving ? "保存中..." : "保存品牌配置"}
        </Button>
      </div>
    </div>
  );
}
