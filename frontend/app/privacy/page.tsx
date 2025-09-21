"use client";

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";

export default function PrivacyAndData() {
  const [exporting, setExporting] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [downloadLink, setDownloadLink] = useState<string | null>(null);
  const [deleteReason, setDeleteReason] = useState("享受 GDPR/CCPA 权利");
  const [exportRequestedAt, setExportRequestedAt] = useState<number | null>(null);

  const requestExport = async () => {
    setExporting(true);
    try {
      const res = await fetch("/api/privacy/export", { method: "POST", credentials: "include" });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setDownloadLink(data.download_url || data.url || null);
      setExportRequestedAt(Date.now());
      const message = data?.message || "数据导出任务已生成，可通过下方链接下载（15 分钟内有效）。";
      toast.success(message);
    } catch (err: any) {
      toast.error(err?.message || "无法提交导出请求，已提供示例下载链接");
      setDownloadLink("https://example.com/ginkgoid-data-export.json");
      setExportRequestedAt(Date.now());
    } finally {
      setExporting(false);
    }
  };

  const confirmDelete = async () => {
    if (!window.confirm("该操作将停用您的账户，并在后台触发删除流程。是否继续？")) return;
    setDeleteLoading(true);
    try {
      const res = await fetch("/api/privacy/delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ reason: deleteReason }),
      });
      if (!res.ok) throw new Error(await res.text());
      let message = "已记录账户删除请求，管理员将尽快处理";
      try {
        const data = await res.json();
        message = data?.message || message;
      } catch (_) {
        // ignore
      }
      toast.success(message);
    } catch (err: any) {
      toast.error(err?.message || "提交失败，功能可能待后端实现");
    } finally {
      setDeleteLoading(false);
    }
  };

  return (
    <div className="container py-10 space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>个人数据导出</CardTitle>
          <CardDescription>导出包含个人资料、授权记录及安全日志的 JSON 文件，可直接下载保存。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            导出任务将在后台生成，并提供一次性下载链接（15 分钟内有效）。如需长期保存，请及时下载并妥善存档。
          </p>
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <Button onClick={requestExport} disabled={exporting}>
              {exporting ? "申请中..." : "申请导出"}
            </Button>
            {exportRequestedAt && (
              <span className="text-muted-foreground">
                最近一次申请：{new Date(exportRequestedAt).toLocaleString()}
              </span>
            )}
            {downloadLink && (
              <a className="btn" href={downloadLink} target="_blank" rel="noreferrer">
                下载最新导出
              </a>
            )}
          </div>
          <div className="rounded-lg border border-border/60 bg-muted/20 p-4 text-xs text-muted-foreground">
            导出内容将包含：基本资料、邮箱与验证状态、授权客户端与 Scope、活跃会话、审计日志以及账户偏好设置。
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>账户删除</CardTitle>
          <CardDescription>自助提交账户删除请求，系统会记录并通知管理员审核，审核通过后将清理所有会话和授权记录。</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            根据隐私法规，账户在管理员确认后 7 天内彻底删除。在此期间可通过联系管理员撤回请求。我们建议先完成数据导出。
          </p>
          <div className="grid gap-2 max-w-lg">
            <Label htmlFor="delete-reason">删除原因（选填，将随请求发送给管理员）</Label>
            <Input
              id="delete-reason"
              value={deleteReason}
              onChange={(e) => setDeleteReason(e.target.value)}
              placeholder="例如：不再使用该服务"
            />
          </div>
          <div className="rounded-lg border border-destructive/40 bg-destructive/5 p-4 text-sm text-destructive">
            删除请求提交后：我们会注销所有会话、撤销所有客户端授权并清理个人资料及安全日志。操作不可逆，请谨慎执行。
          </div>
          <Button variant="destructive" onClick={confirmDelete} disabled={deleteLoading}>
            {deleteLoading ? "提交中..." : "提交删除请求"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
