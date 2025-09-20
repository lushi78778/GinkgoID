"use client";

import React, { useCallback, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { DataTable } from "@/components/ui/data-table";
import type { ColumnDef } from "@tanstack/react-table";
import { confirm } from "@/components/ui/confirm";
import { toast } from "sonner";
import { api, apiJSON } from "@/lib/api";

interface PendingClient {
  client_id: string;
  client_name: string;
  owner_user_id: number;
  created_at: number;
}


/**
 * 管理端 - 客户端审批流页面
 * 展示所有待审批的客户端，支持审批通过和拒绝（需填写理由）。
 * 使用 shadcn/ui 组件，风格统一，体验现代。
 */
const AdminClientApprovals: React.FC = () => {
  const [pending, setPending] = useState<PendingClient[]>([]);
  const [loading, setLoading] = useState(false);
  const [rejecting, setRejecting] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);

  // 获取待审批客户端列表
  const fetchPending = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api("/api/admin/clients/pending");
      setPending(res);
    } catch (e: any) {
      toast.error("获取失败: " + (e.message || "无法获取待审批列表"));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchPending(); }, [fetchPending]);

  // 审批通过
  const handleApprove = async (client_id: string) => {
    const ok = await confirm({ title: '确认通过', content: `确定通过客户端 ${client_id} 的申请？` })
    if (!ok) return
    try {
      await api(`/api/admin/clients/${client_id}/approve`, { method: 'POST' });
      toast.success(`审批通过：客户端 ${client_id} 已通过`);
      fetchPending();
    } catch (e: any) {
      toast.error("审批未成功: " + (e.message || "操作失败"));
    }
  };

  // 打开拒绝理由对话框
  const openRejectDialog = (client_id: string) => {
    setRejecting(client_id);
    setRejectReason("");
    setDialogOpen(true);
  };

  // 提交拒绝
  // 提交拒绝
  const handleReject = async () => {
    if (!rejecting) return;
    if (!rejectReason.trim()) {
      toast.error("请填写拒绝原因");
      return;
    }
    try {
      await apiJSON(`/api/admin/clients/${rejecting}/reject`, { reason: rejectReason });
      toast.success(`已拒绝：客户端 ${rejecting} 已被拒绝`);
      setDialogOpen(false);
      setRejecting(null);
      setRejectReason("");
      fetchPending();
    } catch (e: any) {
      toast.error("拒绝未成功: " + (e.message || "操作失败"));
    }
  };

  const columns: ColumnDef<PendingClient>[] = [
    { accessorKey: 'client_id', header: '客户端ID' },
    { accessorKey: 'client_name', header: '名称' },
    { accessorKey: 'owner_user_id', header: '注册人ID' },
    { accessorKey: 'created_at', header: '注册时间', cell: ({ getValue }) => new Date((getValue<number>() || 0) * 1000).toLocaleString() },
    {
      id: 'actions',
      header: '操作',
      cell: ({ row }) => (
        <div className="space-x-2">
          <Button size="sm" onClick={() => handleApprove(row.original.client_id)}>通过</Button>
          <Button size="sm" variant="destructive" onClick={() => openRejectDialog(row.original.client_id)}>拒绝</Button>
        </div>
      )
    }
  ]

  return (
    <Card className="w-full max-w-4xl mx-auto mt-8 p-4">
      <h2 className="text-xl font-bold mb-4">待审批客户端</h2>
      <DataTable<PendingClient>
        columns={columns}
        data={pending}
        rowKey={(r)=>r.client_id}
        searchable
        searchPlaceholder="搜索客户端ID/名称"
        loading={loading}
      />
      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>拒绝理由</DialogTitle>
          </DialogHeader>
          <Input
            value={rejectReason}
            onChange={e => setRejectReason(e.target.value)}
            placeholder="请填写拒绝原因"
            className="mb-4"
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setDialogOpen(false)}>
              取消
            </Button>
            <Button variant="destructive" onClick={handleReject}>
              确认拒绝
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
};

export default AdminClientApprovals;
