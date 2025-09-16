
import React, { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
// 兼容 shadcn/ui 的 toast 组件导入
// 兼容本地 api 封装（无默认导出）
import { api, apiJSON } from "../lib/api";

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
  // 获取待审批客户端列表
  const fetchPending = async () => {
    setLoading(true);
    try {
      const res = await api("/api/admin/clients/pending");
      setPending(res);
    } catch (e: any) {
      alert("获取失败: " + (e.message || "无法获取待审批列表"));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPending();
  }, []);

  // 审批通过
  // 审批通过
  const handleApprove = async (client_id: string) => {
    try {
      await api(`/api/admin/clients/${client_id}/approve`, { method: 'POST' });
  alert(`审批通过：客户端 ${client_id} 已通过`);
      fetchPending();
    } catch (e: any) {
      alert("审批未成功: " + (e.message || "操作失败"));
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
      alert("请填写拒绝原因");
      return;
    }
    try {
      await apiJSON(`/api/admin/clients/${rejecting}/reject`, { reason: rejectReason });
  alert(`已拒绝：客户端 ${rejecting} 已被拒绝`);
      setDialogOpen(false);
      setRejecting(null);
      setRejectReason("");
      fetchPending();
    } catch (e: any) {
      alert("拒绝未成功: " + (e.message || "操作失败"));
    }
  };


  return (
    <Card className="w-full max-w-4xl mx-auto mt-8">
      <h2 className="text-xl font-bold mb-4">待审批客户端</h2>
      <Table>
        <thead>
          <tr>
            <th>客户端ID</th>
            <th>名称</th>
            <th>注册人ID</th>
            <th>注册时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {pending.length === 0 && !loading && (
            <tr>
              <td colSpan={5} className="text-center text-muted-foreground py-8">暂无待审批客户端</td>
            </tr>
          )}
          {pending.map((cl) => (
            <tr key={cl.client_id}>
              <td>{cl.client_id}</td>
              <td>{cl.client_name}</td>
              <td>{cl.owner_user_id}</td>
              <td>{new Date(cl.created_at * 1000).toLocaleString()}</td>
              <td>
                <Button size="sm" className="mr-2" onClick={() => handleApprove(cl.client_id)}>
                  通过
                </Button>
                <Button size="sm" variant="destructive" onClick={() => openRejectDialog(cl.client_id)}>
                  拒绝
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </Table>
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
