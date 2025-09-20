"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export default function OidcDocs() {
  const [height, setHeight] = useState(720);

  useEffect(() => {
    const update = () => {
      setHeight(Math.max(window.innerHeight - 220, 420));
    };
    update();
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, []);

  return (
    <div className="container py-10 space-y-6">
      <Card>
        <CardHeader className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
          <div>
            <CardTitle>OIDC 集成指南</CardTitle>
            <CardDescription>内嵌平台官方文档，涵盖 Discovery、授权流程、Token 校验、回调示例等内容</CardDescription>
          </div>
          <div className="flex gap-2 text-sm">
            <Button variant="outline" size="sm" asChild>
              <a href="/stoplight.html" target="_blank" rel="noreferrer">
                在新窗口打开
              </a>
            </Button>
            <Button variant="outline" size="sm" asChild>
              <a href="/.well-known/openid-configuration" target="_blank" rel="noreferrer">
                查看 Discovery
              </a>
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <iframe
            title="GinkgoID OIDC 文档"
            src="/stoplight.html"
            className="w-full rounded-xl border border-border"
            style={{ height }}
          />
        </CardContent>
      </Card>
    </div>
  );
}
