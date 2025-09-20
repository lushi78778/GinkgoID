"use client";

import { useEffect } from 'react'
import { initTheme } from '@/lib/theme'
import { AuthProvider } from '@/lib/auth'
import { SidebarLayout } from '@/components/layout/SidebarLayout'
import { Toaster } from 'sonner'

export default function Providers({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    initTheme()
    const id = 'ginkgo-tailwind-css'
    if (!document.getElementById(id)) {
      const link = document.createElement('link')
      link.id = id
      link.rel = 'stylesheet'
      link.href = '/app.css'
      document.head.appendChild(link)
    }
    const inlineId = 'ginkgo-inline-style'
    if (!document.getElementById(inlineId)) {
      const style = document.createElement('style')
      style.id = inlineId
      style.textContent = `
        body { background: #f6f7fb; color: #0f172a; }
        .card { background: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; color: #0f172a; }
        .btn { background: #6366f1; color: #ffffff; border-radius: 8px; padding: 8px 16px; display: inline-flex; align-items: center; gap: 6px; text-decoration: none; font-weight: 600; }
        .btn:hover { background: #4f46e5; }
      `
      document.head.appendChild(style)
    }
  }, [])

  return (
    <AuthProvider>
      <SidebarLayout>
        {children}
        <Toaster richColors position="top-right" />
      </SidebarLayout>
    </AuthProvider>
  )
}
