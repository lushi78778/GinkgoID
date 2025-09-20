import type { Metadata } from 'next'
import type { ReactNode } from 'react'

import Providers from '@/components/providers'
import '@/globals.css'

export const metadata: Metadata = {
  title: 'GinkgoID 控制台',
  description: 'GinkgoID 自托管 OpenID Provider 控制台',
}

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="zh-CN">
      <body className="min-h-screen bg-background text-foreground">
        <Providers>{children}</Providers>
      </body>
    </html>
  )
}
