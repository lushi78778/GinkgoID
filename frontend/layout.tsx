import type { Metadata } from 'next'
import Providers from '@/components/providers'

export const metadata: Metadata = {
  title: 'GinkgoID 控制台',
  description: 'GinkgoID 自托管 OpenID Provider 控制台',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="zh-CN">
      <body className="min-h-screen bg-background text-foreground">
        <Providers>{children}</Providers>
      </body>
    </html>
  )
}
