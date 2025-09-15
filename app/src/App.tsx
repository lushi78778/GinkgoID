import { Outlet } from 'react-router-dom'
import { Toaster } from 'sonner'
import { SidebarLayout } from '@/components/layout/SidebarLayout'

export default function App() {
  return (
    <SidebarLayout>
      <Outlet />
      <Toaster richColors position="top-right" />
    </SidebarLayout>
  )
}
