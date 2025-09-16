import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { initTheme } from './lib/theme'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import Profile from './pages/Profile.tsx'
import AdminUsers from './pages/AdminUsers.tsx'
import Dashboard from './pages/Dashboard.tsx'
import { AuthProvider } from './lib/auth'
import Clients from './pages/Clients'
import Callback from './pages/Callback'
import AuthorizedApps from './pages/AuthorizedApps'
import AdminClientApprovals from './pages/AdminClientApprovals'
import AdminLogs from './pages/AdminLogs'

const router = createBrowserRouter([
  { path: '/app', element: <App />, children: [
    { index: true, element: <Dashboard /> },
    { path: 'profile', element: <Profile /> },
    { path: 'authorized', element: <AuthorizedApps /> },
    { path: 'clients', element: <Clients /> },
    { path: 'cb', element: <Callback /> },
    { path: 'admin/users', element: <AdminUsers /> },
    { path: 'admin/approvals', element: <AdminClientApprovals /> },
    { path: 'admin/logs', element: <AdminLogs /> },
  ]},
])

initTheme()
createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthProvider>
      <RouterProvider router={router} />
    </AuthProvider>
  </StrictMode>,
)
