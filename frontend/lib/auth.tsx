"use client";

import React, { createContext, useContext, useEffect, useMemo, useState } from 'react'
import { api } from './api'

export type Me = { id: number; username: string; name?: string; email?: string; is_admin?: boolean; is_dev?: boolean }

type AuthState = {
  me: Me | null
  loading: boolean
  refresh: () => Promise<void>
  logout: () => Promise<void>
}

const AuthCtx = createContext<AuthState | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [me, setMe] = useState<Me | null>(null)
  const [loading, setLoading] = useState(true)

  const refresh = async () => {
    try {
      const data = await api<Me>('/api/me')
      setMe(data)
    } catch {
      setMe(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { refresh() }, [])

  const logout = async () => {
    await fetch('/logout', { credentials: 'include' })
    window.location.href = '/'
  }

  const value = useMemo(() => ({ me, loading, refresh, logout }), [me, loading])
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthCtx)
  if (!ctx) {
    return {
      me: null,
      loading: true,
      refresh: async () => {},
      logout: async () => {},
    }
  }
  return ctx
}
