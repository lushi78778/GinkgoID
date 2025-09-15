export type Json = Record<string, any>

export async function api<T = any>(input: RequestInfo, init: RequestInit = {}): Promise<T> {
  const opts: RequestInit = {
    credentials: 'include',
    headers: { 'Accept': 'application/json', ...(init.headers || {}) },
    ...init,
  }
  const res = await fetch(input, opts)
  if (res.status === 401) {
    // redirect to server login with next back to current SPA path
    const next = encodeURIComponent(window.location.pathname + window.location.search)
    window.location.href = `/login?next=${next}`
    throw new Error('unauthorized')
  }
  const text = await res.text()
  const ct = res.headers.get('Content-Type') || ''
  let data: any = text
  if (ct.includes('application/json')) {
    try { data = JSON.parse(text) } catch { /* ignore */ }
  }
  if (!res.ok) {
    const msg = (data && (data.error || data.message)) || res.statusText
    throw new Error(typeof msg === 'string' ? msg : JSON.stringify(data))
  }
  return data as T
}

export async function apiJSON<T = any>(input: string, body: any, init: RequestInit = {}): Promise<T> {
  return api<T>(input, {
    method: init.method || 'POST',
    headers: { 'Content-Type': 'application/json', ...(init.headers || {}) },
    body: JSON.stringify(body),
  })
}

