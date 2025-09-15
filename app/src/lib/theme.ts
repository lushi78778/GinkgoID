export type ThemeMode = 'light' | 'dark' | 'system'

const KEY = 'ginkgo-theme'

export function applyTheme(mode: ThemeMode) {
  const root = document.documentElement
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
  const dark = mode === 'dark' || (mode === 'system' && prefersDark)
  root.classList.toggle('dark', dark)
}

export function initTheme() {
  const saved = (localStorage.getItem(KEY) as ThemeMode) || 'system'
  applyTheme(saved)
  if (saved === 'system') {
    const mql = window.matchMedia('(prefers-color-scheme: dark)')
    const handler = () => applyTheme('system')
    try { mql.addEventListener('change', handler) } catch { mql.addListener(handler) }
  }
}

export function getTheme(): ThemeMode {
  return ((localStorage.getItem(KEY) as ThemeMode) || 'system')
}

export function setTheme(mode: ThemeMode) {
  localStorage.setItem(KEY, mode)
  applyTheme(mode)
}

