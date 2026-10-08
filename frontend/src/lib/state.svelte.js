import { api } from './api.js'

// Global UI state (Svelte 5 runes in a shared module).
export const app = $state({
  me: null,        // /api/me response
  status: null,    // /api/status
  meta: null,      // /api/meta
  toasts: [],
})

let nextToast = 1
export function toast(message, kind = 'ok', ms = 4000) {
  const id = nextToast++
  app.toasts.push({ id, message, kind })
  setTimeout(() => { app.toasts = app.toasts.filter((t) => t.id !== id) }, ms)
}
export function toastErr(e) { toast(e?.message || String(e), 'err', 7000) }

export async function refreshStatus() {
  try { app.status = await api.get('/status') } catch { /* shown elsewhere */ }
}
export async function loadMeta() {
  if (!app.meta) app.meta = await api.get('/meta')
  return app.meta
}

export const can = {
  edit: () => ['admin', 'editor'].includes(app.me?.user?.role),
  admin: () => app.me?.user?.role === 'admin',
}
