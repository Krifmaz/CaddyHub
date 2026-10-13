// Thin JSON client for the Caddymium API. The CSRF token comes from /api/me
// (or login) and is sent on every state-changing request.
let csrf = ''
export function setCSRF(t) { csrf = t || '' }

export class APIError extends Error {
  constructor(status, message) { super(message); this.status = status }
}

let onUnauthorized = () => {}
export function handleUnauthorized(fn) { onUnauthorized = fn }

async function req(method, path, body) {
  const opts = { method, headers: {}, credentials: 'same-origin' }
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json'
    opts.body = JSON.stringify(body)
  }
  if (method !== 'GET') opts.headers['X-CSRF-Token'] = csrf
  const res = await fetch('/api' + path, opts)
  const text = await res.text()
  let data = null
  try { data = text ? JSON.parse(text) : null } catch { data = text }
  if (!res.ok) {
    const msg = (data && data.error) || res.statusText || 'request failed'
    if (res.status === 401 && path !== '/login' && path !== '/login/totp') onUnauthorized()
    throw new APIError(res.status, msg)
  }
  return data
}

export const api = {
  get: (p) => req('GET', p),
  post: (p, b) => req('POST', p, b ?? {}),
  put: (p, b) => req('PUT', p, b),
  del: (p) => req('DELETE', p),
}
