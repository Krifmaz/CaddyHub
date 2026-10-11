export function ago(ts) {
  if (!ts) return ''
  const s = (Date.now() - new Date(ts).getTime()) / 1000
  if (s < 60) return 'just now'
  if (s < 3600) return Math.floor(s / 60) + ' min ago'
  if (s < 86400) return Math.floor(s / 3600) + ' h ago'
  return new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}
export function when(ts) { return ts ? new Date(ts).toLocaleString() : '' }
export const kindLabel = { proxy: 'Reverse proxy', static: 'File server', redirect: 'Redirect', respond: 'Static response', forward_proxy: 'Forward proxy', none: 'Custom (raw)' }
export function clone(o) { return JSON.parse(JSON.stringify(o)) }
export function download(name, text) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(a.href), 1000)
}
