// Base domains the user works with, for the hostname picker: domains from
// Domains & DNS, the default domain, and the base of every existing site host.
const isIP = (h) => /^[\d.]+$/.test(h) || h.includes(':')

export function baseDomain(h) {
  h = (h || '').toLowerCase().replace(/^\*\./, '')
  if (!h.includes('.') || isIP(h) || h.endsWith('.localhost') || h === 'localhost') return ''
  const parts = h.split('.')
  return parts.length <= 2 ? h : parts.slice(1).join('.')
}

export function knownDomains(domains = [], sites = [], def = '') {
  const set = new Set()
  if (def) set.add(def.toLowerCase())
  for (const d of domains) if (d.name) set.add(d.name.toLowerCase())
  for (const s of sites) for (const h of s.hosts || []) { const b = baseDomain(h); if (b) set.add(b) }
  return [...set].sort((a, b) => (a === def ? -1 : b === def ? 1 : a.localeCompare(b)))
}

// Split a hostname into subdomain + one of the known domains (longest match).
export function splitHost(host, list) {
  host = (host || '').toLowerCase().trim()
  let best = ''
  for (const d of list) if ((host === d || host.endsWith('.' + d)) && d.length > best.length) best = d
  if (!best) return { custom: true, sub: '', domain: '', full: host }
  return { custom: false, sub: host === best ? '' : host.slice(0, -best.length - 1), domain: best, full: host }
}

export function joinHost(r) {
  if (r.custom) return (r.full || '').trim().toLowerCase()
  const sub = (r.sub || '').trim().toLowerCase().replace(/\.$/, '')
  if (!r.domain) return sub
  return sub ? `${sub}.${r.domain}` : r.domain
}
