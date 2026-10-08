// Minimal hash router: #/sites/3 -> { path: '/sites/3', parts: ['sites','3'] }
function parse() {
  const h = location.hash.replace(/^#/, '') || '/'
  const [path, qs] = h.split('?')
  return { path, parts: path.split('/').filter(Boolean), query: new URLSearchParams(qs || '') }
}
export const route = $state(parse())
window.addEventListener('hashchange', () => Object.assign(route, parse()))
export function go(path) { location.hash = '#' + path }
