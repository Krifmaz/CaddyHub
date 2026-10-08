// Light / dark / system theme, persisted per browser.
const KEY = 'caddyhub-theme'
const mq = matchMedia('(prefers-color-scheme: dark)')

function read() {
  try { return localStorage.getItem(KEY) || 'system' } catch { return 'system' }
}
export const theme = $state({ choice: read() })

function apply() {
  const t = theme.choice === 'system' ? (mq.matches ? 'dark' : 'light') : theme.choice
  document.documentElement.dataset.theme = t
}
mq.addEventListener('change', apply)

export function setTheme(choice) {
  theme.choice = choice
  try { localStorage.setItem(KEY, choice) } catch { /* private mode */ }
  apply()
}
