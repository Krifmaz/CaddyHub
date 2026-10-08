<script>
  import { onMount } from 'svelte'
  import { api, setCSRF, handleUnauthorized } from './lib/api.js'
  import { app, refreshStatus, can } from './lib/state.svelte.js'
  import { route, go } from './lib/router.svelte.js'
  import Login from './pages/Login.svelte'
  import Welcome from './pages/Welcome.svelte'
  import Sites from './pages/Sites.svelte'
  import SiteEditor from './pages/SiteEditor.svelte'
  import Changes from './pages/Changes.svelte'
  import Caddyfile from './pages/Caddyfile.svelte'
  import History from './pages/History.svelte'
  import Domains from './pages/Domains.svelte'
  import Snippets from './pages/Snippets.svelte'
  import Import from './pages/Import.svelte'
  import Settings from './pages/Settings.svelte'
  import Users from './pages/Users.svelte'
  import Notifications from './pages/Notifications.svelte'
  import Audit from './pages/Audit.svelte'
  import Account from './pages/Account.svelte'

  let loading = $state(true)
  let menuOpen = $state(false)

  async function loadMe() {
    try {
      app.me = await api.get('/me')
      setCSRF(app.me.csrf)
    } catch (e) {
      app.me = { user: null, error: e.message }
    }
    loading = false
    if (app.me?.user && !app.me.pending_2fa) refreshStatus()
  }

  handleUnauthorized(() => { if (app.me?.user) loadMe() })

  onMount(() => {
    loadMe()
    const t = setInterval(() => { if (app.me?.user && !document.hidden) refreshStatus() }, 20000)
    return () => clearInterval(t)
  })

  async function logout() {
    await api.post('/logout').catch(() => {})
    app.me = { ...app.me, user: null, csrf: '' }
    setCSRF('')
    go('/')
  }

  const nav = [
    { path: '/sites', label: 'Sites', icon: '◧' },
    { path: '/changes', label: 'Review & apply', icon: '⇪', pending: true },
    { path: '/caddyfile', label: 'Caddyfile', icon: '≡' },
    { path: '/history', label: 'History', icon: '↺' },
    { path: '/domains', label: 'Domains & DNS', icon: '◎', admin: true },
    { path: '/snippets', label: 'Snippets & raw', icon: '{ }' },
    { path: '/import', label: 'Import', icon: '⇩', admin: true },
    { path: '/settings', label: 'Settings', icon: '⚙' },
    { path: '/users', label: 'Users & API keys', icon: '☺', admin: true },
    { path: '/notifications', label: 'Notifications', icon: '✉', admin: true },
    { path: '/audit', label: 'Audit log', icon: '☰', admin: true },
  ]

  const page = $derived(route.parts[0] || 'sites')
  const showWelcome = $derived(app.me?.user && can.admin() && app.me.setup_complete === false && page !== 'import')
  const st = $derived(app.status)
</script>

{#if loading}
  <div class="center muted">Loading…</div>
{:else if !app.me?.user || app.me.pending_2fa}
  <Login onlogin={loadMe} />
{:else}
  <div class="shell">
    <aside class:open={menuOpen}>
      <div class="brand">
        <img src="/favicon.svg" alt="" width="26" height="26" />
        <span>CaddyHub</span>
      </div>
      <nav>
        {#each nav as n}
          {#if !n.admin || can.admin()}
            <a href={'#' + n.path} class:active={page === n.path.slice(1)} onclick={() => (menuOpen = false)}>
              <span class="ic">{n.icon}</span>
              <span class="grow">{n.label}</span>
              {#if n.pending && st?.pending_changes}<span class="dot warn" title="Unapplied changes"></span>{/if}
            </a>
          {/if}
        {/each}
      </nav>
      <div class="foot">
        <a href="#/account" class:active={page === 'account'} onclick={() => (menuOpen = false)}>
          <span class="ic">◉</span><span class="grow">{app.me.user.username}</span><span class="badge">{app.me.user.role}</span>
        </a>
        <button class="btn ghost sm" onclick={logout}>Log out</button>
      </div>
    </aside>
    {#if menuOpen}<div class="scrim" role="presentation" onclick={() => (menuOpen = false)}></div>{/if}

    <div class="main">
      <header class="top">
        <button class="btn ghost icon menu" aria-label="Menu" onclick={() => (menuOpen = !menuOpen)}>☰</button>
        <div class="row status">
          {#if st}
            {#if st.caddy_reachable}
              <span class="row nowrap" title="Caddy admin API reachable"><span class="dot ok"></span> Caddy {st.caddy_version || ''}</span>
            {:else}
              <span class="row nowrap" title={st.caddy_error}><span class="dot err"></span> Caddy unreachable</span>
            {/if}
            <span class="muted hide-sm">{st.sites_enabled}/{st.sites_total} sites on</span>
          {/if}
        </div>
        <div class="right row">
          {#if st?.pending_changes && can.edit()}
            <a class="btn primary sm" href="#/changes">Review & apply changes</a>
          {:else if st?.last_apply}
            <span class="muted small hide-sm">
              {#if st.last_apply.good}<span class="badge ok">applied</span>{:else}<span class="badge err">{st.last_apply.status}</span>{/if}
            </span>
          {/if}
        </div>
      </header>

      <main>
        {#if showWelcome}
          <Welcome />
        {:else if page === 'sites' && route.parts[1]}
          <SiteEditor id={route.parts[1]} />
        {:else if page === 'sites'}
          <Sites />
        {:else if page === 'changes'}
          <Changes />
        {:else if page === 'caddyfile'}
          <Caddyfile />
        {:else if page === 'history'}
          <History />
        {:else if page === 'domains'}
          <Domains />
        {:else if page === 'snippets'}
          <Snippets />
        {:else if page === 'import'}
          <Import />
        {:else if page === 'settings'}
          <Settings />
        {:else if page === 'users'}
          <Users />
        {:else if page === 'notifications'}
          <Notifications />
        {:else if page === 'audit'}
          <Audit />
        {:else if page === 'account'}
          <Account />
        {:else}
          <div class="empty"><h2>Page not found</h2><a href="#/sites">Go to sites</a></div>
        {/if}
      </main>
    </div>
  </div>
{/if}

<div class="toasts" aria-live="polite">
  {#each app.toasts as t (t.id)}
    <div class="toast {t.kind}">{t.message}</div>
  {/each}
</div>

<style>
  .center { display: grid; place-items: center; min-height: 100vh; }
  .shell { display: flex; min-height: 100vh; }
  aside {
    width: 232px; flex: none; background: var(--surface); border-right: 1px solid var(--border);
    display: flex; flex-direction: column; position: sticky; top: 0; height: 100vh;
  }
  .brand { display: flex; align-items: center; gap: 10px; padding: 18px 18px 14px; font-weight: 700; font-size: 16px; }
  nav { display: flex; flex-direction: column; gap: 1px; padding: 4px 10px; overflow-y: auto; flex: 1; }
  nav a, .foot a {
    display: flex; align-items: center; gap: 10px; padding: 7px 10px; border-radius: 7px;
    color: var(--text); font-weight: 500;
  }
  nav a:hover, .foot a:hover { background: var(--surface-2); text-decoration: none; }
  nav a.active, .foot a.active { background: var(--accent-soft); color: var(--accent); }
  .ic { width: 20px; text-align: center; color: var(--muted); font-size: 13px; }
  a.active .ic { color: var(--accent); }
  .foot { border-top: 1px solid var(--border); padding: 10px; display: flex; flex-direction: column; gap: 4px; }
  .foot .btn { align-self: flex-start; margin-left: 4px; }
  .main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .top {
    display: flex; align-items: center; gap: 12px; height: 54px; padding: 0 24px;
    border-bottom: 1px solid var(--border); background: var(--surface); position: sticky; top: 0; z-index: 10;
  }
  .status { gap: 14px; font-size: 13px; }
  .menu { display: none; }
  main { padding: 24px; max-width: 1180px; width: 100%; }
  .scrim { display: none; }

  @media (max-width: 860px) {
    aside { position: fixed; left: 0; top: 0; z-index: 40; transform: translateX(-100%); transition: transform 0.18s; }
    aside.open { transform: none; box-shadow: 0 0 40px rgba(0, 0, 0, 0.35); }
    .scrim { display: block; position: fixed; inset: 0; z-index: 30; background: rgba(0, 0, 0, 0.35); }
    .menu { display: inline-flex; }
    .top { padding: 0 12px; }
    main { padding: 16px; }
  }

  .toasts { position: fixed; bottom: 16px; right: 16px; left: 16px; display: flex; flex-direction: column; align-items: flex-end; gap: 8px; z-index: 100; pointer-events: none; }
  .toast {
    pointer-events: auto; max-width: 440px; padding: 10px 14px; border-radius: 8px; color: #fff;
    background: #1f2a33; box-shadow: 0 8px 24px rgba(0, 0, 0, 0.25); white-space: pre-wrap; word-break: break-word;
  }
  .toast.ok { background: #1d6f5b; }
  .toast.err { background: #a93232; }
</style>
