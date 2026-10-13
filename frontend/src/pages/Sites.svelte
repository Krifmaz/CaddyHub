<script>
  import { onMount } from 'svelte'
  import {
    Plus, Search, LayoutGrid, List, ArrowUp, ArrowDown, Globe, FileInput, Server, Folder, CornerUpRight,
    MessageSquare, Code, Construction, Lock, ExternalLink, Activity, Rocket, Layers, ArrowLeftRight,
  } from '@lucide/svelte'
  import { api } from '../lib/api.js'
  import { app, toast, toastErr, refreshStatus, can } from '../lib/state.svelte.js'
  import { go } from '../lib/router.svelte.js'
  import { kindLabel, ago } from '../lib/util.js'
  import Switch from '../lib/Switch.svelte'
  import Avatar from '../lib/Avatar.svelte'

  let sites = $state(null)
  let q = $state('')
  let tag = $state('')
  let selected = $state({})
  let upstreams = $state({})
  let view = $state(localStorage.getItem('caddymium-sites-view') || 'grid')
  $effect(() => { try { localStorage.setItem('caddymium-sites-view', view) } catch {} })

  const kindIcon = { proxy: Server, static: Folder, redirect: CornerUpRight, respond: MessageSquare, forward_proxy: ArrowLeftRight, none: Code }

  async function load() {
    try { sites = await api.get('/sites') } catch (e) { toastErr(e); sites = [] }
  }
  // Real connection test of every upstream (Caddy's own counters stay at
  // zero unless health checks are configured, so they can't say "healthy").
  async function loadUpstreams() {
    try {
      const m = {}
      for (const u of (await api.get('/upstreams/reach')) || []) m[u.upstream] = u
      upstreams = m
    } catch { upstreams = {} }
  }
  onMount(() => { load(); loadUpstreams() })

  const tags = $derived([...new Set((sites || []).flatMap((s) => s.tags || []))].sort())
  const shown = $derived((sites || []).filter((s) => {
    if (tag && !(s.tags || []).includes(tag)) return false
    if (!q) return true
    const hay = [s.name, ...s.hosts, ...(s.tags || []), ...(s.config.proxy?.upstreams || []), s.config.redirect?.to || ''].join(' ').toLowerCase()
    return hay.includes(q.toLowerCase())
  }))
  const selIDs = $derived(Object.keys(selected).filter((k) => selected[k]).map(Number))

  function target(s) {
    const c = s.config
    switch (s.kind) {
      case 'proxy': return (c.proxy?.upstreams || []).join(', ')
      case 'static': return c.static?.root || ''
      case 'redirect': return c.redirect?.to || ''
      case 'respond': return `${c.respond?.status || 200} · ${(c.respond?.body || '').slice(0, 40)}`
      case 'forward_proxy': { const n = c.forward_proxy?.basic_auth?.length || 0; return n ? `${n} login(s)` : 'open proxy (no login)' }
      default: return 'custom Caddyfile'
    }
  }
  function health(s) {
    if (s.kind !== 'proxy' || !s.enabled) return null
    const us = (s.config.proxy?.upstreams || []).map((u) => upstreams[u.trim()]).filter(Boolean)
    if (!us.length) return null
    return us.every((u) => u.ok) ? 'ok' : 'err'
  }
  function reachError(s) {
    return (s.config.proxy?.upstreams || []).map((u) => upstreams[u.trim()]).find((u) => u && !u.ok)?.error
  }
  const upTotal = $derived(Object.keys(upstreams).length)
  const upHealthy = $derived(Object.values(upstreams).filter((u) => u.ok).length)
  function hostURL(s) {
    const h = s.hosts[0] || ''
    if (h.startsWith('*.')) return null
    return (s.config.tls?.mode === 'off' ? 'http://' : 'https://') + h
  }
  const secured = (s) => (s.config.access?.basic_auth?.length || s.config.access?.forward_auth || s.config.access?.allow_cidrs?.length)

  async function toggle(s, on) {
    try {
      await api.post('/sites/bulk', { ids: [s.id], action: on ? 'enable' : 'disable' })
      s.enabled = on
      refreshStatus()
    } catch (e) { s.enabled = !on; toastErr(e) }
  }
  async function bulk(action) {
    if (!selIDs.length) return
    if (action === 'delete' && !confirm(`Delete ${selIDs.length} site(s)? History keeps the old Caddyfiles.`)) return
    try {
      await api.post('/sites/bulk', { ids: selIDs, action })
      selected = {}
      toast(`Done: ${action} ${selIDs.length} site(s)`)
      await load(); refreshStatus()
    } catch (e) { toastErr(e) }
  }
  async function move(i, dir) {
    const list = [...sites]
    const j = i + dir
    if (j < 0 || j >= list.length) return
    ;[list[i], list[j]] = [list[j], list[i]]
    sites = list
    try { await api.post('/sites/bulk', { ids: list.map((s) => s.id), action: 'reorder' }); refreshStatus() } catch (e) { toastErr(e); load() }
  }
  const st = $derived(app.status)
</script>

<div class="page-head">
  <div>
    <h1>Sites</h1>
    <div class="sub">Everything Caddy serves. Edit freely: nothing goes live until you review and apply.</div>
  </div>
  {#if can.edit()}<a class="btn primary right" href="#/sites/new"><Plus size={16} /> New site</a>{/if}
</div>

<div class="stats">
  <div class="stat">
    <span class="s-ic"><Layers size={18} /></span>
    <div><div class="s-label">Active sites</div><div class="s-val">{st?.sites_enabled ?? '–'}<span class="faint">{" / "}{st?.sites_total ?? '–'}</span></div></div>
  </div>
  <div class="stat">
    <span class="s-ic"><Activity size={18} /></span>
    <div><div class="s-label">Apps reachable</div><div class="s-val">{upTotal ? upHealthy : '–'}<span class="faint">{" / "}{upTotal || '–'}</span></div></div>
  </div>
  <div class="stat">
    <span class="s-ic"><Server size={18} /></span>
    <div>
      <div class="s-label">Caddy</div>
      <div class="s-val row tight">
        {#if st?.caddy_reachable}<span class="dot ok"></span>{st.caddy_version || 'running'}{:else if st}<span class="dot err"></span>offline{:else}–{/if}
      </div>
    </div>
  </div>
  <a class="stat link" href="#/history">
    <span class="s-ic"><Rocket size={18} /></span>
    <div>
      <div class="s-label">Last apply</div>
      <div class="s-val row tight">
        {#if st?.last_apply}
          <span class="dot {st.last_apply.good ? 'ok' : 'err'}"></span>{ago(st.last_apply.created_at)}
        {:else}never{/if}
      </div>
    </div>
  </a>
</div>

{#if sites === null}
  <div class="grid">{#each Array(3) as _}<div class="card skel"></div>{/each}</div>
{:else if sites.length === 0}
  <div class="card empty">
    <div class="icon-wrap"><Globe size={24} /></div>
    <h2>No sites yet</h2>
    <p>Add your first site, or bring in the Caddyfile you already have.</p>
    <div class="row" style="justify-content:center;margin-top:6px">
      {#if can.edit()}<a class="btn primary" href="#/sites/new"><Plus size={16} /> New site</a>{/if}
      {#if can.admin()}<a class="btn" href="#/import"><FileInput size={16} /> Import a Caddyfile</a>{/if}
    </div>
  </div>
{:else}
  <div class="toolbar">
    <div class="searchbox">
      <Search size={16} />
      <input type="search" placeholder="Search hosts, upstreams, tags…" bind:value={q} />
    </div>
    {#if tags.length}
      <select bind:value={tag} class="tagsel">
        <option value="">All tags</option>
        {#each tags as t}<option value={t}>{t}</option>{/each}
      </select>
    {/if}
    {#if selIDs.length && can.edit() && view === 'list'}
      <span class="muted small">{selIDs.length} selected</span>
      <button class="btn sm" onclick={() => bulk('enable')}>Enable</button>
      <button class="btn sm" onclick={() => bulk('disable')}>Disable</button>
      <button class="btn sm danger" onclick={() => bulk('delete')}>Delete</button>
    {/if}
    <div class="tabs viewtabs right" role="group" aria-label="View">
      <button class:active={view === 'grid'} onclick={() => (view = 'grid')} aria-label="Grid view"><LayoutGrid size={15} /></button>
      <button class:active={view === 'list'} onclick={() => (view = 'list')} aria-label="List view"><List size={15} /></button>
    </div>
  </div>

  {#if shown.length === 0}
    <div class="card empty"><div class="icon-wrap"><Search size={22} /></div><p>No sites match your search.</p></div>
  {:else if view === 'grid'}
    <div class="grid">
      {#each shown as s (s.id)}
        {@const KI = kindIcon[s.kind] || Code}
        <div class="card site" class:off={!s.enabled} role="link" tabindex="0" onclick={() => go('/sites/' + s.id)} onkeydown={(e) => e.key === 'Enter' && go('/sites/' + s.id)}>
          <div class="site-top">
            <Avatar name={s.name || s.hosts[0]} size={40} />
            <div class="grow">
              <div class="name truncate">{s.name}</div>
              <div class="host truncate">
                {s.hosts[0]}{#if s.hosts.length > 1}<span class="faint"> +{s.hosts.length - 1}</span>{/if}
              </div>
            </div>
            <span role="presentation" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
              <Switch checked={s.enabled} disabled={!can.edit()} label="Enabled" onchange={(v) => toggle(s, v)} />
            </span>
          </div>
          <div class="target">
            <KI size={14} />
            <span class="muted xs kind">{kindLabel[s.kind]}</span>
            <span class="mono truncate">{target(s)}</span>
          </div>
          {#if health(s) === 'err'}<div class="reach-err">{reachError(s)}</div>{/if}
          <div class="site-foot">
            {#if health(s)}<span class="badge {health(s)}" title={reachError(s) || 'Caddy can connect to this app'}><span class="dot {health(s)}"></span>{health(s) === 'ok' ? 'reachable' : "can't reach app"}</span>{/if}
            {#if s.config.maintenance}<span class="badge warn"><Construction /> maintenance</span>{/if}
            {#if secured(s)}<span class="badge"><Lock /> protected</span>{/if}
            {#each (s.tags || []).slice(0, 3) as t}<span class="badge">{t}</span>{/each}
            {#if hostURL(s) && s.enabled}
              <a class="btn ghost icon xs right" href={hostURL(s)} target="_blank" rel="noreferrer" title="Open site" aria-label="Open site" onclick={(e) => e.stopPropagation()}><ExternalLink size={14} /></a>
            {/if}
          </div>
        </div>
      {/each}
      {#if can.edit() && !q && !tag}
        <a class="card add" href="#/sites/new"><Plus size={22} /><span>Add a site</span></a>
      {/if}
    </div>
  {:else}
    <div class="card flush table-wrap">
      <table class="list">
        <thead>
          <tr>
            {#if can.edit()}<th style="width:36px"></th>{/if}
            <th>Site</th>
            <th class="hide-sm">Type</th>
            <th class="hide-sm">Target</th>
            <th style="width:64px">On</th>
            {#if can.edit() && !q && !tag}<th class="hide-sm" style="width:80px">Order</th>{/if}
          </tr>
        </thead>
        <tbody>
          {#each shown as s, i (s.id)}
            <tr class="clickable" class:off={!s.enabled} onclick={() => go('/sites/' + s.id)}>
              {#if can.edit()}
                <td onclick={(e) => e.stopPropagation()}><input type="checkbox" bind:checked={selected[s.id]} aria-label="Select" /></td>
              {/if}
              <td>
                <div class="row tight nowrap">
                  <Avatar name={s.name || s.hosts[0]} size={28} />
                  <div style="min-width:0">
                    <div class="row tight"><strong>{s.name}</strong>{#if health(s)}<span class="dot {health(s)}"></span>{/if}</div>
                    <div class="muted xs truncate">{s.hosts.join(', ')}</div>
                  </div>
                </div>
              </td>
              <td class="hide-sm muted">{kindLabel[s.kind] || s.kind}</td>
              <td class="hide-sm mono small truncate" style="max-width:280px">{target(s)}</td>
              <td onclick={(e) => e.stopPropagation()}>
                <Switch checked={s.enabled} disabled={!can.edit()} label="Enabled" onchange={(v) => toggle(s, v)} />
              </td>
              {#if can.edit() && !q && !tag}
                <td class="hide-sm nowrap" onclick={(e) => e.stopPropagation()}>
                  <button class="btn ghost icon xs" aria-label="Move up" disabled={i === 0} onclick={() => move(i, -1)}><ArrowUp size={14} /></button>
                  <button class="btn ghost icon xs" aria-label="Move down" disabled={i === shown.length - 1} onclick={() => move(i, 1)}><ArrowDown size={14} /></button>
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/if}

<style>
  .stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 24px; }
  .stat {
    display: flex; gap: 12px; align-items: center; padding: 14px 16px; background: var(--surface);
    border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow-xs); color: var(--text);
  }
  .stat.link:hover { border-color: var(--border-strong); color: var(--text); }
  .s-ic { width: 36px; height: 36px; border-radius: 10px; display: grid; place-items: center; background: var(--accent-soft); color: var(--accent-soft-text); flex: none; }
  .s-label { font-size: 12px; color: var(--muted); font-weight: 500; }
  .s-val { font-size: 17px; font-weight: 650; letter-spacing: -0.02em; line-height: 1.3; }

  .toolbar { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }
  .searchbox { position: relative; flex: 1; max-width: 400px; min-width: 200px; }
  .searchbox :global(svg) { position: absolute; left: 11px; top: 50%; transform: translateY(-50%); color: var(--faint); pointer-events: none; }
  .searchbox input { padding-left: 34px; }
  .tagsel { width: auto; min-width: 130px; }
  .viewtabs { margin-bottom: 0; }
  .viewtabs button { padding: 5px 10px; }

  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 14px; }
  .site {
    padding: 16px; display: flex; flex-direction: column; gap: 14px; cursor: pointer;
    transition: border-color 0.15s, box-shadow 0.15s, transform 0.15s;
  }
  .site:hover { border-color: var(--border-strong); box-shadow: var(--shadow-sm); transform: translateY(-1px); }
  .site:focus-visible { outline: none; box-shadow: 0 0 0 3px var(--ring); }
  .site.off { opacity: 0.6; }
  .site-top { display: flex; align-items: center; gap: 12px; }
  .name { font-weight: 600; font-size: 14.5px; letter-spacing: -0.01em; }
  .host { color: var(--muted); font-size: 12.5px; }
  .target {
    display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-radius: 8px;
    background: var(--surface-2); color: var(--text-2); font-size: 12.5px; min-width: 0;
  }
  .target :global(svg) { color: var(--muted); flex: none; }
  .target .kind { flex: none; }
  .reach-err { font-size: 12.5px; line-height: 1.45; color: var(--danger-soft-text); background: var(--danger-soft); border-radius: 8px; padding: 8px 10px; margin-top: -4px; }
  .site-foot { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; min-height: 22px; }
  .add {
    display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 8px; min-height: 168px;
    border-style: dashed; background: transparent; box-shadow: none; color: var(--muted); font-weight: 550;
  }
  .add:hover { color: var(--accent); border-color: var(--accent); background: var(--accent-soft); }
  .skel { height: 168px; background: linear-gradient(90deg, var(--surface) 0%, var(--surface-2) 50%, var(--surface) 100%); background-size: 200% 100%; animation: shimmer 1.2s infinite; }
  @keyframes shimmer { to { background-position: -200% 0; } }
  tr.off td { opacity: 0.6; }

  @media (max-width: 1000px) { .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
  @media (max-width: 640px) { .grid { grid-template-columns: 1fr; } .stat { padding: 12px; } .s-val { font-size: 15px; } }
</style>
