<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import { app, toast, toastErr, refreshStatus, can } from '../lib/state.svelte.js'
  import { go } from '../lib/router.svelte.js'
  import { kindLabel } from '../lib/util.js'
  import Switch from '../lib/Switch.svelte'

  let sites = $state(null)
  let q = $state('')
  let tag = $state('')
  let selected = $state({})
  let upstreams = $state({})

  async function load() {
    try { sites = await api.get('/sites') } catch (e) { toastErr(e); sites = [] }
  }
  async function loadUpstreams() {
    try {
      const ups = await api.get('/upstreams')
      const m = {}
      for (const u of ups || []) m[u.address] = u
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
      case 'redirect': return '→ ' + (c.redirect?.to || '')
      case 'respond': return (c.respond?.status || 200) + ' ' + (c.respond?.body || '').slice(0, 40)
      default: return 'raw Caddyfile'
    }
  }
  function health(s) {
    if (s.kind !== 'proxy' || !s.enabled) return null
    const us = (s.config.proxy?.upstreams || []).map((u) => upstreams[u.replace(/^https?:\/\//, '')] || upstreams[u]).filter(Boolean)
    if (!us.length) return null
    return us.every((u) => u.fails === 0) ? 'ok' : 'err'
  }

  async function toggle(s, on) {
    try {
      await api.post('/sites/bulk', { ids: [s.id], action: on ? 'enable' : 'disable' })
      s.enabled = on
      refreshStatus()
    } catch (e) { s.enabled = !on; toastErr(e) }
  }
  async function bulk(action) {
    if (!selIDs.length) return
    if (action === 'delete' && !confirm(`Delete ${selIDs.length} site(s)? This can't be undone (but history keeps old Caddyfiles).`)) return
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
</script>

<div class="page-head">
  <div>
    <h1>Sites</h1>
    <div class="sub">Each site is a hostname Caddy serves. Changes are saved here and go live when you apply them.</div>
  </div>
  {#if can.edit()}<a class="btn primary right" href="#/sites/new">+ New site</a>{/if}
</div>

{#if sites === null}
  <p class="muted">Loading…</p>
{:else if sites.length === 0}
  <div class="card empty">
    <h2>No sites yet</h2>
    <p>Add your first site, or import the Caddyfile you already have.</p>
    <div class="row" style="justify-content:center">
      {#if can.edit()}<a class="btn primary" href="#/sites/new">+ New site</a>{/if}
      {#if can.admin()}<a class="btn" href="#/import">Import a Caddyfile</a>{/if}
    </div>
  </div>
{:else}
  <div class="row bar">
    <input type="text" placeholder="Search hosts, upstreams, tags…" bind:value={q} class="grow search" />
    {#if tags.length}
      <select bind:value={tag} class="tagsel">
        <option value="">All tags</option>
        {#each tags as t}<option value={t}>{t}</option>{/each}
      </select>
    {/if}
    {#if selIDs.length && can.edit()}
      <span class="muted">{selIDs.length} selected</span>
      <button class="btn sm" onclick={() => bulk('enable')}>Enable</button>
      <button class="btn sm" onclick={() => bulk('disable')}>Disable</button>
      <button class="btn sm danger" onclick={() => bulk('delete')}>Delete</button>
    {/if}
  </div>

  <div class="card flush table-wrap">
    <table class="list">
      <thead>
        <tr>
          {#if can.edit()}<th style="width:34px"></th>{/if}
          <th>Site</th>
          <th class="hide-sm">Type</th>
          <th class="hide-sm">Target</th>
          <th style="width:60px">On</th>
          {#if can.edit() && !q && !tag}<th class="hide-sm" style="width:70px">Order</th>{/if}
        </tr>
      </thead>
      <tbody>
        {#each shown as s, i (s.id)}
          <tr class="clickable" onclick={() => go('/sites/' + s.id)}>
            {#if can.edit()}
              <td onclick={(e) => e.stopPropagation()}><input type="checkbox" bind:checked={selected[s.id]} aria-label="Select" /></td>
            {/if}
            <td>
              <div class="row name">
                {#if health(s)}<span class="dot {health(s)}" title={health(s) === 'ok' ? 'Upstream healthy' : 'Upstream failing'}></span>{/if}
                <strong>{s.name}</strong>
                {#each s.tags || [] as t}<span class="badge">{t}</span>{/each}
                {#if s.config.maintenance}<span class="badge warn">maintenance</span>{/if}
              </div>
              <div class="muted small hosts">{s.hosts.join(', ')}</div>
            </td>
            <td class="hide-sm">{kindLabel[s.kind] || s.kind}</td>
            <td class="hide-sm mono small target">{target(s)}</td>
            <td onclick={(e) => e.stopPropagation()}>
              <Switch checked={s.enabled} disabled={!can.edit()} label="Enabled" onchange={(v) => toggle(s, v)} />
            </td>
            {#if can.edit() && !q && !tag}
              <td class="hide-sm nowrap" onclick={(e) => e.stopPropagation()}>
                <button class="btn ghost icon sm" aria-label="Move up" disabled={i === 0} onclick={() => move(i, -1)}>↑</button>
                <button class="btn ghost icon sm" aria-label="Move down" disabled={i === shown.length - 1} onclick={() => move(i, 1)}>↓</button>
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
    {#if shown.length === 0}<div class="empty">No sites match.</div>{/if}
  </div>
{/if}

<style>
  .bar { margin-bottom: 12px; }
  .search { max-width: 380px; }
  .tagsel { width: auto; }
  .name { gap: 6px; }
  .hosts { word-break: break-all; }
  .target { max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
</style>
