<script>
  import { Radar, Search, Globe, Lock, ChevronDown, Container, Network } from '@lucide/svelte'
  import { api } from './api.js'
  import Modal from './Modal.svelte'
  import Avatar from './Avatar.svelte'

  // Scans for running apps (Docker networks + the LAN) and lets the user
  // pick one as the upstream.
  let { onpick, onclose } = $props()
  let target = $state('')
  let busy = $state(false)
  let error = $state('')
  let results = $state(null)
  let scanned = $state([])
  let showOther = $state(false)

  async function run(e) {
    e?.preventDefault()
    busy = true; error = ''; results = null
    try {
      const r = await api.post('/scan', { target })
      results = r.results
      scanned = r.scanned || []
      if (r.timed_out) error = 'The scan hit its time limit; results may be incomplete. Try a narrower range.'
    } catch (err) { error = err.message }
    busy = false
  }
  run()

  const web = $derived((results || []).filter((r) => r.scheme))
  const groups = $derived([
    { id: 'docker', title: 'Docker containers', icon: Container, items: web.filter((r) => r.source === 'docker') },
    { id: 'lan', title: 'On your network', icon: Network, items: web.filter((r) => r.source !== 'docker') },
  ].filter((g) => g.items.length))
  const other = $derived((results || []).filter((r) => !r.scheme))
</script>

<Modal title="Find a running app" description="Looks for web apps in Docker and on your network, and fills in the address for you." wide {onclose}>
  <form class="row" onsubmit={run}>
    <div class="searchbox grow">
      <Search size={16} />
      <input type="text" bind:value={target} placeholder="Empty = Docker + your network · or an IP, name, or range like 10.0.2.0/24" />
    </div>
    <button class="btn primary" type="submit" disabled={busy}><Radar size={15} /> {busy ? 'Scanning…' : 'Scan'}</button>
  </form>

  {#if busy}
    <div class="scanning"><span class="pulse"><Radar size={22} /></span><span class="muted">Scanning{target ? ` ${target}` : ' Docker and your network'}… this takes a few seconds.</span></div>
  {:else if scanned.length}
    <div class="row tight small muted">Scanned: {#each scanned as s}<span class="badge">{s}</span>{/each}</div>
  {/if}
  {#if error}<div class="alert warn"><span>{error}</span></div>{/if}

  {#if results && !busy}
    {#if web.length === 0}
      <div class="empty"><div class="icon-wrap"><Radar size={22} /></div>
        <p>No web apps found.</p>
        <p class="small">If your apps are on another subnet, enter its range above (e.g. <code>10.0.2.0/24</code>) or add it under Settings → Proxies &amp; DNS → Find app ranges.</p>
      </div>
    {:else}
      <div class="results">
        {#each groups as g}
          <div class="group"><g.icon size={14} /> {g.title} <span class="faint">({g.items.length})</span></div>
          {#each g.items as r}
            <button class="res" onclick={() => onpick(r)}>
              <Avatar name={r.guess || r.name || r.host} size={34} />
              <div class="grow info">
                <div class="truncate"><strong>{r.guess || r.name || r.host}</strong>{#if r.name && r.name !== r.guess}<span class="faint small"> · {r.name}</span>{/if}</div>
                <div class="mono small truncate">{r.upstream}</div>
              </div>
              {#if r.scheme === 'https'}<span class="badge"><Lock /> HTTPS</span>{:else}<span class="badge"><Globe /> HTTP</span>{/if}
              <span class="btn sm primary use">Use</span>
            </button>
          {/each}
        {/each}
      </div>
    {/if}
    {#if other.length}
      <button class="btn ghost sm" onclick={() => (showOther = !showOther)}><ChevronDown size={15} /> {other.length} other open port(s) (not web servers)</button>
      {#if showOther}
        <div class="row tight">{#each other as r}<span class="badge mono">{r.host}:{r.port}</span>{/each}</div>
      {/if}
    {/if}
  {/if}
</Modal>

<style>
  .searchbox { position: relative; min-width: 220px; }
  .searchbox :global(svg) { position: absolute; left: 11px; top: 50%; transform: translateY(-50%); color: var(--faint); }
  .searchbox input { padding-left: 34px; }
  .scanning { display: flex; align-items: center; gap: 12px; padding: 18px 4px; }
  .pulse { color: var(--accent); animation: spin 1.6s linear infinite; display: inline-flex; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .results { display: flex; flex-direction: column; gap: 6px; max-height: 52vh; overflow-y: auto; }
  .group { display: flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; padding: 8px 2px 2px; }
  .res {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 10px 12px; text-align: left; font: inherit;
    color: var(--text); background: var(--surface); border: 1px solid var(--border); border-radius: 10px; cursor: pointer;
  }
  .res:hover { border-color: var(--accent); background: var(--accent-soft); }
  .info { min-width: 0; }
  .use { pointer-events: none; }
</style>
