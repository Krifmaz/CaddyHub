<script>
  import { Radar, Search, Globe, Lock, ChevronDown } from '@lucide/svelte'
  import { api } from './api.js'
  import Modal from './Modal.svelte'
  import Avatar from './Avatar.svelte'

  // Scans for running apps and lets the user pick one as the upstream.
  let { onpick, onclose } = $props()
  let target = $state('')
  let busy = $state(false)
  let error = $state('')
  let results = $state(null)
  let showOther = $state(false)

  async function run(e) {
    e?.preventDefault()
    busy = true; error = ''; results = null
    try {
      const r = await api.post('/scan', { target })
      results = r.results
      if (r.timed_out) error = 'The scan hit its time limit; results may be incomplete. Try a narrower target.'
    } catch (err) { error = err.message }
    busy = false
  }
  run()

  const web = $derived((results || []).filter((r) => r.scheme))
  const other = $derived((results || []).filter((r) => !r.scheme))
</script>

<Modal title="Find a running app" description="Looks for web apps on common ports and fills in the address for you." wide {onclose}>
  <form class="row" onsubmit={run}>
    <div class="searchbox grow">
      <Search size={16} />
      <input type="text" bind:value={target} placeholder="Empty = this Docker network · or an IP, container name, or 10.0.1.0/24" />
    </div>
    <button class="btn primary" type="submit" disabled={busy}><Radar size={15} /> {busy ? 'Scanning…' : 'Scan'}</button>
  </form>

  {#if busy}
    <div class="scanning"><span class="pulse"><Radar size={22} /></span><span class="muted">Scanning{target ? ` ${target}` : ' the Docker network'}… this takes a few seconds.</span></div>
  {/if}
  {#if error}<div class="alert warn"><span>{error}</span></div>{/if}

  {#if results && !busy}
    {#if web.length === 0}
      <div class="empty"><div class="icon-wrap"><Radar size={22} /></div>
        <p>No web apps found{target ? ` on ${target}` : ' on the Docker network'}.</p>
        <p class="small">Apps in other Docker stacks are only visible if their network is attached to CaddyHub. You can also scan your LAN, e.g. <code>10.0.1.0/24</code>, or the server's IP.</p>
      </div>
    {:else}
      <div class="results">
        {#each web as r}
          <button class="res" onclick={() => onpick(r)}>
            <Avatar name={r.guess || r.host} size={34} />
            <div class="grow info">
              <div class="truncate"><strong>{r.guess || r.host}</strong></div>
              <div class="mono small truncate">{r.upstream}</div>
            </div>
            {#if r.scheme === 'https'}<span class="badge"><Lock /> HTTPS</span>{:else}<span class="badge"><Globe /> HTTP</span>{/if}
            {#if r.host !== r.ip}<span class="faint xs hide-sm">{r.ip}</span>{/if}
            <span class="btn sm primary use">Use</span>
          </button>
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
  .res {
    display: flex; align-items: center; gap: 12px; width: 100%; padding: 10px 12px; text-align: left; font: inherit;
    color: var(--text); background: var(--surface); border: 1px solid var(--border); border-radius: 10px; cursor: pointer;
  }
  .res:hover { border-color: var(--accent); background: var(--accent-soft); }
  .info { min-width: 0; }
  .use { pointer-events: none; }
</style>
