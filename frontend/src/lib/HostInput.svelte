<script>
  import { X, Plus } from '@lucide/svelte'
  import { splitHost, joinHost } from './domains.js'

  // Edits a site's hostnames as "subdomain . [domain ▾]" rows. Hosts that
  // don't belong to a known domain (or when none exist) use a full input.
  let { hosts = $bindable(), domains = [], defaultDomain = '' } = $props()

  const fallback = () => defaultDomain || domains[0] || ''
  function toRow(h) {
    if (!domains.length) return { custom: true, sub: '', domain: '', full: h || '' }
    if (!h) return { custom: false, sub: '', domain: fallback(), full: '' }
    return splitHost(h, domains)
  }
  let rows = $state((hosts?.length ? hosts : ['']).map(toRow))

  $effect(() => { hosts = rows.map(joinHost) })

  function pick(r, v) {
    if (v === '__custom') { r.full = joinHost(r); r.custom = true; return }
    if (r.custom) { const s = splitHost(r.full, [v]); r.sub = s.custom ? '' : s.sub; r.custom = false }
    r.domain = v
  }
  function add() { rows.push(toRow('')) }
</script>

<div class="list">
  {#each rows as r, i}
    <div class="item">
      {#if r.custom}
        <input type="text" bind:value={r.full} placeholder="app.example.com" class="grow" aria-label="Hostname" />
      {:else}
        <div class="split grow">
          <input type="text" bind:value={r.sub} placeholder="app" aria-label="Subdomain" class="sub" />
          <span class="dotsep">.</span>
        </div>
      {/if}
      {#if domains.length}
        <select value={r.custom ? '__custom' : r.domain} onchange={(e) => pick(r, e.target.value)} aria-label="Domain" class="dom">
          {#each domains as d}<option value={d}>{d}</option>{/each}
          <option value="__custom">Other / full hostname…</option>
        </select>
      {/if}
      {#if rows.length > 1}
        <button class="btn ghost icon sm" type="button" aria-label="Remove" onclick={() => rows.splice(i, 1)}><X size={16} /></button>
      {/if}
    </div>
    {#if !r.custom && domains.length}
      <div class="preview">
        {#if r.sub.trim()}→ <span class="mono">{joinHost(r)}</span>{:else}→ <span class="mono">{r.domain}</span> <span class="faint">(the domain itself; type a name like “jellyfin” for a subdomain)</span>{/if}
      </div>
    {/if}
  {/each}
  <div><button class="btn xs" type="button" onclick={add}><Plus size={14} /> Add another hostname</button></div>
</div>

<style>
  .list { display: flex; flex-direction: column; gap: 6px; }
  .item { display: flex; gap: 6px; align-items: center; }
  .split { display: flex; align-items: center; gap: 6px; min-width: 0; }
  .sub { font-weight: 550; }
  .dotsep { color: var(--muted); font-weight: 700; }
  .dom { width: auto; max-width: 52%; flex: none; }
  .preview { font-size: 12.5px; color: var(--muted); margin: -2px 0 4px 2px; }
  .preview .mono { color: var(--accent-soft-text); }
  @media (max-width: 520px) { .item { flex-wrap: wrap; } .dom { max-width: none; flex: 1; } }
</style>
