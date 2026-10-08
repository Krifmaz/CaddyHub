<script>
  import { tick } from 'svelte'
  import { Search, CornerDownLeft, Globe, Plus, ArrowRight } from '@lucide/svelte'
  import { api } from './api.js'
  import { go } from './router.svelte.js'
  import { can } from './state.svelte.js'

  let { pages = [] } = $props()
  let open = $state(false)
  let q = $state('')
  let sel = $state(0)
  let sites = $state([])
  let input = $state()

  export async function show() {
    open = true
    q = ''
    sel = 0
    api.get('/sites').then((s) => (sites = s)).catch(() => {})
    await tick()
    input?.focus()
  }

  function onkey(e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); open ? (open = false) : show() }
    else if (open && e.key === 'Escape') open = false
  }

  const items = $derived.by(() => {
    const t = q.trim().toLowerCase()
    const list = []
    if (can.edit()) list.push({ group: 'Actions', label: 'New site', icon: Plus, run: () => go('/sites/new') })
    if (can.edit()) list.push({ group: 'Actions', label: 'Review & apply changes', icon: ArrowRight, run: () => go('/changes') })
    for (const p of pages) list.push({ group: 'Go to', label: p.label, icon: p.icon, run: () => go(p.path) })
    for (const s of sites) list.push({ group: 'Sites', label: s.name, hint: s.hosts.join(', '), icon: Globe, run: () => go('/sites/' + s.id) })
    if (!t) return list.filter((i) => i.group !== 'Sites').concat(list.filter((i) => i.group === 'Sites').slice(0, 6))
    const byLabel = list.filter((i) => i.label.toLowerCase().includes(t))
    const byHint = list.filter((i) => !i.label.toLowerCase().includes(t) && (i.hint || '').toLowerCase().includes(t))
    return byLabel.concat(byHint)
  })
  $effect(() => { q; sel = 0 })

  function nav(e) {
    if (e.key === 'ArrowDown') { e.preventDefault(); sel = Math.min(sel + 1, items.length - 1); scroll() }
    else if (e.key === 'ArrowUp') { e.preventDefault(); sel = Math.max(sel - 1, 0); scroll() }
    else if (e.key === 'Enter' && items[sel]) { e.preventDefault(); pick(items[sel]) }
  }
  async function scroll() { await tick(); document.querySelector('.cp-item.sel')?.scrollIntoView({ block: 'nearest' }) }
  function pick(i) { open = false; i.run() }
</script>

<svelte:window onkeydown={onkey} />

{#if open}
  <div class="cp-backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && (open = false)}>
    <div class="cp" role="dialog" aria-modal="true" aria-label="Command palette">
      <div class="cp-input">
        <Search size={18} />
        <input bind:this={input} bind:value={q} onkeydown={nav} placeholder="Search sites and pages…" aria-label="Search" />
        <span class="kbd">Esc</span>
      </div>
      <div class="cp-list">
        {#each items as it, i}
          {#if i === 0 || items[i - 1].group !== it.group}<div class="cp-group">{it.group}</div>{/if}
          <button class="cp-item" class:sel={i === sel} onmousemove={() => (sel = i)} onclick={() => pick(it)}>
            <it.icon size={16} />
            <span class="truncate">{it.label}</span>
            {#if it.hint}<span class="faint small truncate">{it.hint}</span>{/if}
            {#if i === sel}<CornerDownLeft size={14} class="enter" />{/if}
          </button>
        {:else}
          <div class="cp-empty">No results for “{q}”</div>
        {/each}
      </div>
    </div>
  </div>
{/if}

<style>
  .cp-backdrop {
    position: fixed; inset: 0; z-index: 80; background: rgba(9, 9, 11, 0.45); backdrop-filter: blur(3px);
    display: flex; justify-content: center; align-items: flex-start; padding: 12vh 16px 16px; animation: fade 0.12s;
  }
  .cp {
    width: 100%; max-width: 580px; background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius-lg); box-shadow: var(--shadow-lg); overflow: hidden; animation: pop 0.14s ease-out;
  }
  .cp-input { display: flex; align-items: center; gap: 10px; padding: 0 16px; border-bottom: 1px solid var(--border); color: var(--muted); }
  .cp-input input { border: 0; box-shadow: none; height: 52px; padding: 0; font-size: 15px; background: transparent; }
  .cp-input input:focus { box-shadow: none; }
  .cp-list { max-height: 50vh; overflow-y: auto; padding: 6px; }
  .cp-group { font-size: 11.5px; font-weight: 600; color: var(--faint); padding: 10px 10px 4px; text-transform: uppercase; letter-spacing: 0.04em; }
  .cp-item {
    display: flex; align-items: center; gap: 10px; width: 100%; padding: 9px 10px; border: 0; background: none;
    border-radius: 8px; font: inherit; color: var(--text); cursor: pointer; text-align: left;
  }
  .cp-item :global(svg) { color: var(--muted); flex: none; }
  .cp-item.sel { background: var(--accent-soft); }
  .cp-item.sel :global(svg) { color: var(--accent-soft-text); }
  .cp-item :global(.enter) { margin-left: auto; }
  .cp-empty { padding: 28px; text-align: center; color: var(--muted); }
  @keyframes fade { from { opacity: 0; } }
  @keyframes pop { from { opacity: 0; transform: scale(0.97) translateY(-6px); } }
</style>
