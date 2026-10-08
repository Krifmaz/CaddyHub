<script>
  import { onMount } from 'svelte'
  import { Upload, ScanSearch, FileInput, Radar, ShieldCheck, TriangleAlert, CircleCheck, CircleX, Info, ClipboardPaste } from '@lucide/svelte'
  import { api } from '../lib/api.js'
  import { toast, toastErr, refreshStatus } from '../lib/state.svelte.js'
  import { go } from '../lib/router.svelte.js'

  let { embedded = false, ondone } = $props()
  let sources = $state(null)
  let picked = $state(null)   // detected source id, or null for pasted text
  let text = $state('')
  let preview = $state(null)
  let replace = $state(false)
  let settings = $state(true)
  let busy = $state(false)
  let done = $state(null)
  let showPaste = $state(false)

  onMount(async () => {
    try { sources = await api.get('/import/sources') } catch { sources = [] }
    if (!sources.length) showPaste = true
  })

  const body = () => (picked ? { source: picked } : { caddyfile: text })

  async function file(e) {
    const f = e.target.files?.[0]
    if (f) { text = await f.text(); picked = null; preview = null }
  }
  async function analyze(src = null) {
    picked = src
    busy = true; preview = null; done = null
    try { preview = await api.post('/import/preview', body()) } catch (e) { toastErr(e) }
    busy = false
  }
  async function commit() {
    if (replace && !confirm('Replace ALL existing sites, snippets and raw blocks with the imported ones?')) return
    busy = true
    try {
      done = await api.post('/import/commit', { ...body(), replace, settings })
      toast(`Imported ${done.sites} site(s). Nothing is live until you apply.`)
      refreshStatus()
      ondone?.(done)
    } catch (e) { toastErr(e) }
    busy = false
  }
  const statusBadge = { structured: 'ok', partial: 'warn', raw: 'accent', skipped: 'err' }
  const statusLabel = { structured: 'editable', partial: 'partly editable', raw: 'kept for review', skipped: 'skipped' }
  const ph = 'example.com {\n\treverse_proxy localhost:8080\n}\n\n(or paste Caddy JSON config)'
  const pickedLabel = $derived(sources?.find((s) => s.id === picked)?.label)
</script>

{#if !embedded}
  <div class="page-head">
    <div>
      <h1>Import</h1>
      <div class="sub">Bring in your existing Caddy config. What CaddyHub understands becomes editable sites; everything else is kept, nothing is dropped silently. Nothing goes live until you apply.</div>
    </div>
  </div>
{/if}

<div class="stack">
  {#if sources === null}
    <div class="card row muted"><Radar size={18} /> Looking for an existing Caddy config…</div>
  {:else if sources.length}
    {#each sources as s}
      <div class="card found" class:active={picked === s.id && preview}>
        <span class="f-ic"><Radar size={20} /></span>
        <div class="grow">
          <div class="f-title">Found an existing config in {s.label}</div>
          <div class="muted small">{s.detail}</div>
          {#if s.hosts?.length}<div class="hosts">{#each s.hosts.slice(0, 8) as h}<span class="badge">{h}</span>{/each}{#if s.hosts.length > 8}<span class="faint small">+{s.hosts.length - 8} more</span>{/if}</div>{/if}
        </div>
        <button class="btn primary" onclick={() => analyze(s.id)} disabled={busy}><ScanSearch size={15} /> Preview import</button>
      </div>
    {/each}
    {#if !showPaste}
      <div><button class="btn ghost sm" onclick={() => (showPaste = true)}><ClipboardPaste size={15} /> Paste a Caddyfile instead</button></div>
    {/if}
  {/if}

  {#if showPaste}
    <div class="card stack">
      <div class="card-head">
        <div><h2>{sources?.length ? 'Or paste a config' : 'Paste your Caddyfile'}</h2>
          <div class="desc">{sources?.length ? '' : 'No running config was found automatically. '}A Caddyfile or Caddy's JSON config both work.</div></div>
        <label class="btn sm right"><Upload size={15} /> Choose file… <input type="file" class="hidden" onchange={file} /></label>
      </div>
      <textarea rows="12" bind:value={text} placeholder={ph}></textarea>
      <div><button class="btn primary" onclick={() => analyze(null)} disabled={busy || !text.trim()}><ScanSearch size={15} /> Analyze</button></div>
    </div>
  {/if}

  {#if busy && !preview}
    <div class="card row muted"><ScanSearch size={18} /> Analyzing and test-regenerating with Caddy…</div>
  {/if}

  {#if preview}
    <div class="card stack">
      <div class="card-head">
        <div><h2>Import preview</h2><div class="desc">{picked ? `From ${pickedLabel}` : 'From pasted config'}</div></div>
      </div>

      {#if preview.verify?.checked && preview.verify.differences.length === 0}
        <div class="alert ok"><ShieldCheck /><span><strong>{preview.verify.sites} site(s) imported, 0 differences.</strong> CaddyHub regenerated the config, Caddy checked it, and every host behaves the same as before.</span></div>
      {:else if preview.verify?.checked}
        <div class="alert warn"><TriangleAlert /><span><strong>{preview.verify.differences.length} difference(s) after regeneration:</strong>
          <ul>{#each preview.verify.differences as d}<li class="mono small">{d}</li>{/each}</ul></span></div>
      {:else if preview.verify?.error}
        <div class="alert info"><Info /><span>Round-trip check skipped: {preview.verify.error}</span></div>
      {/if}

      {#each preview.warnings || [] as w}<div class="alert warn"><TriangleAlert /><span>{w}</span></div>{/each}

      <div class="row tight small">
        <span class="badge ok"><CircleCheck /> {preview.sites.length} sites</span>
        {#if preview.snippets?.length}<span class="badge">{preview.snippets.length} snippets</span>{/if}
        {#if preview.credentials?.length}<span class="badge">{preview.credentials.length} DNS accounts</span>{/if}
        {#if preview.domains?.length}<span class="badge">{preview.domains.length} domains</span>{/if}
        {#if preview.raw_blocks?.length}<span class="badge accent">{preview.raw_blocks.length} kept for review</span>{/if}
      </div>

      <div class="table-wrap"><table class="list">
        <thead><tr><th>Block</th><th>Result</th><th class="hide-sm">Details</th></tr></thead>
        <tbody>
          {#each preview.report as r}
            <tr><td class="mono small">{r.block}</td><td><span class="badge {statusBadge[r.status] || ''}">{statusLabel[r.status] || r.status}</span></td><td class="hide-sm small muted">{r.detail}</td></tr>
          {/each}
        </tbody>
      </table></div>
      {#if preview.raw_blocks?.length}
        <p class="muted small">Blocks “kept for review” land under <strong>Snippets &amp; raw</strong>, disabled, with the original config so you can convert them by hand.</p>
      {/if}

      <label class="check"><input type="checkbox" bind:checked={settings} /> Also import global options (email, certificate authority)</label>
      <label class="check"><input type="checkbox" bind:checked={replace} /> Replace my existing sites (otherwise hostnames that already exist are skipped)</label>
      <div class="row"><button class="btn primary" onclick={commit} disabled={busy}><FileInput size={15} /> Import {preview.sites.length} site(s)</button></div>
    </div>
  {/if}

  {#if done && !embedded}
    <div class="alert ok"><CircleCheck /><span>
      Imported {done.sites} site(s){#if done.credentials}, {done.credentials} DNS account(s){/if}{#if done.raw_blocks}, {done.raw_blocks} block(s) kept for review{/if}.
      {#if done.skipped?.length}Skipped (already exist): {done.skipped.join(', ')}.{/if}
      <div class="row" style="margin-top:8px"><button class="btn primary sm" onclick={() => go('/changes')}>Review & apply</button><button class="btn sm" onclick={() => go('/sites')}>See sites</button></div>
    </span></div>
  {/if}
</div>

<style>
  .found { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; border-color: color-mix(in srgb, var(--accent) 45%, var(--border));
    background: linear-gradient(120deg, var(--accent-soft), var(--surface) 75%); }
  .found.active { box-shadow: 0 0 0 3px var(--ring); }
  .f-ic { width: 42px; height: 42px; border-radius: 12px; display: grid; place-items: center; background: var(--accent); color: var(--accent-text); flex: none; }
  .f-title { font-weight: 600; font-size: 14.5px; }
  .hosts { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 8px; align-items: center; }
  ul { margin: 6px 0 0; padding-left: 18px; }
</style>
