<script>
  import { api } from '../lib/api.js'
  import { toast, toastErr, refreshStatus } from '../lib/state.svelte.js'
  import { go } from '../lib/router.svelte.js'

  let { embedded = false, ondone } = $props()
  let text = $state('')
  let preview = $state(null)
  let replace = $state(false)
  let settings = $state(true)
  let busy = $state(false)
  let done = $state(null)

  async function file(e) {
    const f = e.target.files?.[0]
    if (f) { text = await f.text(); preview = null }
  }
  async function analyze() {
    busy = true; preview = null; done = null
    try { preview = await api.post('/import/preview', { caddyfile: text }) } catch (e) { toastErr(e) }
    busy = false
  }
  async function commit() {
    if (replace && !confirm('Replace ALL existing sites, snippets and raw blocks with the imported ones?')) return
    busy = true
    try {
      done = await api.post('/import/commit', { caddyfile: text, replace, settings })
      toast(`Imported ${done.sites} site(s). Review and apply when ready.`)
      refreshStatus()
      ondone?.(done)
    } catch (e) { toastErr(e) }
    busy = false
  }
  const statusBadge = { structured: 'ok', partial: 'warn', raw: 'accent', skipped: 'err' }
  const ph = 'example.com {\n\treverse_proxy localhost:8080\n}'
</script>

{#if !embedded}
  <div class="page-head">
    <div>
      <h1>Import a Caddyfile</h1>
      <div class="sub">Paste or upload your existing Caddyfile. CaddyHub turns what it understands into editable sites and keeps everything else verbatim, so nothing is lost. Nothing goes live until you apply.</div>
    </div>
  </div>
{/if}

<div class="stack">
  <div class="card stack">
    <div class="row">
      <label class="btn sm">Choose file… <input type="file" class="hidden" onchange={file} /></label>
      <span class="muted small">or paste below</span>
    </div>
    <textarea rows="14" bind:value={text} placeholder={ph}></textarea>
    <div><button class="btn primary" onclick={analyze} disabled={busy || !text.trim()}>Analyze</button></div>
  </div>

  {#if preview}
    <div class="card stack">
      <h2>What will be imported</h2>
      <div class="row small">
        <span class="badge">{preview.sites.length} sites</span>
        <span class="badge">{preview.snippets.length} snippets</span>
        <span class="badge">{preview.raw_blocks.length} raw blocks</span>
        {#if preview.domains?.length}<span class="badge">{preview.domains.length} domains</span>{/if}
        {#if preview.credentials?.length}<span class="badge">{preview.credentials.length} DNS accounts</span>{/if}
      </div>
      <div class="table-wrap"><table class="list">
        <thead><tr><th>Block</th><th>Result</th><th class="hide-sm">Details</th></tr></thead>
        <tbody>
          {#each preview.report as r}
            <tr><td class="mono small">{r.block}</td><td><span class="badge {statusBadge[r.status] || ''}">{r.status}</span></td><td class="hide-sm small">{r.detail}</td></tr>
          {/each}
        </tbody>
      </table></div>
      <p class="muted small"><strong>structured</strong>: fully editable with forms · <strong>partial</strong>: forms plus leftover directives in the site's custom box · <strong>raw</strong>: kept verbatim as a raw block</p>
      <label class="check"><input type="checkbox" bind:checked={settings} /> Also import global options (email, certificate authority, other options)</label>
      <label class="check"><input type="checkbox" bind:checked={replace} /> Replace my existing sites (otherwise sites whose hostnames already exist are skipped)</label>
      <div class="row"><button class="btn primary" onclick={commit} disabled={busy}>Import</button></div>
    </div>
  {/if}

  {#if done && !embedded}
    <div class="alert ok stack">
      <div>Imported {done.sites} site(s), {done.snippets} snippet(s), {done.raw_blocks} raw block(s).
        {#if done.skipped?.length}Skipped (already exist): {done.skipped.join(', ')}.{/if}</div>
      <div class="row"><button class="btn primary sm" onclick={() => go('/changes')}>Review & apply</button><button class="btn sm" onclick={() => go('/sites')}>See sites</button></div>
    </div>
  {/if}
</div>
