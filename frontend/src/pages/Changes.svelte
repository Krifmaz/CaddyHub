<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import { toast, toastErr, refreshStatus, can } from '../lib/state.svelte.js'
  import Diff from '../lib/Diff.svelte'
  import Errors from '../lib/Errors.svelte'

  let plan = $state(null)
  let loading = $state(true)
  let applying = $state(false)
  let result = $state(null)
  let message = $state('')
  let showFull = $state(false)

  async function load() {
    loading = true
    result = null
    try { plan = await api.post('/config/plan') } catch (e) { toastErr(e) }
    loading = false
  }
  onMount(load)

  async function run(dry) {
    applying = true
    result = null
    try {
      result = await api.post('/config/apply', { dry_run: dry, message })
      if (result.status === 'applied') { toast('Applied. Caddy is running the new config.'); message = '' }
      refreshStatus()
      if (result.plan) plan = result.plan
    } catch (e) { toastErr(e) }
    applying = false
  }
</script>

<div class="page-head">
  <div>
    <h1>Review & apply</h1>
    <div class="sub">CaddyHub generates the Caddyfile, has Caddy check it, shows you what changes, then loads it. If Caddy isn't healthy afterwards it rolls back automatically.</div>
  </div>
  <button class="btn right" onclick={load} disabled={loading}>Refresh</button>
</div>

{#if loading && !plan}
  <p class="muted">Generating and validating…</p>
{:else if plan}
  <div class="stack">
    {#if result}
      {#if result.status === 'applied'}
        <div class="alert ok"><strong>Applied.</strong> {result.message}</div>
      {:else if result.status === 'dry_run'}
        <div class="alert info"><strong>Dry run passed.</strong> The config is valid; nothing was applied.</div>
      {:else if result.status === 'rolled_back'}
        <div class="alert err"><strong>Rolled back.</strong> {result.message}</div>
      {:else}
        <div class="alert err"><strong>Not applied ({result.status}).</strong> {result.message}</div>
      {/if}
    {/if}

    <Errors {plan} />
    {#each plan.warnings || [] as w}<div class="alert warn">{w}</div>{/each}

    <div class="card stack">
      <div class="row">
        <h2 style="margin:0">Changes</h2>
        {#if plan.changed}
          <span class="badge ok">+{plan.added}</span><span class="badge err">−{plan.removed}</span>
        {:else}
          <span class="badge">nothing changed since the last apply</span>
        {/if}
        {#if plan.valid}<span class="badge ok right">✓ Caddy validated this config</span>{/if}
      </div>
      {#if plan.changed}<Diff diff={plan.diff} />{/if}
      {#if !plan.previous_id}<p class="muted small">This is the first config CaddyHub applies, so everything is new.</p>{/if}
    </div>

    {#if can.edit()}
      <div class="card stack">
        <label class="field"><span>Note (optional)</span><input type="text" bind:value={message} placeholder="e.g. added jellyfin" /></label>
        <div class="row">
          <button class="btn primary" onclick={() => run(false)} disabled={applying || !plan.valid}>{applying ? 'Applying…' : 'Apply to Caddy'}</button>
          <button class="btn" onclick={() => run(true)} disabled={applying}>Dry run (validate only)</button>
        </div>
      </div>
    {/if}

    <div>
      <button class="btn ghost sm" onclick={() => (showFull = !showFull)}>{showFull ? 'Hide' : 'Show'} the full generated Caddyfile</button>
      {#if showFull}<pre style="margin-top:8px">{plan.caddyfile}</pre>{/if}
    </div>
  </div>
{/if}
