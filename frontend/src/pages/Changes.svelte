<script>
  import { onMount } from 'svelte'
  import { RefreshCw, ShieldCheck, CircleCheck, CircleX, Info, TriangleAlert, Rocket, FlaskConical, FileCode, Undo2 } from '@lucide/svelte'
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
  const resultView = {
    applied: { cls: 'ok', icon: CircleCheck, title: 'Applied' },
    dry_run: { cls: 'info', icon: Info, title: 'Dry run passed. The config is valid; nothing was applied.' },
    rolled_back: { cls: 'err', icon: Undo2, title: 'Rolled back' },
  }
</script>

<div class="page-head">
  <div>
    <h1>Review & apply</h1>
    <div class="sub">CaddyHub writes the Caddyfile, Caddy checks it, you see exactly what changes. If Caddy isn't healthy after applying, the previous config is restored automatically.</div>
  </div>
  <button class="btn right" onclick={load} disabled={loading}><RefreshCw size={15} class={loading ? 'spin' : ''} /> Refresh</button>
</div>

{#if loading && !plan}
  <div class="card loading"><RefreshCw size={18} class="spin" /> Generating and validating with Caddy…</div>
{:else if plan}
  <div class="stack">
    {#if result}
      {@const v = resultView[result.status] || { cls: 'err', icon: CircleX, title: `Not applied (${result.status})` }}
      <div class="alert {v.cls}"><v.icon /><span><strong>{v.title}.</strong> {result.status !== 'dry_run' ? result.message : ''}</span></div>
    {/if}

    <div class="summary card">
      <div class="sum-item">
        <span class="sum-ic {plan.valid ? 'ok' : 'err'}">{#if plan.valid}<ShieldCheck size={20} />{:else}<CircleX size={20} />{/if}</span>
        <div><div class="sum-label">Validation</div><div class="sum-val">{plan.valid ? 'Passed' : 'Failed'}</div></div>
      </div>
      <div class="sum-item">
        <span class="sum-ic"><FileCode size={20} /></span>
        <div>
          <div class="sum-label">Changes</div>
          <div class="sum-val">
            {#if plan.changed}<span class="plus">+{plan.added}</span> <span class="minus">−{plan.removed}</span> lines{:else}None{/if}
          </div>
        </div>
      </div>
      {#if can.edit()}
        <div class="sum-actions">
          <button class="btn" onclick={() => run(true)} disabled={applying}><FlaskConical size={15} /> Dry run</button>
          <button class="btn primary" onclick={() => run(false)} disabled={applying || !plan.valid}>
            <Rocket size={15} /> {applying ? 'Applying…' : 'Apply to Caddy'}
          </button>
        </div>
      {/if}
    </div>

    <Errors {plan} />
    {#each plan.warnings || [] as w}<div class="alert warn"><TriangleAlert /><span>{w}</span></div>{/each}

    {#if can.edit() && plan.valid && plan.changed}
      <input type="text" bind:value={message} placeholder="Optional note for the history, e.g. “added jellyfin”" />
    {/if}

    <div class="card stack">
      <div class="card-head">
        <div><h2>Diff</h2><div class="desc">{plan.previous_id ? `Compared with the last applied version (#${plan.previous_id})` : 'First apply: everything is new'}</div></div>
      </div>
      {#if plan.changed}
        <Diff diff={plan.diff} />
      {:else}
        <div class="empty"><div class="icon-wrap"><CircleCheck size={22} /></div><p>Caddy is already running this exact config.</p></div>
      {/if}
    </div>

    <div>
      <button class="btn ghost sm" onclick={() => (showFull = !showFull)}><FileCode size={15} /> {showFull ? 'Hide' : 'Show'} the full generated Caddyfile</button>
      {#if showFull}<pre style="margin-top:10px">{plan.caddyfile}</pre>{/if}
    </div>
  </div>
{/if}

<style>
  .loading { display: flex; align-items: center; gap: 10px; color: var(--muted); }
  .summary { display: flex; align-items: center; gap: 28px; flex-wrap: wrap; padding: 16px 18px; }
  .sum-item { display: flex; align-items: center; gap: 12px; }
  .sum-ic { width: 40px; height: 40px; border-radius: 10px; display: grid; place-items: center; background: var(--surface-2); color: var(--muted); }
  .sum-ic.ok { background: var(--ok-soft); color: var(--ok); }
  .sum-ic.err { background: var(--danger-soft); color: var(--danger); }
  .sum-label { font-size: 12px; color: var(--muted); }
  .sum-val { font-weight: 650; font-size: 15px; letter-spacing: -0.01em; }
  .plus { color: var(--ok); }
  .minus { color: var(--danger); }
  .sum-actions { margin-left: auto; display: flex; gap: 8px; }
  :global(.spin) { animation: spin 0.9s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @media (max-width: 640px) { .sum-actions { margin-left: 0; width: 100%; } .sum-actions .btn { flex: 1; } }
</style>
