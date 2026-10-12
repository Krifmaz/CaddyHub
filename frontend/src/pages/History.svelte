<script>
  import { History as HistoryIcon, Download, Undo2 } from '@lucide/svelte'
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import { toast, toastErr, refreshStatus, can } from '../lib/state.svelte.js'
  import { ago, when, download } from '../lib/util.js'
  import Modal from '../lib/Modal.svelte'
  import Diff from '../lib/Diff.svelte'

  let versions = $state(null)
  let open = $state(null)     // version with caddyfile
  let tab = $state('diff')
  let diff = $state(null)
  let busy = $state(false)

  const badge = { applied: 'ok', dry_run: 'accent', invalid: 'err', failed: 'err', rolled_back: 'warn' }

  async function load() { try { versions = await api.get('/versions?limit=100') } catch (e) { toastErr(e) } }
  onMount(load)

  async function show(v) {
    tab = 'diff'
    diff = null
    try {
      open = await api.get('/versions/' + v.id)
      const prev = versions.find((x) => x.id < v.id && x.good)
      diff = prev ? await api.get(`/versions/diff?a=${prev.id}&b=${v.id}`).catch(() => null) : { diff: '', first: true }
    } catch (e) { toastErr(e) }
  }
  async function diffPending() {
    tab = 'pending'
    diff = await api.get(`/versions/diff?a=${open.id}&b=0`).catch((e) => { toastErr(e); return null })
  }
  async function rollback() {
    const msg = open.snapshot
      ? `Restore version ${open.id}? Caddy will run exactly that Caddyfile again (it's validated first), and the sites and settings in CaddyHub go back to that version too. Unapplied edits are lost.`
      : `Re-apply version ${open.id}? Caddy will run exactly that Caddyfile again (it's validated first).\n\nThis version was applied before CaddyHub saved sites with versions, so your sites and settings are not changed; the next normal apply will use them again.`
    if (!confirm(msg)) return
    busy = true
    try {
      const r = await api.post(`/versions/${open.id}/rollback`)
      if (r.status === 'applied') toast('Rolled back to version ' + open.id)
      else toast(r.message, 'err', 8000)
      open = null
      load(); refreshStatus()
    } catch (e) { toastErr(e) }
    busy = false
  }
</script>

<div class="page-head">
  <div>
    <h1>History</h1>
    <div class="sub">Every apply attempt is recorded with its exact Caddyfile. Successful ones can be restored with one click.</div>
  </div>
</div>

{#if versions === null}
  <p class="muted">Loading…</p>
{:else if versions.length === 0}
  <div class="card empty"><div class="icon-wrap"><HistoryIcon size={22} /></div><h2>Nothing applied yet</h2><p>Versions appear here once you apply a config.</p></div>
{:else}
  <div class="card flush table-wrap">
    <table class="list">
      <thead><tr><th>#</th><th>When</th><th>Result</th><th class="hide-sm">By</th><th class="hide-sm">Message</th></tr></thead>
      <tbody>
        {#each versions as v (v.id)}
          <tr class="clickable" onclick={() => show(v)}>
            <td class="mono">{v.id}</td>
            <td class="nowrap" title={when(v.created_at)}>{ago(v.created_at)}</td>
            <td><span class="badge {badge[v.status] || ''}">{v.status.replace('_', ' ')}</span></td>
            <td class="hide-sm">{v.user}</td>
            <td class="hide-sm small msg">{v.message}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}

{#if open}
  <Modal title={`Version ${open.id}`} wide onclose={() => (open = null)}>
    <div class="row small">
      <span class="badge {badge[open.status] || ''}">{open.status.replace('_', ' ')}</span>
      <span class="muted">{when(open.created_at)} · {open.user} · Caddy {open.caddy_version || '?'}</span>
      {#if open.good}
        {#if open.snapshot}<span class="badge accent" title="Restoring this version also brings back its sites and settings">sites &amp; settings saved</span>{:else}<span class="badge" title="Applied before CaddyHub saved sites with versions; only the Caddyfile can be re-applied">Caddyfile only</span>{/if}
      {/if}
    </div>
    {#if open.message}<p class="small">{open.message}</p>{/if}
    <div class="tabs">
      <button class:active={tab === 'diff'} onclick={() => show(open)}>Changes in this version</button>
      <button class:active={tab === 'pending'} onclick={diffPending}>Compare with current</button>
      <button class:active={tab === 'file'} onclick={() => (tab = 'file')}>Caddyfile</button>
    </div>
    {#if tab === 'file'}
      <pre class="scroll">{open.caddyfile}</pre>
    {:else if diff?.first}
      <p class="muted">This is the first applied version.</p>
    {:else if diff}
      <div class="scroll"><Diff diff={diff.diff} /></div>
    {:else}
      <p class="muted">Loading…</p>
    {/if}
    {#snippet footer()}
      <button class="btn" onclick={() => download(`Caddyfile.v${open.id}`, open.caddyfile)}><Download size={15} /> Download</button>
      {#if can.edit() && open.good}<button class="btn primary" onclick={rollback} disabled={busy}><Undo2 size={15} /> Restore this version</button>{/if}
    {/snippet}
  </Modal>
{/if}

<style>
  .msg { max-width: 420px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .scroll { max-height: 55vh; overflow: auto; }
</style>
