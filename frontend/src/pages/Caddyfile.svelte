<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import { toastErr } from '../lib/state.svelte.js'
  import { download } from '../lib/util.js'

  let out = $state(null)
  let copied = $state(false)
  onMount(async () => { try { out = await api.get('/config/preview') } catch (e) { toastErr(e) } })
  async function copy() { await navigator.clipboard.writeText(out.caddyfile); copied = true; setTimeout(() => (copied = false), 1500) }
</script>

<div class="page-head">
  <div>
    <h1>Caddyfile</h1>
    <div class="sub">The full config generated from your sites and settings. You can always export it and run Caddy without CaddyHub.</div>
  </div>
  {#if out}
    <div class="row right">
      <button class="btn" onclick={copy}>{copied ? 'Copied' : 'Copy'}</button>
      <button class="btn primary" onclick={() => download('Caddyfile', out.caddyfile)}>Download</button>
    </div>
  {/if}
</div>
{#if out}
  {#each out.warnings || [] as w}<div class="alert warn" style="margin-bottom:10px">{w}</div>{/each}
  <pre>{out.caddyfile}</pre>
  <p class="muted small" style="margin-top:10px">Want to change something CaddyHub has no field for? Use a site's “Custom Caddyfile” box, a snippet, or a raw block. Editing this file directly would be overwritten on the next apply.</p>
{:else}
  <p class="muted">Loading…</p>
{/if}
