<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import { toastErr } from '../lib/state.svelte.js'
  import { ago, when } from '../lib/util.js'

  let entries = $state([])
  let q = $state('')
  let offset = $state(0)
  const limit = 100

  async function load() {
    try { entries = await api.get(`/audit?limit=${limit}&offset=${offset}&q=${encodeURIComponent(q)}`) } catch (e) { toastErr(e) }
  }
  onMount(load)
  let t
  function search() { clearTimeout(t); t = setTimeout(() => { offset = 0; load() }, 250) }
</script>

<div class="page-head">
  <div><h1>Audit log</h1><div class="sub">Who changed what, and when.</div></div>
</div>

<div class="row" style="margin-bottom:12px">
  <input type="text" placeholder="Search user, action, target…" bind:value={q} oninput={search} style="max-width:360px" />
</div>

<div class="card flush table-wrap">
  <table class="list">
    <thead><tr><th>When</th><th>User</th><th>Action</th><th class="hide-sm">Target</th><th class="hide-sm">Details</th><th class="hide-sm">IP</th></tr></thead>
    <tbody>
      {#each entries as e}
        <tr>
          <td class="nowrap" title={when(e.ts)}>{ago(e.ts)}</td>
          <td>{e.user}</td><td class="mono small">{e.action}</td>
          <td class="hide-sm">{e.target}</td><td class="hide-sm small">{e.details}</td><td class="hide-sm mono small">{e.ip}</td>
        </tr>
      {/each}
    </tbody>
  </table>
  {#if entries.length === 0}<div class="empty">No entries.</div>{/if}
</div>
<div class="row" style="margin-top:12px">
  <button class="btn sm" disabled={offset === 0} onclick={() => { offset = Math.max(0, offset - limit); load() }}>← Newer</button>
  <button class="btn sm" disabled={entries.length < limit} onclick={() => { offset += limit; load() }}>Older →</button>
</div>
