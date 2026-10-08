<script>
  // Edits a string map as rows. The parent binds `value` (object or null).
  let { value = $bindable(), keyPlaceholder = 'Name', valuePlaceholder = 'Value', addLabel = 'Add' } = $props()
  let rows = $state(Object.entries(value || {}).map(([k, v]) => ({ k, v })))
  $effect(() => {
    const o = {}
    for (const r of rows) if (r.k.trim()) o[r.k.trim()] = r.v
    value = Object.keys(o).length ? o : undefined
  })
</script>

<div class="list">
  {#each rows as r, i}
    <div class="row item">
      <input type="text" bind:value={r.k} placeholder={keyPlaceholder} class="k" />
      <input type="text" bind:value={r.v} placeholder={valuePlaceholder} />
      <button class="btn ghost icon" type="button" aria-label="Remove" onclick={() => rows.splice(i, 1)}>✕</button>
    </div>
  {/each}
  <div><button class="btn sm" type="button" onclick={() => rows.push({ k: '', v: '' })}>+ {addLabel}</button></div>
</div>

<style>
  .list { display: flex; flex-direction: column; gap: 6px; }
  .item { flex-wrap: nowrap; gap: 4px; }
  .k { max-width: 40%; }
</style>
