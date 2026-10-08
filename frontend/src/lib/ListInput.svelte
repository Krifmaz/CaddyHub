<script>
  // Edits a list of strings, one input per item.
  let { items = $bindable(), placeholder = '', addLabel = 'Add' } = $props()
  if (!Array.isArray(items)) items = []
  if (items.length === 0) items = ['']
</script>

<div class="list">
  {#each items as _, i}
    <div class="row item">
      <input type="text" bind:value={items[i]} {placeholder} />
      <button class="btn ghost icon" type="button" aria-label="Remove" onclick={() => { items.splice(i, 1); if (!items.length) items.push('') }}>✕</button>
    </div>
  {/each}
  <div><button class="btn sm" type="button" onclick={() => items.push('')}>+ {addLabel}</button></div>
</div>

<style>
  .list { display: flex; flex-direction: column; gap: 6px; }
  .item { flex-wrap: nowrap; gap: 4px; }
</style>
