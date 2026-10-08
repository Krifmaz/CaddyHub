<script>
  import { X, Plus } from '@lucide/svelte'
  // Edits a list of strings, one input per item.
  let { items = $bindable(), placeholder = '', addLabel = 'Add' } = $props()
  if (!Array.isArray(items)) items = []
  if (items.length === 0) items = ['']
</script>

<div class="list">
  {#each items as _, i}
    <div class="item">
      <input type="text" bind:value={items[i]} {placeholder} />
      {#if items.length > 1 || items[i]}
        <button class="btn ghost icon sm" type="button" aria-label="Remove" onclick={() => { items.splice(i, 1); if (!items.length) items.push('') }}><X size={16} /></button>
      {/if}
    </div>
  {/each}
  <div><button class="btn xs" type="button" onclick={() => items.push('')}><Plus size={14} /> {addLabel}</button></div>
</div>

<style>
  .list { display: flex; flex-direction: column; gap: 6px; }
  .item { display: flex; gap: 4px; align-items: center; }
</style>
