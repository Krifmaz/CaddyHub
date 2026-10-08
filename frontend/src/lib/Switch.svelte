<script>
  let { checked = $bindable(false), disabled = false, label = '', onchange } = $props()
</script>

<label class="switch" title={label}>
  <input type="checkbox" bind:checked {disabled} aria-label={label} onchange={() => onchange?.(checked)} />
  <span></span>
</label>
