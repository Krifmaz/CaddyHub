<script>
  let { title, onclose, children, footer, wide = false } = $props()
  function key(e) { if (e.key === 'Escape') onclose?.() }
</script>

<svelte:window onkeydown={key} />
<div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose?.()}>
  <div class="modal" class:wide role="dialog" aria-modal="true" aria-label={title}>
    <header>
      <h2>{title}</h2>
      <button class="btn ghost icon" aria-label="Close" onclick={() => onclose?.()}>✕</button>
    </header>
    <div class="content">{@render children()}</div>
    {#if footer}<footer>{@render footer()}</footer>{/if}
  </div>
</div>

<style>
  .backdrop {
    position: fixed; inset: 0; background: rgba(10, 14, 18, 0.5); z-index: 50;
    display: flex; align-items: flex-start; justify-content: center; padding: 6vh 16px; overflow-y: auto;
  }
  .modal {
    background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    width: 100%; max-width: 520px; box-shadow: 0 20px 50px rgba(0, 0, 0, 0.3);
  }
  .modal.wide { max-width: 900px; }
  header { display: flex; align-items: center; padding: 14px 16px 0 18px; }
  header h2 { margin: 0; flex: 1; }
  .content { padding: 14px 18px 18px; display: flex; flex-direction: column; gap: 14px; }
  footer { display: flex; justify-content: flex-end; gap: 8px; padding: 12px 18px; border-top: 1px solid var(--border); flex-wrap: wrap; }
</style>
