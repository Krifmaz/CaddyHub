<script>
  import { X } from '@lucide/svelte'
  let { title, description = '', onclose, children, footer, wide = false } = $props()
  function key(e) { if (e.key === 'Escape') onclose?.() }
</script>

<svelte:window onkeydown={key} />
<div class="backdrop" role="presentation" onclick={(e) => e.target === e.currentTarget && onclose?.()}>
  <div class="modal" class:wide role="dialog" aria-modal="true" aria-label={title}>
    <header>
      <div class="grow">
        <h2>{title}</h2>
        {#if description}<p class="muted small">{description}</p>{/if}
      </div>
      <button class="btn ghost icon sm" aria-label="Close" onclick={() => onclose?.()}><X size={18} /></button>
    </header>
    <div class="content">{@render children()}</div>
    {#if footer}<footer>{@render footer()}</footer>{/if}
  </div>
</div>

<style>
  .backdrop {
    position: fixed; inset: 0; background: rgba(9, 9, 11, 0.45); backdrop-filter: blur(3px); z-index: 60;
    display: flex; align-items: flex-start; justify-content: center; padding: 8vh 16px 16px; overflow-y: auto;
    animation: fade 0.12s;
  }
  .modal {
    background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-lg);
    width: 100%; max-width: 540px; box-shadow: var(--shadow-lg); animation: pop 0.16s ease-out;
  }
  .modal.wide { max-width: 920px; }
  header { display: flex; align-items: flex-start; gap: 12px; padding: 20px 20px 4px 24px; }
  header h2 { font-size: 17px; }
  header p { margin-top: 4px; }
  .content { padding: 16px 24px 24px; display: flex; flex-direction: column; gap: 16px; }
  footer {
    display: flex; justify-content: flex-end; gap: 8px; padding: 14px 24px; border-top: 1px solid var(--border);
    flex-wrap: wrap; background: var(--surface-2); border-radius: 0 0 var(--radius-lg) var(--radius-lg);
  }
  @keyframes fade { from { opacity: 0; } }
  @keyframes pop { from { opacity: 0; transform: scale(0.97) translateY(8px); } }
</style>
