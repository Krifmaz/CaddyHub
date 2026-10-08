<script>
  // Renders a unified diff with added/removed lines highlighted.
  let { diff = '' } = $props()
  const lines = $derived((diff || '').split('\n').filter((l, i, a) => !(i === a.length - 1 && l === '')))
  function cls(l) {
    if (l.startsWith('+++') || l.startsWith('---')) return 'meta'
    if (l.startsWith('@@')) return 'hunk'
    if (l.startsWith('+')) return 'add'
    if (l.startsWith('-')) return 'del'
    return ''
  }
</script>

{#if lines.length}
  <pre class="diff">{#each lines as l}<span class={cls(l)}>{l || ' '}</span>{'\n'}{/each}</pre>
{:else}
  <p class="muted">No differences.</p>
{/if}

<style>
  .diff { padding: 8px 0; }
  .diff span { display: inline-block; min-width: 100%; padding: 0 14px; }
  .add { background: var(--add); color: var(--add-text); }
  .del { background: var(--del); color: var(--del-text); }
  .hunk { color: var(--accent); }
  .meta { color: var(--muted); font-weight: 600; }
</style>
