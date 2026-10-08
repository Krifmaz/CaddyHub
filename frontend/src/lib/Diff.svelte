<script>
  // Unified diff with old/new line numbers and highlighted changes.
  let { diff = '' } = $props()

  const rows = $derived.by(() => {
    const out = []
    let a = 0, b = 0
    for (const l of (diff || '').split('\n')) {
      if (l.startsWith('+++') || l.startsWith('---') || l === '') continue
      const m = l.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/)
      if (m) { a = +m[1]; b = +m[2]; out.push({ t: 'hunk', text: l }); continue }
      if (l[0] === '+') out.push({ t: 'add', b: b++, text: l.slice(1) })
      else if (l[0] === '-') out.push({ t: 'del', a: a++, text: l.slice(1) })
      else out.push({ t: 'ctx', a: a++, b: b++, text: l.slice(1) })
    }
    return out
  })
</script>

{#if rows.length}
  <div class="diff">
    <table>
      <tbody>
        {#each rows as r}
          {#if r.t === 'hunk'}
            <tr class="hunk"><td colspan="4">{r.text}</td></tr>
          {:else}
            <tr class={r.t}>
              <td class="n">{r.a ?? ''}</td><td class="n">{r.b ?? ''}</td>
              <td class="sign">{r.t === 'add' ? '+' : r.t === 'del' ? '−' : ''}</td>
              <td class="code">{r.text}</td>
            </tr>
          {/if}
        {/each}
      </tbody>
    </table>
  </div>
{:else}
  <p class="muted">No differences.</p>
{/if}

<style>
  .diff { border: 1px solid var(--border); border-radius: var(--radius); overflow: auto; background: var(--code-bg); }
  table { border-collapse: collapse; width: 100%; font: 12.5px/1.7 var(--mono); }
  td { padding: 0 8px; white-space: pre; vertical-align: top; }
  .n { width: 1%; text-align: right; color: var(--faint); user-select: none; padding: 0 8px; min-width: 38px; }
  .sign { width: 1%; user-select: none; color: var(--faint); padding: 0 4px; }
  .code { color: var(--text-2); width: 100%; tab-size: 4; }
  tr.add { background: var(--add); }
  tr.add .code, tr.add .sign { color: var(--add-text); }
  tr.add .n { background: var(--add-gutter); color: var(--add-text); }
  tr.del { background: var(--del); }
  tr.del .code, tr.del .sign { color: var(--del-text); }
  tr.del .n { background: var(--del-gutter); color: var(--del-text); }
  tr.hunk td { color: var(--muted); background: var(--surface-2); padding: 4px 12px; font-size: 11.5px; border-block: 1px solid var(--border); }
  tr.hunk:first-child td { border-top: 0; }
</style>
