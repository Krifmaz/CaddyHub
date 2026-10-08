<script>
  import { CircleX } from '@lucide/svelte'
  // Shows caddy adapt/validate messages from a plan.
  let { plan } = $props()
</script>

{#if plan && !plan.valid}
  <div class="alert err">
    <CircleX />
    <div class="grow">
      <strong>Caddy rejected this config at the {plan.stage} step. Nothing was changed.</strong>
      <ul>
        {#each plan.errors || [] as e}<li class="mono">{e.text}</li>{/each}
      </ul>
    </div>
  </div>
{/if}

<style>
  ul { margin: 6px 0 0; padding-left: 18px; }
  li { white-space: pre-wrap; word-break: break-word; }
</style>
