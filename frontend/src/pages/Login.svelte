<script>
  import { api, setCSRF } from '../lib/api.js'
  import { app } from '../lib/state.svelte.js'

  let { onlogin } = $props()
  let username = $state('')
  let password = $state('')
  let password2 = $state('')
  let token = $state('')
  let code = $state('')
  let error = $state('')
  let busy = $state(false)

  const setup = $derived(app.me?.needs_setup)
  const twofa = $derived(app.me?.pending_2fa)

  async function submit(e) {
    e.preventDefault()
    error = ''
    if (setup && password !== password2) { error = "Passwords don't match"; return }
    busy = true
    try {
      let res
      if (twofa) res = await api.post('/login/totp', { code })
      else if (setup) res = await api.post('/setup', { username, password, token })
      else res = await api.post('/login', { username, password })
      setCSRF(res.csrf)
      if (res.pending_2fa) { app.me = { ...app.me, ...res }; busy = false; return }
      await onlogin()
    } catch (err) {
      error = err.message
    }
    busy = false
  }
</script>

<div class="wrap">
  <form class="card box" onsubmit={submit}>
    <div class="brand"><img src="/favicon.svg" alt="" width="34" height="34" /> CaddyHub</div>
    {#if twofa}
      <h2>Two-factor code</h2>
      <p class="muted">Enter the 6-digit code from your authenticator app.</p>
      <label class="field"><span>Code</span>
        <input type="text" inputmode="numeric" autocomplete="one-time-code" bind:value={code} required />
      </label>
    {:else if setup}
      <h2>Welcome! Create your admin account</h2>
      <p class="muted">This account manages your Caddy server. You can add more users later.</p>
      {#if app.me?.setup_token_required}
        <label class="field"><span>Setup token</span>
          <input type="password" bind:value={token} required />
          <span class="hint">The value of CADDYHUB_SETUP_TOKEN from your server's environment.</span>
        </label>
      {/if}
      <label class="field"><span>Username</span><input type="text" autocomplete="username" bind:value={username} required /></label>
      <label class="field"><span>Password</span>
        <input type="password" autocomplete="new-password" bind:value={password} required minlength="10" />
        <span class="hint">At least 10 characters. A few random words works well.</span>
      </label>
      <label class="field"><span>Repeat password</span><input type="password" autocomplete="new-password" bind:value={password2} required /></label>
    {:else}
      <h2>Log in</h2>
      <label class="field"><span>Username</span><input type="text" autocomplete="username" bind:value={username} required /></label>
      <label class="field"><span>Password</span><input type="password" autocomplete="current-password" bind:value={password} required /></label>
    {/if}
    {#if error}<div class="alert err">{error}</div>{/if}
    <button class="btn primary" type="submit" disabled={busy}>
      {busy ? 'Please wait…' : twofa ? 'Verify' : setup ? 'Create account' : 'Log in'}
    </button>
  </form>
</div>

<style>
  .wrap { min-height: 100vh; display: grid; place-items: center; padding: 16px; }
  .box { width: 100%; max-width: 400px; display: flex; flex-direction: column; gap: 14px; padding: 28px; }
  .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 18px; margin-bottom: 6px; }
  h2 { margin: 0; }
  p { margin: -6px 0 0; }
</style>
