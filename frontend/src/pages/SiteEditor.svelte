<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import { app, toast, toastErr, refreshStatus, loadMeta, can } from '../lib/state.svelte.js'
  import { go } from '../lib/router.svelte.js'
  import { clone } from '../lib/util.js'
  import ListInput from '../lib/ListInput.svelte'
  import KVInput from '../lib/KVInput.svelte'
  import Switch from '../lib/Switch.svelte'
  import { templates } from '../lib/templates.js'

  let { id } = $props()
  const isNew = $derived(id === 'new')

  function blank() {
    return {
      name: '', hosts: [''], kind: 'proxy', enabled: true, tags: [],
      config: { proxy: { upstreams: [''] }, tls: { mode: 'auto' }, access: {}, routes: [] },
    }
  }

  let site = $state(null)
  let tagText = $state('')
  let snippets = $state([])
  let busy = $state(false)
  let error = $state('')
  let rawCheck = $state(null)
  let accessLog = $state('default')

  const feat = (fid) => (app.meta?.features || []).find((f) => f.id === fid)
  const available = (fid) => feat(fid)?.available !== false

  function ensure(s) {
    const c = s.config
    c.tls ||= { mode: 'auto' }
    c.tls.mode ||= 'auto'
    c.access ||= {}
    c.routes ||= []
    c.proxy ||= { upstreams: [''] }
    c.proxy.upstreams = c.proxy.upstreams?.length ? c.proxy.upstreams : ['']
    c.static ||= { root: '' }
    c.redirect ||= { to: '', code: 302 }
    c.respond ||= { status: 200, body: '' }
    c.access.allow_cidrs ||= []
    c.access.deny_cidrs ||= []
    c.access.basic_auth ||= []
    c.headers_remove ||= []
    c.compression ||= []
    c.snippets ||= []
    c.www_redirect ||= ''
    c.proxy.lb_policy ||= ''
    if (!s.hosts?.length) s.hosts = ['']
    return s
  }

  onMount(async () => {
    loadMeta().catch(() => {})
    api.get('/snippets').then((x) => (snippets = x)).catch(() => {})
    try {
      const s = isNew ? blank() : await api.get('/sites/' + id)
      site = ensure(s)
      tagText = (site.tags || []).join(', ')
      accessLog = site.config.access_log == null ? 'default' : site.config.access_log ? 'on' : 'off'
    } catch (e) { toastErr(e); go('/sites') }
  })

  function applyTemplate(t) {
    if (!t) return
    const s = ensure(clone({ ...blank(), ...t.site, config: { ...blank().config, ...t.site.config } }))
    s.hosts = site.hosts.some((h) => h.trim()) ? site.hosts : ['']
    s.name = site.name || t.name
    site = s
    toast(`Filled in ${t.name} defaults. Set the hostname and upstream address.`)
  }

  // Strip the editor-only defaults for handler types the site doesn't use.
  function payload() {
    const s = clone(site)
    const c = s.config
    s.tags = tagText.split(',').map((t) => t.trim()).filter(Boolean)
    s.hosts = s.hosts.map((h) => h.trim()).filter(Boolean)
    for (const k of ['proxy', 'static', 'redirect', 'respond']) if (s.kind !== k) delete c[k]
    if (c.redirect) c.redirect.code = Number(c.redirect.code) || 302
    if (c.respond) c.respond.status = Number(c.respond.status) || 200
    c.access_log = accessLog === 'default' ? null : accessLog === 'on'
    c.access.allow_cidrs = c.access.allow_cidrs.map((x) => x.trim()).filter(Boolean)
    c.access.deny_cidrs = c.access.deny_cidrs.map((x) => x.trim()).filter(Boolean)
    c.headers_remove = c.headers_remove.map((x) => x.trim()).filter(Boolean)
    if (c.access.rate_limit && !c.access.rate_limit.events) delete c.access.rate_limit
    if (c.access.rate_limit) c.access.rate_limit.events = Number(c.access.rate_limit.events)
    if (c.access.forward_auth && !c.access.forward_auth.upstream) delete c.access.forward_auth
    for (const r of c.routes) for (const k of ['proxy', 'static', 'redirect', 'respond']) if (r.kind !== k) delete r[k]
    return s
  }

  async function save(review = false) {
    error = ''
    busy = true
    try {
      const body = payload()
      const saved = isNew ? await api.post('/sites', body) : await api.put('/sites/' + id, body)
      toast('Saved. Apply to make it live.')
      refreshStatus()
      if (review) go('/changes')
      else if (isNew) go('/sites/' + saved.id)
      else { site = ensure(saved); }
    } catch (e) { error = e.message }
    busy = false
  }

  async function remove() {
    if (!confirm(`Delete ${site.name}?`)) return
    try { await api.del('/sites/' + id); toast('Deleted'); refreshStatus(); go('/sites') } catch (e) { toastErr(e) }
  }
  async function duplicate() {
    try { const c = await api.post(`/sites/${id}/clone`); toast('Copy created (disabled)'); go('/sites/' + c.id) } catch (e) { toastErr(e) }
  }
  async function checkRaw() {
    rawCheck = null
    try { rawCheck = await api.post('/config/validate', { text: site.config.raw || '', context: 'site' }) } catch (e) { rawCheck = { valid: false, error: e.message } }
  }

  function addRoute() { site.config.routes.push({ path: '/api/*', kind: 'proxy', strip_prefix: false, proxy: { upstreams: [''] } }) }
  function routeKind(r, k) {
    r.kind = k
    if (k === 'proxy') r.proxy ||= { upstreams: [''] }
    if (k === 'static') r.static ||= { root: '' }
    if (k === 'redirect') r.redirect ||= { to: '', code: 302 }
    if (k === 'respond') r.respond ||= { status: 200, body: '' }
  }
  function toggleComp(alg, on) {
    const c = site.config
    c.compression = on ? [...new Set([...c.compression, alg])] : c.compression.filter((x) => x !== alg)
  }
  function toggleSnippet(name, on) {
    const c = site.config
    c.snippets = on ? [...new Set([...c.snippets, name])] : c.snippets.filter((x) => x !== name)
  }
  function ensureRL() { site.config.access.rate_limit ||= { events: 100, window: '1m', key: '' } }
  function ensureFA() { site.config.access.forward_auth ||= { preset: 'authelia', upstream: '', uri: '/api/authz/forward-auth', copy_headers: ['Remote-User', 'Remote-Groups', 'Remote-Email', 'Remote-Name'] } }
  function faPreset(p) {
    const fa = site.config.access.forward_auth
    fa.preset = p
    if (p === 'authelia') { fa.uri = '/api/authz/forward-auth'; fa.copy_headers = ['Remote-User', 'Remote-Groups', 'Remote-Email', 'Remote-Name'] }
    if (p === 'authentik') { fa.uri = '/outpost.goauthentik.io/auth/caddy'; fa.copy_headers = ['X-Authentik-Username', 'X-Authentik-Groups', 'X-Authentik-Email', 'X-Authentik-Name', 'X-Authentik-Uid'] }
  }
  const ro = $derived(!can.edit())
</script>

{#if !site}
  <p class="muted">Loading…</p>
{:else}
  <div class="page-head">
    <a class="btn ghost sm" href="#/sites">← Sites</a>
    <h1 class="grow">{isNew ? 'New site' : site.name}</h1>
    {#if !isNew && can.edit()}
      <button class="btn sm" onclick={duplicate}>Duplicate</button>
      <button class="btn sm danger" onclick={remove}>Delete</button>
    {/if}
  </div>

  <fieldset class="stack" disabled={ro}>
    {#if isNew}
      <div class="card row">
        <span class="grow"><strong>Start from a template</strong> <span class="muted">(optional): sensible defaults for common self-hosted apps</span></span>
        <select style="max-width:260px" onchange={(e) => applyTemplate(templates.find((t) => t.id === e.target.value))}>
          <option value="">Choose an app…</option>
          {#each templates as t}<option value={t.id}>{t.name}</option>{/each}
        </select>
      </div>
    {/if}

    <div class="card stack">
      <div class="grid2">
        <label class="field"><span>Name</span><input type="text" bind:value={site.name} placeholder="My app" /></label>
        <label class="field"><span>Tags</span><input type="text" bind:value={tagText} placeholder="media, home (comma separated)" /></label>
      </div>
      <div class="field">
        <span>Hostnames</span>
        <ListInput bind:items={site.hosts} placeholder="app.example.com" addLabel="Add hostname" />
        <span class="hint">The address(es) people type in their browser. HTTPS certificates are obtained automatically.</span>
      </div>
      <div class="row">
        <Switch bind:checked={site.enabled} label="Enabled" /> <span>Enabled</span>
      </div>
    </div>

    <div class="card stack">
      <h2>What should this site do?</h2>
      <div class="kinds">
        {#each [['proxy', 'Reverse proxy', 'Forward to an app (e.g. localhost:8080)'], ['static', 'File server', 'Serve files from a folder'], ['redirect', 'Redirect', 'Send visitors to another URL'], ['respond', 'Static response', 'Return fixed text / status'], ['none', 'Custom', 'Write raw Caddyfile directives']] as [k, label, desc]}
          <label class="kind" class:active={site.kind === k}>
            <input type="radio" name="kind" value={k} bind:group={site.kind} />
            <strong>{label}</strong><span class="muted small">{desc}</span>
          </label>
        {/each}
      </div>

      {#if site.kind === 'proxy'}
        <div class="field">
          <span>Upstream address(es)</span>
          <ListInput bind:items={site.config.proxy.upstreams} placeholder="localhost:8080 or https://10.0.0.5:8443" addLabel="Add upstream" />
          <span class="hint">Where your app is listening. More than one = load balancing.</span>
        </div>
        <div class="checks">
          <label class="check"><input type="checkbox" bind:checked={site.config.proxy.websocket} /> WebSockets / streaming</label>
          <label class="check"><input type="checkbox" bind:checked={site.config.proxy.tls_skip_verify} /> Upstream uses a self-signed certificate (skip verify)</label>
          <label class="check"><input type="checkbox" bind:checked={site.config.proxy.h2c} /> gRPC / h2c upstream</label>
        </div>
      {:else if site.kind === 'static'}
        <div class="grid2">
          <label class="field"><span>Folder</span><input type="text" bind:value={site.config.static.root} placeholder="/srv/www" />
            <span class="hint">Path inside the Caddy container.</span></label>
        </div>
        <div class="checks">
          <label class="check"><input type="checkbox" bind:checked={site.config.static.browse} /> Show directory listings</label>
          <label class="check"><input type="checkbox" bind:checked={site.config.static.spa} /> Single-page app (fall back to index.html)</label>
        </div>
      {:else if site.kind === 'redirect'}
        <div class="grid2">
          <label class="field"><span>Redirect to</span><input type="text" bind:value={site.config.redirect.to} placeholder="https://example.com" /></label>
          <label class="field"><span>Type</span>
            <select bind:value={site.config.redirect.code}>
              <option value={302}>Temporary (302)</option><option value={301}>Permanent (301)</option>
              <option value={307}>Temporary, keep method (307)</option><option value={308}>Permanent, keep method (308)</option>
            </select></label>
        </div>
        <label class="check"><input type="checkbox" bind:checked={site.config.redirect.keep_path} /> Keep the path (/foo → target/foo)</label>
      {:else if site.kind === 'respond'}
        <div class="grid2">
          <label class="field"><span>Status code</span><input type="number" bind:value={site.config.respond.status} /></label>
          <label class="field"><span>Content type</span><input type="text" bind:value={site.config.respond.content_type} placeholder="text/plain (optional)" /></label>
        </div>
        <label class="field"><span>Body</span><textarea rows="4" bind:value={site.config.respond.body}></textarea></label>
      {:else}
        <p class="muted">Write the directives below under “Custom Caddyfile”. They go inside this site's block.</p>
      {/if}
    </div>

    {#if site.kind === 'proxy'}
      <details class="section">
        <summary>Load balancing, health checks & timeouts</summary>
        <div class="body">
          <div class="grid2">
            <label class="field"><span>Load balancing policy</span>
              <select bind:value={site.config.proxy.lb_policy}>
                <option value="">Default (random)</option>
                {#each ['round_robin', 'least_conn', 'first', 'ip_hash', 'client_ip_hash', 'uri_hash', 'random_choose 2'] as p}<option value={p}>{p}</option>{/each}
              </select></label>
            <label class="field"><span>Retry for</span><input type="text" bind:value={site.config.proxy.lb_try_duration} placeholder="e.g. 5s" /></label>
            <label class="field"><span>Active health check path</span><input type="text" bind:value={site.config.proxy.health_uri} placeholder="/health" /></label>
            <label class="field"><span>Check interval</span><input type="text" bind:value={site.config.proxy.health_interval} placeholder="30s" /></label>
            <label class="field"><span>Passive: mark down after fails</span><input type="number" bind:value={site.config.proxy.max_fails} placeholder="1" /></label>
            <label class="field"><span>Passive: remember fails for</span><input type="text" bind:value={site.config.proxy.fail_duration} placeholder="30s" /></label>
            <label class="field"><span>Dial timeout</span><input type="text" bind:value={site.config.proxy.dial_timeout} placeholder="e.g. 5s" /></label>
            <label class="field"><span>Response header timeout</span><input type="text" bind:value={site.config.proxy.response_header_timeout} placeholder="e.g. 30s" /></label>
            <label class="field"><span>Upstream TLS server name</span><input type="text" bind:value={site.config.proxy.tls_server_name} placeholder="(optional)" /></label>
            <label class="field"><span>Flush interval</span><input type="text" bind:value={site.config.proxy.flush_interval} placeholder="-1 for streaming" /></label>
          </div>
          <div class="field"><span>Headers sent to the upstream</span><KVInput bind:value={site.config.proxy.header_up} keyPlaceholder="Header" valuePlaceholder="Value (or -Header to remove)" addLabel="Add header" /></div>
          <div class="field"><span>Headers changed in the response</span><KVInput bind:value={site.config.proxy.header_down} keyPlaceholder="Header" addLabel="Add header" /></div>
        </div>
      </details>
    {/if}

    <details class="section">
      <summary>Path routes <span class="muted small">({site.config.routes.length})</span></summary>
      <div class="body">
        <p class="muted small">Send specific paths somewhere else, e.g. <code>/api/*</code> to a backend. Checked in order, before the main handler.</p>
        {#each site.config.routes as r, i}
          <div class="route stack">
            <div class="row">
              <input type="text" bind:value={r.path} placeholder="/api/*" style="max-width:200px" />
              <select value={r.kind} onchange={(e) => routeKind(r, e.target.value)} style="max-width:170px">
                <option value="proxy">Reverse proxy</option><option value="static">File server</option>
                <option value="redirect">Redirect</option><option value="respond">Static response</option>
              </select>
              <label class="check"><input type="checkbox" bind:checked={r.strip_prefix} /> Strip prefix</label>
              <button class="btn ghost sm right" type="button" onclick={() => site.config.routes.splice(i, 1)}>Remove</button>
            </div>
            {#if r.kind === 'proxy'}<ListInput bind:items={r.proxy.upstreams} placeholder="localhost:9000" addLabel="Add upstream" />
            {:else if r.kind === 'static'}<input type="text" bind:value={r.static.root} placeholder="/srv/files" />
            {:else if r.kind === 'redirect'}<input type="text" bind:value={r.redirect.to} placeholder="https://…" />
            {:else}<div class="row"><input type="number" bind:value={r.respond.status} style="max-width:100px" /><input type="text" bind:value={r.respond.body} placeholder="Body" class="grow" /></div>{/if}
          </div>
        {/each}
        <div><button class="btn sm" type="button" onclick={addRoute}>+ Add route</button></div>
      </div>
    </details>

    <details class="section">
      <summary>HTTPS & redirects</summary>
      <div class="body">
        <div class="grid2">
          <label class="field"><span>Certificate</span>
            <select bind:value={site.config.tls.mode}>
              <option value="auto">Automatic (Let's Encrypt / your domain settings)</option>
              <option value="internal">Caddy internal CA (LAN / self-signed)</option>
              <option value="custom">My own certificate files</option>
              <option value="off">Off (plain HTTP only)</option>
            </select></label>
          <label class="field"><span>www handling</span>
            <select bind:value={site.config.www_redirect}>
              <option value="">Leave as is</option><option value="to_apex">Redirect www → bare domain</option><option value="to_www">Redirect bare domain → www</option>
            </select></label>
        </div>
        {#if site.config.tls.mode === 'custom'}
          <div class="grid2">
            <label class="field"><span>Certificate file</span><input type="text" bind:value={site.config.tls.cert_file} placeholder="/certs/site.crt" /></label>
            <label class="field"><span>Key file</span><input type="text" bind:value={site.config.tls.key_file} placeholder="/certs/site.key" /></label>
          </div>
        {/if}
        {#if site.config.tls.mode !== 'off'}
          <label class="check"><input type="checkbox" checked={site.config.http_redirect !== false} onchange={(e) => (site.config.http_redirect = e.target.checked ? null : false)} /> Redirect HTTP to HTTPS</label>
        {/if}
      </div>
    </details>

    <details class="section">
      <summary>Access control</summary>
      <div class="body">
        <div class="field">
          <span>Password protection (basic auth)</span>
          {#each site.config.access.basic_auth as u, i}
            <div class="row">
              <input type="text" bind:value={u.username} placeholder="username" style="max-width:200px" />
              {#if u.hash?.startsWith('$2')}
                <span class="muted small">password set</span>
                <button class="btn sm" type="button" onclick={() => (u.hash = '')}>Change</button>
              {:else}
                <input type="password" bind:value={u.hash} placeholder="new password" style="max-width:220px" autocomplete="new-password" />
              {/if}
              <button class="btn ghost sm" type="button" onclick={() => site.config.access.basic_auth.splice(i, 1)}>Remove</button>
            </div>
          {/each}
          <div><button class="btn sm" type="button" onclick={() => site.config.access.basic_auth.push({ username: '', hash: '' })}>+ Add user</button></div>
        </div>
        <div class="grid2">
          <div class="field"><span>Only allow these IPs / ranges</span><ListInput bind:items={site.config.access.allow_cidrs} placeholder="192.168.1.0/24" addLabel="Add range" />
            <span class="hint">Leave empty to allow everyone. Use <code>private_ranges</code> for LAN only.</span></div>
          <div class="field"><span>Block these IPs / ranges</span><ListInput bind:items={site.config.access.deny_cidrs} placeholder="203.0.113.7" addLabel="Add range" /></div>
        </div>
        <div class="field">
          <span>Single sign-on (forward auth)</span>
          {#if site.config.access.forward_auth}
            <div class="grid2">
              <label class="field"><span>Provider</span>
                <select value={site.config.access.forward_auth.preset} onchange={(e) => faPreset(e.target.value)}>
                  <option value="authelia">Authelia</option><option value="authentik">Authentik</option><option value="custom">Other</option>
                </select></label>
              <label class="field"><span>Auth server address</span><input type="text" bind:value={site.config.access.forward_auth.upstream} placeholder="authelia:9091" /></label>
              <label class="field"><span>Verify URI</span><input type="text" bind:value={site.config.access.forward_auth.uri} /></label>
            </div>
            <div><button class="btn ghost sm" type="button" onclick={() => delete site.config.access.forward_auth}>Remove SSO</button></div>
          {:else}
            <div><button class="btn sm" type="button" onclick={ensureFA}>+ Protect with Authelia / Authentik</button></div>
          {/if}
        </div>
        <div class="field">
          <span>Rate limit {#if !available('rate_limit')}<span class="badge warn">plugin not installed</span>{/if}</span>
          {#if site.config.access.rate_limit}
            <div class="row">
              <input type="number" bind:value={site.config.access.rate_limit.events} style="max-width:110px" /> requests per
              <input type="text" bind:value={site.config.access.rate_limit.window} style="max-width:90px" /> per client
              <button class="btn ghost sm" type="button" onclick={() => delete site.config.access.rate_limit}>Remove</button>
            </div>
          {:else}
            <div><button class="btn sm" type="button" onclick={ensureRL} disabled={!available('rate_limit')}>+ Add rate limit</button></div>
          {/if}
        </div>
        {#if available('crowdsec')}
          <label class="check"><input type="checkbox" bind:checked={site.config.access.crowdsec} /> Block IPs flagged by CrowdSec</label>
        {/if}
      </div>
    </details>

    <details class="section">
      <summary>Headers, compression & limits</summary>
      <div class="body">
        <div class="checks">
          <label class="check"><input type="checkbox" checked={site.config.compression.includes('zstd')} onchange={(e) => toggleComp('zstd', e.target.checked)} /> zstd compression</label>
          <label class="check"><input type="checkbox" checked={site.config.compression.includes('gzip')} onchange={(e) => toggleComp('gzip', e.target.checked)} /> gzip compression</label>
        </div>
        <div class="field"><span>Set response headers</span><KVInput bind:value={site.config.headers_set} keyPlaceholder="Header" addLabel="Add header" /></div>
        <div class="field"><span>Remove response headers</span><ListInput bind:items={site.config.headers_remove} placeholder="Server" addLabel="Add header" /></div>
        <div class="grid2">
          <label class="field"><span>Max upload size</span><input type="text" bind:value={site.config.max_body_size} placeholder="e.g. 100MB (empty = unlimited)" /></label>
          <label class="field"><span>Access log</span>
            <select bind:value={accessLog}><option value="default">Default (from settings)</option><option value="on">On</option><option value="off">Off</option></select></label>
        </div>
      </div>
    </details>

    <details class="section">
      <summary>Maintenance mode {#if site.config.maintenance}<span class="badge warn">on</span>{/if}</summary>
      <div class="body">
        <label class="check"><input type="checkbox" bind:checked={site.config.maintenance} /> Show a maintenance page instead of the site (HTTP 503)</label>
        {#if site.config.maintenance}
          <label class="field"><span>Message</span><textarea rows="3" bind:value={site.config.maintenance_body} placeholder="We'll be right back."></textarea></label>
        {/if}
      </div>
    </details>

    <details class="section" open={site.kind === 'none' || !!site.config.raw}>
      <summary>Custom Caddyfile {#if site.config.raw}<span class="badge accent">in use</span>{/if}</summary>
      <div class="body">
        {#if snippets.length}
          <div class="field"><span>Include snippets</span>
            <div class="checks">
              {#each snippets as sn}
                <label class="check"><input type="checkbox" checked={site.config.snippets.includes(sn.name)} onchange={(e) => toggleSnippet(sn.name, e.target.checked)} /> {sn.name} <span class="muted small">{sn.description}</span></label>
              {/each}
            </div>
          </div>
        {/if}
        <label class="field"><span>Extra directives (placed inside this site's block)</span>
          <textarea rows="8" bind:value={site.config.raw} placeholder={'# anything Caddy supports, e.g.\nheader /static/* Cache-Control "max-age=86400"'}></textarea>
        </label>
        <div class="row">
          <button class="btn sm" type="button" onclick={checkRaw}>Check syntax</button>
          {#if rawCheck}{#if rawCheck.valid}<span class="badge ok">looks valid</span>{:else}<span class="mono small err">{rawCheck.error}</span>{/if}{/if}
        </div>
      </div>
    </details>
  </fieldset>

  {#if error}<div class="alert err" style="margin-top:14px">{error}</div>{/if}
  {#if can.edit()}
    <div class="actions">
      <button class="btn" onclick={() => save(false)} disabled={busy}>Save</button>
      <button class="btn primary" onclick={() => save(true)} disabled={busy}>Save & review changes</button>
    </div>
  {/if}
{/if}

<style>
  fieldset { border: 0; padding: 0; margin: 0; min-width: 0; }
  .kinds { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 8px; }
  .kind {
    display: flex; flex-direction: column; gap: 2px; padding: 10px 12px; border: 1px solid var(--border);
    border-radius: 8px; cursor: pointer; background: var(--surface);
  }
  .kind input { position: absolute; opacity: 0; pointer-events: none; }
  .kind.active { border-color: var(--accent); background: var(--accent-soft); }
  .checks { display: flex; flex-direction: column; gap: 8px; }
  .route { border: 1px dashed var(--border); border-radius: 8px; padding: 10px; gap: 8px; }
  .actions {
    position: sticky; bottom: 0; display: flex; gap: 8px; justify-content: flex-end; padding: 14px 0;
    background: linear-gradient(transparent, var(--bg) 30%); margin-top: 8px;
  }
  .err { color: var(--danger); }
</style>
