# CaddyHub

A self-hosted web UI that makes editing and updating your [Caddy](https://caddyserver.com) config easy, without breaking it.

You manage sites with forms (or raw Caddyfile text where you need it). CaddyHub generates a clean Caddyfile, has Caddy validate it, shows you a diff, applies it through Caddy's admin API, checks that Caddy is still healthy, and **rolls back automatically** if it isn't. Every apply is kept in history, and you can restore any earlier version with one click.

It also manages Caddy itself: install plugins and update Caddy from the UI, keep your DNS records pointed at your home IP (dynamic DNS), and run an authenticated HTTPS forward proxy next to your reverse proxies.

## Why it doesn't break your config

- **The UI owns a structured model** (SQLite) and *generates* the Caddyfile. It never regex-edits text, so there's no drift.
- **Every apply runs:** generate → `caddy adapt` → `caddy validate` → diff preview → `POST /load` → health check → keep, or roll back to the exact previous config.
- **The applied Caddyfile is persisted**, so a Caddy restart comes back with the same config.
- **No lock-in:** you can export the plain Caddyfile at any time and run Caddy without CaddyHub.
- **Nothing is lost on import:** blocks it can't map stay as raw text, verbatim.
- **Plugin installs are checked first:** a new Caddy build only goes live after your current config validates with it, and the previous build stays available for a rollback.

## Quick start (Docker)

```sh
git clone https://github.com/Krifmaz/CaddyHub.git
cd CaddyHub
cp .env.example .env          # optional, but set CADDYHUB_SECRET_KEY (openssl rand -base64 32)
docker compose up -d
```

Open `http://<your-server>:8080`, create your admin account, and follow the two-step setup (certificate email, optionally import your existing Caddyfile).

One container runs everything: the panel on port 8080 starts Caddy (ports 80/443) inside the same container, keeps it running, and validates every config with the exact binary that serves traffic. Caddy's admin API only listens on localhost inside the container. Certificates, the database and the Caddy binary live in the single `data` volume; to keep certificates from a previous Caddy, mount its data volume at `/data/caddy-data` (see the comments in [docker-compose.yml](docker-compose.yml)).

Prefer Caddy in its own container? [docker-compose.split.yml](docker-compose.split.yml) runs the panel and a separate Caddy image (ports 80/443) that talk over an internal network; it needs the `caddyhub-caddy` image as well.

> Tip: to put the panel itself behind HTTPS, set **Settings → Advanced → Serve CaddyHub itself at** (e.g. `caddyhub.example.com`), apply, then set `CADDYHUB_BASE_URL=https://caddyhub.example.com` and `CADDYHUB_TRUST_PROXY_HEADERS=true` in `.env`. After that you can stop publishing port 8080.

### Portainer / prebuilt images

Every push to `main` publishes a ready-made image (amd64; arm64 on request from the Actions tab) to GitHub Container Registry:

- `ghcr.io/krifmaz/caddyhub:latest`: the panel with Caddy built in, including the plugins for Cloudflare, Porkbun, DuckDNS, Namecheap, Route53, DigitalOcean, Hetzner, deSEC, OVH, Gandi and ACME-DNS, plus rate limiting
- `ghcr.io/krifmaz/caddyhub-caddy:latest`: the separate Caddy image for the two-container layout (rebuilt when `caddy/` changes)

Version tags (`v0.3.0`) additionally publish `ghcr.io/krifmaz/caddyhub:0.3.0` and appear under [Releases](https://github.com/Krifmaz/CaddyHub/releases) with notes; `:latest` always follows `main`.

Paste [docker-compose.yml](docker-compose.yml) into a Portainer stack (drop the `build:` line). It only pulls images, so it works with Portainer's remote agents, which can't build. Anything the image lacks can be added later from **Plugins** in the UI, no rebuild needed.

## Using it

1. **Sites**: add a reverse proxy, file server, redirect, static response or forward proxy. Templates fill in sensible defaults for common apps (Vaultwarden, Jellyfin, Immich, Nextcloud, Home Assistant, Proxmox, …), and “Find app” scans Docker and your LAN to fill in the upstream.
   Per site you can set path routes, load balancing and health checks, HTTPS mode, www/HTTP redirects, headers, compression, upload limits, basic auth, IP allow/deny lists, Authelia/Authentik forward auth, rate limits, maintenance mode, and an extra raw Caddyfile box.
2. **Review & apply**: see the diff and validation result, then apply, or do a dry run.
3. **History**: every attempt with its exact Caddyfile, a diff against any other version, and one-click restore.

Other pages:

- **Domains & DNS**: DNS-01 validation per domain (each domain can use a different provider/account) and optional wildcard certificates.
- **Dynamic DNS**: keep A/AAAA records pointed at this server's public address. Uses the same DNS provider accounts as DNS validation and the `caddy-dynamicdns` plugin; the page shows the public IP and whether each record matches.
- **Plugins**: see which plugins are compiled into the running Caddy, add or remove any package from the official catalog, and update Caddy to the latest release. CaddyHub downloads the build from caddyserver.com's download service (the same one `caddy add-package` uses), checks it, validates your config against it, swaps it in and restarts Caddy. Previous build kept for rollback; “Reset to image” returns to the Caddy shipped in the container image.
- **Updates** (on the Plugins page): a background checker looks for new Caddy releases (every 6 hours by default), shows a dot in the navigation and sends the “Caddy update available” notification once per release. Turn on **Install new releases automatically** to have them installed through the same checked path, optionally only inside a daily maintenance window.
- **Snippets & raw**: reusable snippets you attach to sites, plus verbatim top-level blocks.
- **Import**: on first start, CaddyHub looks for your existing config and offers it with no pasting needed. It checks, in order: the running Caddy (admin API), the `autosave.json` a previous Caddy left in the shared config volume (the Caddy container backs it up once before its first start), and an old Caddyfile mounted at `/import/Caddyfile`. You can also paste a Caddyfile or Caddy JSON. Before you import, CaddyHub regenerates the config, has Caddy check it, and compares every host ("4 sites imported, 0 differences"). Anything it can't map is kept, disabled, for you to review. DNS tokens written in plain text are moved into encrypted storage.
- **Settings**: certificate authority (Let's Encrypt, ZeroSSL, Google, staging, custom ACME), propagation resolvers, trusted proxies/CDNs, logs and metrics, extra global options, and a dry-run safety mode.
- **Users & API keys**: admin / editor / viewer roles, TOTP two-factor, and bearer-token API keys.
- **Notifications**: ntfy, Gotify, Discord, Slack, email or webhook when an apply fails.
- **Audit log**: who changed what.

### Forward proxy

A **Forward proxy** site turns Caddy into an HTTPS proxy your phones and laptops can use on the road (`https://proxy.example.com:443`). It needs the `forwardproxy` plugin (install it from **Plugins**). Set logins, allowed destination ports, access rules (`deny 192.168.0.0/16`, `allow all`), probe resistance and the usual HTTPS options. Logins are stored as entered, because the plugin compares them as-is, so use a dedicated password.

### DNS providers and plugins

DNS validation and dynamic DNS need the matching caddy-dns plugin in your Caddy build. Add it from **Plugins** (no rebuild), or bake it into the image by listing it in `.env`:

```sh
CADDY_PLUGINS=github.com/caddy-dns/cloudflare github.com/caddy-dns/porkbun github.com/mholt/caddy-ratelimit
```

Then run `docker compose build caddy && docker compose up -d`. CaddyHub detects the installed modules on startup: providers and features whose plugin is missing are marked in the UI instead of generating broken config.

Create least-privilege tokens: DNS edit on the zone you use, nothing more. Each provider in the UI links to its token docs. DNS secrets are encrypted at rest and reach Caddy only as `{file.*}` placeholders, never as plain text in the Caddyfile. You can also enter `env:VAR` or `file:/path` instead of a value.

### How plugin installs work

Caddy plugins are compiled in, so a plugin install means a new binary. The panel downloads one with your selection, runs it to confirm the version and modules, validates the current config with it, and only then installs it as `caddy-custom` next to the running binary and asks Caddy to exit. In the all-in-one image the panel itself restarts Caddy with the custom build; in the two-container layout the Caddy container's entrypoint does the same from the shared `caddy-bin` volume. Either way, a custom build that dies right after starting is set aside and the image's Caddy takes over, so you are never left without Caddy. Every install also moves Caddy to the latest release (that is how the download service works); plugins are fetched at their newest version.

### Upgrading Caddy

Three ways, all optional:

- **Automatically**: on the Plugins page, under Updates, turn on **Install new releases automatically**. The checker looks for releases on the interval you pick; when one is newer than the running Caddy it is downloaded with your plugins, verified, validated against your configuration, installed and Caddy restarted (a few seconds of downtime). Set a daily window (server local time; set `TZ` on the container) to keep restarts to the night. A release that fails any check is discarded, the running build stays, and the “Automatic Caddy update failed” notification tells you. An update that failed is not retried until the next release, so a broken plugin cannot cause a restart loop.
- **From the UI**: **Plugins → Update Caddy** when the dot in the navigation says a release is out.
- **Through the image**: every image build ships the then-current Caddy, so re-pulling `ghcr.io/krifmaz/caddyhub:latest` (or a version tag) also moves Caddy forward:

```sh
docker compose pull && docker compose up -d
```

A custom build installed from the Plugins page keeps being used after an image update as long as it starts; it is newer or equal anyway, since every install fetches the current release.

### Backups

Everything lives in Docker volumes. Back up `panel-data` (database + secret key, if generated) and `caddy-data` (certificates). If you set `CADDYHUB_SECRET_KEY` in `.env`, keep it with the backup: it decrypts stored DNS credentials.

## Configuration

All configuration is environment variables (see [.env.example](.env.example)). The most useful ones:

| Variable | Default | Purpose |
|----------|---------|---------|
| `CADDYHUB_SECRET_KEY` / `_FILE` | generated | Key that encrypts secrets in the DB |
| `CADDYHUB_SETUP_TOKEN` | — | Required to create the first admin |
| `CADDYHUB_INITIAL_ADMIN_USER` / `_PASSWORD` | — | Create the admin unattended |
| `CADDYHUB_BASE_URL` | — | Public URL of the panel (enables Secure cookies) |
| `CADDYHUB_TRUST_PROXY_HEADERS` | `false` | Trust `X-Forwarded-For` (panel behind Caddy) |
| `CADDYHUB_LISTEN` | `:8080` | Panel listen address |
| `CADDYHUB_CADDY_ADMIN` | `caddy-admin:2019` | Caddy admin API address (TCP or `unix//path`) |
| `CADDYHUB_CADDY_ARCH` | detected | Architecture for plugin downloads (`amd64`, `arm64`) |
| `CADDYHUB_GITHUB_TOKEN` | — | Raises the GitHub API limit for update checks |

## Development

Requirements: Rust 1.85+ and Node 24+. A Caddy binary is optional; with one, the tests also run against real Caddy (set `CADDY_BIN`). A build with plugins, for the dynamic DNS and forward proxy cases, comes from the download service: `https://caddyserver.com/api/download?os=linux&arch=amd64&p=github.com/mholt/caddy-dynamicdns&p=github.com/caddyserver/forwardproxy`.

```sh
# backend
cd backend
cargo test                           # CADDY_BIN=/path/to/caddy cargo test for the real-Caddy tests
cargo run                            # see src/config.rs for env vars; UPDATE_GOLDEN=1 cargo test rewrites generator goldens

# frontend (proxies /api to localhost:8080)
cd frontend
npm install
npm run dev
npm run build                        # writes backend/ui/dist, embedded by cargo build
```

Layout:

```
backend/src/
  main.rs       entry point and background jobs
  config.rs     environment configuration
  model.rs      structured config types
  store/        SQLite store + migrations
  generator.rs  model → Caddyfile (golden-file tested in testdata/generator)
  apply.rs      adapt/validate/diff/load/health-check/rollback pipeline
  importer/     Caddyfile and Caddy JSON → model (keeps unknown blocks raw)
  registry/     DNS providers + features mapped to Caddy modules/versions
  plugins.rs    plugin manager: download service, verify, swap, restart
  supervisor.rs all-in-one mode: runs Caddy as a child process and keeps it up
  ddns.rs       dynamic DNS status (public IP vs. records)
  server/       REST API + auth (sessions, CSRF, TOTP, API keys, roles)
  caddy/        caddy CLI runner + admin API client
  scan.rs       "Find app" network scanner
  notify.rs     notification channels (webhooks, ntfy, Gotify, email, …)
frontend/       Svelte 5 UI
caddy/          Caddy image (xcaddy + plugins) and entrypoint
```

## Status & roadmap

Working now: everything listed under “Using it” above, tested against Caddy v2.11.7.

Planned:

- Certificate overview (expiry, issuer, force renew) with expiry alerts
- Live access-log viewer and per-site metrics
- “Test route” button
- Backup/restore archive from the UI, and scheduled backups
- OIDC login (Authentik, Authelia, Pocket ID, Keycloak)
- Docker label auto-discovery
- Update notifications
- Syntax-highlighted editor for raw blocks
