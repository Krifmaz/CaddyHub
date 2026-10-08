# CaddyHub

A self-hosted web UI that makes editing and updating your [Caddy](https://caddyserver.com) config easy, without breaking it.

You manage sites with forms (or raw Caddyfile text where you need it). CaddyHub generates a clean Caddyfile, has Caddy validate it, shows you a diff, applies it through Caddy's admin API, checks that Caddy is still healthy, and **rolls back automatically** if it isn't. Every apply is kept in history, and you can restore any earlier version with one click.

## Why it doesn't break your config

- **The UI owns a structured model** (SQLite) and *generates* the Caddyfile. It never regex-edits text, so there's no drift.
- **Every apply runs:** generate → `caddy adapt` → `caddy validate` → diff preview → `POST /load` → health check → keep, or roll back to the exact previous config.
- **The applied Caddyfile is persisted**, so a Caddy restart comes back with the same config.
- **No lock-in:** you can export the plain Caddyfile at any time and run Caddy without CaddyHub.
- **Nothing is lost on import:** blocks it can't map stay as raw text, verbatim.

## Quick start (Docker)

```sh
git clone https://github.com/Krifmaz/CaddyHub.git
cd CaddyHub
cp .env.example .env          # optional, but set CADDYHUB_SECRET_KEY (openssl rand -base64 32)
docker compose up -d --build
```

Open `http://<your-server>:8080`, create your admin account, and follow the two-step setup (certificate email, optionally import your existing Caddyfile).

The stack runs two containers:

| Container | What it does |
|-----------|--------------|
| `caddy`   | Caddy built with xcaddy plus your plugins. Serves ports 80/443. Its admin API only listens on an internal Docker network, never on the host. |
| `panel`   | CaddyHub (UI + API) on port 8080. Writes the Caddyfile to a shared volume and validates with the *same* Caddy binary that serves traffic. |

> Tip: to put the panel itself behind HTTPS, set **Settings → Advanced → Serve CaddyHub itself at** (e.g. `caddyhub.example.com`), apply, then set `CADDYHUB_BASE_URL=https://caddyhub.example.com` and `CADDYHUB_TRUST_PROXY_HEADERS=true` in `.env`. After that you can stop publishing port 8080.

## Using it

1. **Sites**: add a reverse proxy, file server, redirect or static response. Templates fill in sensible defaults for common apps (Vaultwarden, Jellyfin, Immich, Nextcloud, Home Assistant, Proxmox, …).
   Per site you can set path routes, load balancing and health checks, HTTPS mode, www/HTTP redirects, headers, compression, upload limits, basic auth, IP allow/deny lists, Authelia/Authentik forward auth, rate limits, maintenance mode, and an extra raw Caddyfile box.
2. **Review & apply**: see the diff and validation result, then apply, or do a dry run.
3. **History**: every attempt with its exact Caddyfile, a diff against any other version, and one-click restore.

Other pages:

- **Domains & DNS**: DNS-01 validation per domain (each domain can use a different provider/account) and optional wildcard certificates.
- **Snippets & raw**: reusable snippets you attach to sites, plus verbatim top-level blocks.
- **Import**: paste or upload a Caddyfile to turn it into sites.
- **Settings**: certificate authority (Let's Encrypt, ZeroSSL, Google, staging, custom ACME), propagation resolvers, trusted proxies/CDNs, logs and metrics, extra global options, and a dry-run safety mode.
- **Users & API keys**: admin / editor / viewer roles, TOTP two-factor, and bearer-token API keys.
- **Notifications**: ntfy, Gotify, Discord, Slack, email or webhook when an apply fails.
- **Audit log**: who changed what.

### DNS providers and plugins

DNS validation needs the matching caddy-dns plugin in your Caddy build. The default build includes Cloudflare and rate limiting. To add more, list them in `.env`:

```sh
CADDY_PLUGINS=github.com/caddy-dns/cloudflare github.com/caddy-dns/porkbun github.com/mholt/caddy-ratelimit
```

Then run `docker compose build caddy && docker compose up -d`. CaddyHub detects the installed modules on startup: providers and features whose plugin is missing are marked in the UI instead of generating broken config.

Create least-privilege tokens: DNS edit on the zone you use, nothing more. Each provider in the UI links to its token docs. DNS secrets are encrypted at rest and reach Caddy only as `{file.*}` placeholders, never as plain text in the Caddyfile. You can also enter `env:VAR` or `file:/path` instead of a value.

### Upgrading Caddy

```sh
docker compose build --pull caddy && docker compose up -d caddy
```

To pin a version, set `CADDY_VERSION` (an official image tag such as `2.11` or `2.11.7`) in `.env`.

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

## Development

Requirements: Go 1.27+ and Node 24+. A Caddy binary is optional; with one, the tests also run against real Caddy.

```sh
# backend
cd backend
go test ./...                        # set CADDY_BIN=/path/to/caddy for real-Caddy tests
go run ./cmd/caddyhub                # see internal/app/config.go for env vars

# frontend (proxies /api to localhost:8080)
cd frontend
npm install
npm run dev
npm run build                        # writes backend/internal/web/ui/dist, embedded by go build
```

Layout:

```
backend/cmd/caddyhub     entry point
backend/internal/
  model       structured config types
  store       SQLite store + migrations
  generator   model → Caddyfile (golden-file tested)
  apply       adapt/validate/diff/load/health-check/rollback pipeline
  importer    Caddyfile → model (keeps unknown blocks raw)
  registry    DNS providers + features mapped to Caddy modules/versions
  server      REST API + auth (sessions, CSRF, TOTP, API keys, roles)
  caddy       caddy CLI runner + admin API client
frontend/      Svelte 5 UI
caddy/         Caddy image (xcaddy + plugins) and entrypoint
```

## Status & roadmap

Working now: everything listed under “Using it” above, tested against Caddy v2.11.7.

Planned:

- Certificate overview (expiry, issuer, force renew) with expiry alerts
- Live access-log viewer and per-site metrics
- “Test route” button
- Backup/restore archive from the UI, and scheduled backups
- OIDC login (Authentik, Authelia, Pocket ID, Keycloak)
- Plugin manager and one-click Caddy upgrade with a pre-upgrade validation check
- Docker label auto-discovery
- Update notifications
- Syntax-highlighted editor for raw blocks
