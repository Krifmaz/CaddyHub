#!/bin/sh
# Prepares the volumes shared with the CaddyHub panel, then runs Caddy from
# the Caddyfile the panel maintains.
set -eu

CADDYFILE="${CADDYFILE:-/etc/caddyhub/Caddyfile}"
ADMIN="${CADDY_ADMIN_LISTEN:-caddy-admin:2019}"
PANEL_UID="${PANEL_UID:-1000}"

# Share this exact binary so the panel validates with the same build (and
# the same plugins) that serves traffic.
if [ -d /caddy-bin ]; then
	cp /usr/bin/caddy /caddy-bin/caddy.tmp && mv -f /caddy-bin/caddy.tmp /caddy-bin/caddy
	chmod 0755 /caddy-bin/caddy
fi

mkdir -p "$(dirname "$CADDYFILE")" /run/caddyhub/secrets /var/log/caddy
# The panel (non-root) writes the Caddyfile and secret files.
chown "$PANEL_UID" "$(dirname "$CADDYFILE")" /run/caddyhub/secrets
chmod 0700 /run/caddyhub/secrets
chmod 0755 /var/log/caddy

# First start: a minimal config that only enables the admin API on the
# internal network, so the panel can take over.
if [ ! -s "$CADDYFILE" ]; then
	cat > "$CADDYFILE" <<CFG
{
	admin $ADMIN {
		origins $ADMIN
	}
}
CFG
	chown "$PANEL_UID" "$CADDYFILE"
fi

exec caddy run --config "$CADDYFILE" --adapter caddyfile
