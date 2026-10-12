#!/usr/bin/env bash
# Starts the freshly built Linux panel binary against a throwaway data dir
# and checks that the API and the embedded UI answer. Used after
# build-images.sh on a machine without Docker.
set -euo pipefail
WORK="${WORK:-$HOME/caddyhub-build}"
D=$(mktemp -d)
CADDYHUB_LISTEN=127.0.0.1:8098 CADDYHUB_DATA_DIR="$D/data" CADDYHUB_CADDY_BIN="$WORK/caddy" \
	CADDYHUB_CADDY_ADMIN=127.0.0.1:1 CADDYHUB_CADDYFILE="$D/Caddyfile" CADDYHUB_SECRETS_DIR="$D/secrets" \
	CADDYHUB_LOG_DIR="$D/logs" "$WORK/caddyhub" >"$D/log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
sleep 2
echo "health: $(curl -s --max-time 5 http://127.0.0.1:8098/api/health)"
echo "me:     $(curl -s --max-time 5 http://127.0.0.1:8098/api/me)"
echo "ui:     $(curl -s --max-time 5 -o /dev/null -w '%{http_code} %{content_type}' http://127.0.0.1:8098/)"
sleep 3
grep -E "detected caddy|listening" "$D/log" | head -3
