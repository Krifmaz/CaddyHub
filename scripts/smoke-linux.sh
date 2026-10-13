#!/usr/bin/env bash
# Starts the freshly built Linux panel binary against a throwaway data dir
# and checks that the API and the embedded UI answer. Used after
# build-images.sh on a machine without Docker.
set -euo pipefail
WORK="${WORK:-$HOME/caddymium-build}"
D=$(mktemp -d)
CADDYMIUM_LISTEN=127.0.0.1:8098 CADDYMIUM_DATA_DIR="$D/data" CADDYMIUM_CADDY_BIN="$WORK/caddy" \
	CADDYMIUM_CADDY_ADMIN=127.0.0.1:1 CADDYMIUM_CADDYFILE="$D/Caddyfile" CADDYMIUM_SECRETS_DIR="$D/secrets" \
	CADDYMIUM_LOG_DIR="$D/logs" "$WORK/caddymium" >"$D/log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true' EXIT
sleep 2
echo "health: $(curl -s --max-time 5 http://127.0.0.1:8098/api/health)"
echo "me:     $(curl -s --max-time 5 http://127.0.0.1:8098/api/me)"
echo "ui:     $(curl -s --max-time 5 -o /dev/null -w '%{http_code} %{content_type}' http://127.0.0.1:8098/)"
sleep 3
grep -E "detected caddy|listening" "$D/log" | head -3
