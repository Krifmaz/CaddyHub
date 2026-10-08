# Caddy with the plugins CaddyHub can use. Rebuild with different plugins:
#   docker compose build --build-arg CADDY_PLUGINS="github.com/caddy-dns/cloudflare ..." caddy
ARG CADDY_VERSION=2

FROM caddy:${CADDY_VERSION}-builder AS build
ARG CADDY_PLUGINS="github.com/caddy-dns/cloudflare github.com/mholt/caddy-ratelimit"
RUN set -eu; args=""; \
    for p in $CADDY_PLUGINS; do args="$args --with $p"; done; \
    xcaddy build $args --output /usr/bin/caddy

FROM caddy:${CADDY_VERSION}-alpine
COPY --from=build /usr/bin/caddy /usr/bin/caddy
COPY entrypoint.sh /usr/local/bin/caddyhub-entrypoint
RUN chmod 0755 /usr/local/bin/caddyhub-entrypoint
ENTRYPOINT ["/usr/local/bin/caddyhub-entrypoint"]
