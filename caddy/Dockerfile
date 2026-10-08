# Caddy with the plugins CaddyHub can use. Rebuild with different plugins:
#   docker compose build --build-arg CADDY_PLUGINS="github.com/caddy-dns/cloudflare ..." caddy
ARG CADDY_VERSION=2

FROM --platform=$BUILDPLATFORM caddy:${CADDY_VERSION}-builder AS build
ARG TARGETOS
ARG TARGETARCH
ARG CADDY_PLUGINS="github.com/caddy-dns/cloudflare github.com/caddy-dns/porkbun github.com/caddy-dns/duckdns github.com/caddy-dns/namecheap github.com/caddy-dns/route53 github.com/caddy-dns/digitalocean github.com/caddy-dns/hetzner/v2 github.com/caddy-dns/desec github.com/caddy-dns/ovh github.com/caddy-dns/gandi github.com/caddy-dns/acmedns github.com/mholt/caddy-ratelimit"
RUN set -eu; args=""; \
    for p in $CADDY_PLUGINS; do args="$args --with $p"; done; \
    GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 xcaddy build $args --output /usr/bin/caddy

FROM caddy:${CADDY_VERSION}-alpine
COPY --from=build /usr/bin/caddy /usr/bin/caddy
COPY entrypoint.sh /usr/local/bin/caddyhub-entrypoint
RUN chmod 0755 /usr/local/bin/caddyhub-entrypoint
ENTRYPOINT ["/usr/local/bin/caddyhub-entrypoint"]
