# CaddyHub panel: web UI + API (Caddy runs in its own container, see caddy/).
# Build stages run on the build machine's architecture and cross-compile
# with cargo-zigbuild (zig as the C compiler/linker), so arm64 images don't
# need emulation.

FROM --platform=$BUILDPLATFORM node:25-alpine AS ui
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN mkdir -p ../backend/ui && npm run build

FROM --platform=$BUILDPLATFORM rust:1-bookworm AS build
ARG VERSION=dev
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends python3-pip && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages --no-cache-dir "cargo-zigbuild==0.23.4" "ziglang<0.15"
WORKDIR /src/backend
RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl > /target ;; \
      arm64) echo aarch64-unknown-linux-musl > /target ;; \
      *) echo "unsupported TARGETARCH $TARGETARCH" >&2; exit 1 ;; \
    esac && rustup target add "$(cat /target)"
# Dependencies first, so they are cached across source changes.
COPY backend/Cargo.toml backend/Cargo.lock ./
RUN mkdir -p src ui/dist && echo 'fn main() {}' > src/main.rs \
    && cargo zigbuild --release --locked --target "$(cat /target)" \
    && rm -rf src target/*/release/deps/caddyhub* target/*/release/caddyhub*
COPY backend/ ./
COPY --from=ui /src/backend/ui/dist ./ui/dist
RUN CADDYHUB_VERSION="$VERSION" cargo zigbuild --release --locked --target "$(cat /target)" \
    && cp "target/$(cat /target)/release/caddyhub" /caddyhub

FROM alpine:3
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 1000 -h /data caddyhub
COPY --from=build /caddyhub /usr/local/bin/caddyhub
USER caddyhub
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["caddyhub", "-healthcheck"]
ENTRYPOINT ["caddyhub"]
