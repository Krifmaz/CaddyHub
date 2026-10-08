# CaddyHub panel: web UI + API (Caddy runs in its own container, see caddy/).
# Build stages run on the build machine's architecture and cross-compile.

FROM --platform=$BUILDPLATFORM node:24-alpine AS ui
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN mkdir -p ../backend/internal/web/ui && npm run build

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
COPY --from=ui /src/backend/internal/web/ui/dist ./internal/web/ui/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /caddyhub ./cmd/caddyhub

FROM alpine:3
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 1000 -h /data caddyhub
COPY --from=build /caddyhub /usr/local/bin/caddyhub
USER caddyhub
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["caddyhub", "-healthcheck"]
ENTRYPOINT ["caddyhub"]
