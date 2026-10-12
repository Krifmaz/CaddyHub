#!/usr/bin/env bash
# Builds CaddyHub's images on a Linux box (or WSL) without Docker and without
# a system C toolchain: zig is the C compiler and linker for everything.
#   build-images.sh panel   compile the panel for linux/amd64 and pack the image
#   build-images.sh caddy   pack the Caddy image from a downloaded Caddy binary
#   build-images.sh all
#
# Needs: rustup (with the x86_64-unknown-linux-musl target), python3, and zig
# at $ZIG (default ~/zig/zig-x86_64-linux-0.14.1/zig).
# Inputs/outputs live under $WORK (default ~/caddyhub-build):
#   $WORK/src          copy of backend/ (with ui/dist built)
#   $WORK/caddy        Caddy linux/amd64 binary with plugins (from caddyserver.com/api/download)
#   $WORK/out          caddyhub.tar and caddyhub-caddy.tar, ready for `docker load`
set -euo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
WORK="${WORK:-$HOME/caddyhub-build}"
ZIG="${ZIG:-$HOME/zig/zig-x86_64-linux-0.14.1/zig}"
VERSION="${VERSION:-local-$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo dev)}"
TARGET=x86_64-unknown-linux-musl
mkdir -p "$WORK/out" "$WORK/bin"

# zig as C compiler/linker. The host (gnu) wrapper swaps libgcc for zig's
# libunwind, the way cargo-zigbuild does; build scripts and proc macros are
# host binaries, so the host needs a linker too.
write_wrappers() {
	cat > "$WORK/bin/zigcc-musl" <<EOF
#!/usr/bin/env bash
exec "$ZIG" cc -target x86_64-linux-musl "\$@"
EOF
	cat > "$WORK/bin/zigcc-gnu" <<EOF
#!/usr/bin/env bash
args=()
for a in "\$@"; do
	case "\$a" in
		-lgcc_s) args+=(-lunwind) ;;
		-lgcc) ;;
		*) args+=("\$a") ;;
	esac
done
exec "$ZIG" cc -target x86_64-linux-gnu.2.28 "\${args[@]}"
EOF
	cat > "$WORK/bin/zigar" <<EOF
#!/usr/bin/env bash
exec "$ZIG" ar "\$@"
EOF
	chmod +x "$WORK/bin/"*
}

build_panel() {
	source "$HOME/.cargo/env"
	test -x "$ZIG" || { echo "zig not found at $ZIG" >&2; exit 1; }
	write_wrappers
	rm -rf "$WORK/src"
	mkdir -p "$WORK/src"
	tar -C "$REPO/backend" --exclude=./target -cf - . | tar -xf - -C "$WORK/src"
	test -f "$WORK/src/ui/dist/index.html" || { echo "build the UI first (frontend: npm run build)" >&2; exit 1; }
	(
		cd "$WORK/src"
		export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$WORK/bin/zigcc-musl"
		export CC_x86_64_unknown_linux_musl="$WORK/bin/zigcc-musl"
		export AR_x86_64_unknown_linux_musl="$WORK/bin/zigar"
		export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$WORK/bin/zigcc-gnu"
		export CC="$WORK/bin/zigcc-gnu" AR="$WORK/bin/zigar"
		CADDYHUB_VERSION="$VERSION" cargo build --release --locked --target "$TARGET"
	)
	cp "$WORK/src/target/$TARGET/release/caddyhub" "$WORK/caddyhub"
	ls -la "$WORK/caddyhub"
	"$WORK/caddyhub" --version
	python3 "$REPO/scripts/mkimage.py" panel --binary "$WORK/caddyhub" --out "$WORK/out/caddyhub.tar" --version "$VERSION"
}

build_caddy() {
	test -f "$WORK/caddy" || { echo "put the Caddy linux/amd64 binary at $WORK/caddy first" >&2; exit 1; }
	chmod +x "$WORK/caddy"
	"$WORK/caddy" version
	python3 "$REPO/scripts/mkimage.py" caddy --binary "$WORK/caddy" --entrypoint "$REPO/caddy/entrypoint.sh" --out "$WORK/out/caddyhub-caddy.tar" --version "$VERSION"
}

case "${1:-all}" in
	panel) build_panel ;;
	caddy) build_caddy ;;
	all) build_caddy; build_panel ;;
	*) echo "usage: $0 panel|caddy|all" >&2; exit 2 ;;
esac
ls -la "$WORK/out"
