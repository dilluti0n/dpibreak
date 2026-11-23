#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build the single-file DPIBreak Panel for Linux: a static (musl)
# dpibreak is embedded into the panel, which links normally against
# glibc and the system X11/Wayland/GL libraries.
#
# Usage (from anywhere):  sh gui/build-bundle.sh
# Output:                 dist/DPIBreak-Panel-linux-x86_64
#
# Needs: rustup target add x86_64-unknown-linux-musl, and musl-gcc
# (Debian/Ubuntu: musl-tools, Fedora: musl-gcc, Arch: musl).

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

target=x86_64-unknown-linux-musl

if ! command -v cargo >/dev/null 2>&1; then
    if [ -x "$HOME/.cargo/bin/cargo" ]; then
        PATH="$HOME/.cargo/bin:$PATH"
    else
        echo "cargo not found. Install Rust from https://rustup.rs and try again." >&2
        exit 1
    fi
fi
if [ -n "${DPIBREAK_BUNDLE_DIR:-}" ]; then
    stage=$(CDPATH= cd -- "$DPIBREAK_BUNDLE_DIR" && pwd)
    if [ ! -f "$stage/dpibreak" ]; then
        echo "Missing released dpibreak binary in $stage" >&2
        exit 1
    fi
else
    if command -v rustup >/dev/null 2>&1 &&
        ! rustup target list --installed | grep -qx "$target"; then
        echo "Missing Rust target: rustup target add $target" >&2
        exit 1
    fi

    echo "Building static dpibreak ($target)..."
    cargo build --release --locked -p dpibreak --target "$target"

    stage="$root/target/bundle-linux"
    mkdir -p "$stage"
    cp -f "target/$target/release/dpibreak" "$stage/dpibreak"
    strip "$stage/dpibreak" 2>/dev/null || true
fi

echo "Building DPIBreak Panel..."
DPIBREAK_BUNDLE_DIR="$stage" cargo build --release --locked --manifest-path gui/Cargo.toml

mkdir -p dist
out="dist/DPIBreak-Panel-linux-x86_64"
tmp_out=$(mktemp "$out.tmp.XXXXXX")
trap 'rm -f "$tmp_out"' 0
cp -f gui/target/release/dpibreak-gui "$tmp_out"
strip "$tmp_out" 2>/dev/null || true
chmod 0755 "$tmp_out"
mv -f "$tmp_out" "$out"
trap - 0

size=$(du -h "$out" | cut -f1)
sha256sum "$out" > "$out.sha256"
echo "Done: $out ($size)"
echo "SHA256: $(sha256sum "$out" | cut -d' ' -f1)"
echo "Checksum: $out.sha256"
