#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Download, verify, install for the current user, and launch the latest panel.

set -eu

asset=DPIBreak-Panel-linux-x86_64
base=https://github.com/siimsek/dpibreak/releases/latest/download

if [ "$(id -u)" -eq 0 ]; then
    echo "Run this installer as your desktop user, not as root." >&2
    exit 1
fi

case $(uname -s) in
    Linux) ;;
    *) echo "This installer supports Linux only." >&2; exit 1 ;;
esac

case $(uname -m) in
    x86_64|amd64) ;;
    *) echo "The DPIBreak Panel release currently supports x86_64 only." >&2; exit 1 ;;
esac

if [ -z "${HOME:-}" ]; then
    echo "HOME is not set; cannot install the panel for this user." >&2
    exit 1
fi

if ! command -v sha256sum >/dev/null 2>&1; then
    echo "sha256sum is required to verify the download (usually provided by coreutils)." >&2
    exit 1
fi

download() {
    url=$1
    destination=$2
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error --retry 2 --output "$destination" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget --quiet --tries=2 --output-document="$destination" "$url"
    else
        echo "Install curl or wget, then run this command again." >&2
        return 1
    fi
}

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/dpibreak-panel.XXXXXX")
cleanup() {
    rm -f "$tmpdir/$asset" "$tmpdir/$asset.sha256" "$HOME/.local/bin/.dpibreak-panel.$$"
    rmdir "$tmpdir" 2>/dev/null || true
}
trap cleanup 0 HUP INT TERM

if ! download "$base/$asset" "$tmpdir/$asset"; then
    echo "The latest release does not contain $asset yet." >&2
    echo "A maintainer must publish a Linux Panel release before this installer can run." >&2
    exit 1
fi

if ! download "$base/$asset.sha256" "$tmpdir/$asset.sha256"; then
    echo "The release is missing the SHA-256 checksum for $asset." >&2
    echo "Use a release that includes the binary and its .sha256 file." >&2
    exit 1
fi

expected=$(awk 'NR == 1 { print $1; exit }' "$tmpdir/$asset.sha256")
case $expected in
    *[!0123456789abcdefABCDEF]*|'')
        echo "The release checksum file is malformed." >&2
        exit 1
        ;;
esac
if [ "${#expected}" -ne 64 ]; then
    echo "The release checksum is not a SHA-256 value." >&2
    exit 1
fi

actual=$(sha256sum "$tmpdir/$asset" | awk '{ print $1 }')
if [ "$(printf '%s' "$expected" | tr 'ABCDEF' 'abcdef')" != "$actual" ]; then
    echo "SHA-256 verification failed; the panel was not installed." >&2
    exit 1
fi

target_dir=$HOME/.local/bin
target=$target_dir/dpibreak-panel
staged=$target_dir/.dpibreak-panel.$$
mkdir -p "$target_dir"
cp "$tmpdir/$asset" "$staged"
chmod 0755 "$staged"
mv -f "$staged" "$target"

echo "Installed verified DPIBreak Panel at $target. Launching it now."
cleanup
trap - 0 HUP INT TERM
exec "$target" "$@"
