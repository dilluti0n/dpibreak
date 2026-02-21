# SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
#
# DPIBreak install script
# CHANGELOG:
# v1.1 - Remove make dependency

set -eu

PROJECT='DPIBreak'
REPO='dilluti0n/dpibreak'
LINUX='Linux'
AMD64='x86_64'

die() {
    [ $# -eq 0 ] || echo Error: "$@" >&2
    exit 1
}

get_tag() {
    api_version='2022-11-28'
    api_uri="https://api.github.com/repos/$REPO/releases/latest"

    tag=$(curl -fsSL -H "X-GitHub-Api-Version: $api_version" "$api_uri" \
              | grep '"tag_name":' | cut -d '"' -f 4)
    [ -n "$tag" ] || die Failed to fetch latest release tag from $api_uri

    echo Latest release: $tag >&2

    echo "$tag"
}

available_cmd() {
    [ $# -eq 0 ] && return

    cmd=

    for cmd in "$@"; do
        if command -v "$cmd" >/dev/null 2>&1; then
            echo "$cmd"
            return 0
        fi
    done

    return 1
}

do_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
        return $?
    fi

    SUDO=$(available_cmd sudo doas)

    [ -n "$SUDO" ] || die No privilege escalation command found '(sudo/doas)'. Re-run as root.

    echo Privilege escalation required: "$@" >&2
    $SUDO "$@"
}

get_opt() {
    if [ $# -eq 0 ]; then
        echo install
    elif [ "$1" = "uninstall" ]; then
        echo uninstall
    else
        die "Unknown argument: $1"
    fi
}

echo $PROJECT installer for $AMD64 $LINUX
echo Source: "https://github.com/$REPO/install.sh"

MODE=$(get_opt "$@") || die
KERNEL=$(uname -s)
ARCH=$(uname -m)

[ "$KERNEL" = "$LINUX" ] || die "$KERNEL: not supported. Only $LINUX is supported."
[ "$ARCH" = "$AMD64" ] || die "$ARCH: not supported. Only $AMD64 is supported."

TAG=$(get_tag)
TARBALL="$PROJECT-${TAG#v}-$ARCH-unknown-linux-musl.tar.gz"
EXDIR="${TARBALL%.tar.gz}"
URI="https://github.com/$REPO/releases/download/$TAG/$TARBALL"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

cd "$WORKDIR" || die Failed to create temporary directory
curl -fsSL --retry 3 --connect-timeout 5 -o "$TARBALL" "$URI" \
    || die Failed to download $URI
tar -xzvf "$TARBALL"
cd "$EXDIR" || die Failed to enter directory: $EXDIR

PREFIX=/usr/local
MANPREFIX="$PREFIX/share/man"
PROG='dpibreak'
MAN='dpibreak.1'

do_install() {
    do_sudo install -Dm755 "$PROG" "$PREFIX/bin/$PROG"
    do_sudo install -Dm644 "$MAN"  "$MANPREFIX/man1/$MAN"
    echo "Installation complete." >&2
}

do_uninstall() {
    do_sudo rm -f "$PREFIX/bin/$PROG"
    do_sudo rm -f "$MANPREFIX/man1/$MAN"
    echo "Uninstallation complete." >&2
}

case "$MODE" in
    install)   do_install   ;;
    uninstall) do_uninstall ;;
esac
