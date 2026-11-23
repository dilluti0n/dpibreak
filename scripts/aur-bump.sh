#!/bin/bash
#
# Bump the dpibreak AUR package to a release tag.
#     scripts/aur-bump.sh [vX.Y.Z]   (default: latest release)

REPO="dilluti0n/dpibreak"
AUR="ssh://aur@aur.archlinux.org/dpibreak.git"
IMAGE="dpibreak-aur"
DOCKERFILE_DIR="$(cd "$(dirname "$0")/.." && pwd)/contrib/aur"

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

TAG="${1:-$(get_tag)}"
VER="${TAG#v}"
WORKDIR=$(mktemp -d)
trap 'rm -rf $WORKDIR' EXIT

sum=$(curl -fsSL "https://github.com/$REPO/archive/refs/tags/v$VER.tar.gz" \
          | sha256sum | cut -d ' ' -f 1)
[ ${#sum} -eq 64 ] || die "Fail to fetch v$VER tarball"

docker image inspect "$IMAGE" >/dev/null 2>&1 \
    || docker build -t "$IMAGE" "$DOCKERFILE_DIR" || die "Fail to build $IMAGE"

git clone -q "$AUR" "$WORKDIR/dpibreak" || die "Fail to clone $AUR"
cd "$WORKDIR/dpibreak"

sed -i -e "s/^pkgver=.*/pkgver=$VER/" \
       -e "s/^pkgrel=.*/pkgrel=1/" \
       -e "s/^sha256sums=.*/sha256sums=('$sum')/" PKGBUILD

docker run --rm -v "$PWD":/home/builder/pkg "$IMAGE" \
       bash -c "cd pkg && makepkg --printsrcinfo > .SRCINFO" \
    || die "Fail to generate .SRCINFO"

git --no-pager diff
git commit -q -am "upgpkg: dpibreak $VER" || die "Nothing to commit"

read -rp "Push to $AUR? [y/N] " ans
[ "$ans" = y ] && git push
