#!/bin/bash

REPO="dilluti0n/dpibreak"
EMAIL="hskim@dilluti0n.com"
FILE="sha256sum.txt"
SIG_FILE="$FILE.sig"

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
WORKDIR=$(mktemp -d)
trap 'rm -rf $WORKDIR' EXIT

cd "$WORKDIR"

gh release download "$TAG" -R "$REPO" -p "$FILE" || die "Fail to download $TAG from $REPO"
gpg --local-user "$EMAIL" --output "$SIG_FILE" --detach-sign "$FILE" \
    || die "Fail to sign with $EMAIL"
gh release upload "$TAG" -R "$REPO" "$SIG_FILE"
