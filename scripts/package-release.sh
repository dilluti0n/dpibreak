#/usr/bin/env bash

# Copyright 2025 Dillution <hskimse1@gmail.com>.
#
# This file is part of DPIBreak.
#
# DPIBreak is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# DPIBreak is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License
# along with DPIBreak. If not, see <https://www.gnu.org/licenses/>.

set -e

if [ ! -f Cargo.toml ] || [ ! -d src ]; then
    echo "Err: execute this on project root only." >&2
    exit 1
fi

NAME=$(cargo metadata --format-version=1 --no-deps \
           | jq -r '.packages[0].name')
VERSION=$(cargo metadata --format-version=1 --no-deps \
              | jq -r '.packages[0].version')
TARGET="x86_64-unknown-linux-musl"
DISTNAME="$NAME-$VERSION-$TARGET"

export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) # for reproducible build

cargo build --release --target "$TARGET"

DIST_DIR="dist/$DISTNAME"

mkdir -p "$DIST_DIR"
cp "target/$TARGET/release/$NAME" "$DIST_DIR"

pushd "$DIST_DIR"
objcopy --only-keep-debug "$NAME" "${NAME}.debug"
strip --strip-unneeded "$NAME"
objcopy --add-gnu-debuglink="${NAME}.debug" "$NAME"
popd

cp COPYING "$DIST_DIR"
cp CHANGELOG "$DIST_DIR"
cp README.md "$DIST_DIR"

TARBALL_NAME="${DISTNAME}.tar.gz"

pushd dist
tar --sort=name \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=0 --group=0 --numeric-owner \
    -czf "$TARBALL_NAME" "$DISTNAME"

echo "$TARBALL_NAME is ready"

sha256sum "$TARBALL_NAME" | tee "${TARBALL_NAME}.sha256"

BUILD_INFO="${DISTNAME}.buildinfo"

cat > "$BUILD_INFO" <<EOF
Name:       $NAME
Version:    $VERSION
Built with: $(rustc --version --verbose | head -n1)
Cargo:      $(cargo --version)
glibc:      $(ldd --version | head -n1 | awk '{print $NF}')
Date:       $(date -u -d "@$SOURCE_DATE_EPOCH" +"%Y-%m-%dT%H:%M:%SZ")
Host:       $(uname -srvmo)
EOF

echo "Build info on $BUILD_INFO"
popd
