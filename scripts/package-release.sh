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

NAME=$(cargo metadata --format-version=1 --no-deps \
           | jq -r '.packages[0].name')
VERSION=$(cargo metadata --format-version=1 --no-deps \
              | jq -r '.packages[0].version')
DISTNAME="$NAME-$VERSION"

export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) # for reproducible build

cargo build --release

mkdir -p "dist/$DISTNAME"
cp "target/release/$NAME" "dist/$DISTNAME/"
cp COPYING "dist/$DISTNAME/"
cp README.md "dist/$DISTNAME/"

tar -C dist \
    --sort=name \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=0 --group=0 --numeric-owner \
    -czf "${DISTNAME}.tar.gz" "$DISTNAME"
