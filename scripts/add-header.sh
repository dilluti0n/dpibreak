#!/usr/bin/env bash

set -e

targets=('*.rs' '*.toml' '*.sh')

license_text="$(cat <<'EOF'
Copyright 2025 Dillution <hskimse1@gmail.com>.

This file is part of DPIBreak.

DPIBreak is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

DPIBreak is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with DPIBreak. If not, see <https://www.gnu.org/licenses/>.

EOF
)"

comment_file() {
    local comment_token=''
    case "$1" in
        rs)      comment_token='\/\/' ;;
        toml|sh) comment_token='#'    ;;
    esac

    echo "$license_text" | sed "s/^/$comment_token /" | sed 's/[[:blank:]]\+$//'
}

for pattern in "${targets[@]}"; do
    for file in $(find . -type f -name "$pattern"); do
        ext="${file##*.}"
        if grep -q "GNU General Public License" "$file"; then
            echo "SKIP: $file (already has license)"
            continue
        fi
        echo "ADDING: $file"
        header="$(comment_file "$ext")"
        tmpfile="$(mktemp)"
        chmod --reference="$file" "$tmpfile"
        {
            echo "$header"
            echo
            cat "$file"
        } > "$tmpfile"
        mv "$tmpfile" "$file"
    done
done
