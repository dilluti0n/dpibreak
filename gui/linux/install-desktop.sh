#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Install the panel for the current user: binary, menu entry and icon.
# Nothing here needs root; the panel asks for the password itself.
#
# Usage: sh gui/linux/install-desktop.sh [path/to/DPIBreak-Panel-linux-x86_64]

set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
bin=${1:-$root/dist/DPIBreak-Panel-linux-x86_64}
data=${XDG_DATA_HOME:-$HOME/.local/share}

install -Dm755 "$bin" "$HOME/.local/bin/dpibreak-panel"
install -Dm644 "$here/dpibreak-panel.desktop" "$data/applications/dpibreak-panel.desktop"
install -Dm644 "$root/res/icon_256.png" "$data/icons/hicolor/256x256/apps/dpibreak-panel.png"
install -Dm644 "$root/res/icon_48.png" "$data/icons/hicolor/48x48/apps/dpibreak-panel.png"
command -v update-desktop-database >/dev/null 2>&1 &&
    update-desktop-database "$data/applications" 2>/dev/null || true

echo "Installed $HOME/.local/bin/dpibreak-panel and the DPIBreak Panel menu entry."
