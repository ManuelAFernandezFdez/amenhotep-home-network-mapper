#!/usr/bin/env bash
# Install the Amenhotep launcher entry + icon for the current user (no root needed).
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exe="$root/.venv/bin/amenhotep-gui"
[ -x "$exe" ] || { echo "not found: $exe (run: pip install -e '.[gui]')" >&2; exit 1; }
apps="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
icons="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/scalable/apps"
mkdir -p "$apps" "$icons"
cp "$root/assets/amenhotep-logo.svg" "$icons/amenhotep.svg"
cat > "$apps/amenhotep.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Amenhotep
Comment=Nothing stays hidden from Amun: map every device on your home network
Exec=$exe
Icon=amenhotep
Terminal=false
Categories=Network;Utility;
StartupWMClass=amenhotep
EOF
update-desktop-database "$apps" 2>/dev/null || true
gtk-update-icon-cache -q "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" 2>/dev/null || true
echo "installed: $apps/amenhotep.desktop"
