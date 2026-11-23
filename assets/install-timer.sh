#!/usr/bin/env bash
# Install (or remove) a systemd *user* timer that runs `amenhotep watch` regularly.
#   assets/install-timer.sh [minutes]     default 20
#   assets/install-timer.sh --remove
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
if [ "${1:-}" = "--remove" ]; then
  systemctl --user disable --now amenhotep-watch.timer 2>/dev/null || true
  rm -f "$dir/amenhotep-watch.service" "$dir/amenhotep-watch.timer"
  systemctl --user daemon-reload
  echo "removed amenhotep-watch timer"; exit 0
fi
minutes="${1:-20}"
[[ "$minutes" =~ ^[0-9]+$ ]] && [ "$minutes" -ge 5 ] || { echo "minutes must be a number >= 5" >&2; exit 1; }
exe="$root/.venv/bin/amenhotep"
[ -x "$exe" ] || { echo "not found: $exe (run: pip install -e .)" >&2; exit 1; }
mkdir -p "$dir"
cat > "$dir/amenhotep-watch.service" <<EOF
[Unit]
Description=Amenhotep presence pass

[Service]
Type=oneshot
ExecStart=$exe watch --notify
Nice=10
EOF
cat > "$dir/amenhotep-watch.timer" <<EOF
[Unit]
Description=Run the Amenhotep presence pass every $minutes minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=${minutes}min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now amenhotep-watch.timer
echo "installed: every $minutes minutes. Check with: systemctl --user list-timers amenhotep-watch"
