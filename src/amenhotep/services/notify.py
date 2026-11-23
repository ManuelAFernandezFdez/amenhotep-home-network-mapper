"""Desktop notifications through `notify-send` (optional; silently skipped when absent)."""

from __future__ import annotations

import shutil
import subprocess

from amenhotep.core.models import cap


def _plain(text: str, limit: int) -> str:
    # Notification servers may render a small HTML subset: neutralise markup from LAN data.
    clean = cap(text, limit) or ""
    return clean.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def notify(title: str, body: str) -> bool:
    exe = shutil.which("notify-send")
    if not exe:
        return False
    try:
        subprocess.run(  # noqa: S603 (argument list, absolute path, no shell)
            [exe, "--app-name=Amenhotep", "--icon=amenhotep", _plain(title, 80), _plain(body, 300)],
            timeout=5,
            check=False,
            capture_output=True,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return True
