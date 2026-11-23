import threading
import time

import pytest

from amenhotep.collectors.nmap import NmapCollector, NmapError, ScanCancelled


def test_cancellable_runner_terminates_process_promptly():
    c = NmapCollector(nmap_path="/usr/bin/nmap")
    threading.Timer(0.5, c.cancel.set).start()
    start = time.monotonic()
    with pytest.raises(ScanCancelled):
        c._cancellable_run(["sleep", "30"], timeout=60)
    assert time.monotonic() - start < 5


def test_cancellable_runner_enforces_timeout():
    c = NmapCollector(nmap_path="/usr/bin/nmap")
    with pytest.raises(NmapError, match="timed out"):
        c._cancellable_run(["sleep", "30"], timeout=1)


def test_cancellable_runner_returns_output():
    c = NmapCollector(nmap_path="/usr/bin/nmap")
    code, out, _ = c._cancellable_run(["echo", "hi"], timeout=5)
    assert code == 0 and out.strip() == "hi"
