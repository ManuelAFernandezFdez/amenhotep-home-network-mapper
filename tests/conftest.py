from pathlib import Path

import pytest

from amenhotep.store import db
from amenhotep.store.repo import Repository

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Never touch the user's real data dir."""
    monkeypatch.setenv("AMENHOTEP_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("AMENHOTEP_DB", raising=False)


@pytest.fixture
def repo():
    return Repository(db.connect(":memory:"))


@pytest.fixture
def nmap_xml() -> str:
    return (FIXTURES / "nmap" / "lan_standard.xml").read_text()
