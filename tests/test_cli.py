from pathlib import Path

from amenhotep import cli

ROOT = Path(__file__).parents[1]


def test_scan_rejects_public_target(capsys):
    assert cli.main(["scan", "--target", "8.8.8.0/24"]) == 2
    assert "refused" in capsys.readouterr().err


def test_list_empty_db(capsys):
    assert cli.main(["list"]) == 0
    assert "MAC" in capsys.readouterr().out


def test_doctor_runs(capsys):
    cli.main(["doctor"])
    assert "amenhotep" in capsys.readouterr().out


def test_validate_example_house(capsys):
    assert cli.main(["validate-house", str(ROOT / "model/house.example.json")]) == 0


def test_validate_bad_house(tmp_path, capsys):
    bad = tmp_path / "h.json"
    bad.write_text('{"format": "nope"}')
    assert cli.main(["validate-house", str(bad)]) == 1
