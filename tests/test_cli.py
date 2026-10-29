from pathlib import Path

import pytest

from casebook.cli import main

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "sample-alert.json"


def test_triage_validates_sample(capsys):
    assert main(["triage", str(SAMPLE)]) == 0
    out = capsys.readouterr().out
    assert "sample-mfa-burst" in out
    assert "T1621" in out


def test_triage_missing_file(capsys, tmp_path):
    assert main(["triage", str(tmp_path / "nope.json")]) == 1
    assert "not found" in capsys.readouterr().err


def test_triage_invalid_alert(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"id": "x"}', encoding="utf-8")
    assert main(["triage", str(bad)]) == 1
    assert "not a valid alert" in capsys.readouterr().err


def test_replay_runs():
    assert main(["replay"]) == 0


def test_command_required():
    with pytest.raises(SystemExit):
        main([])
