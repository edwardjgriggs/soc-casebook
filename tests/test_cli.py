import json

import pytest

from casebook import cli
from casebook.cli import main
from casebook.records import load_run
from conftest import SAMPLE_ALERT, SAMPLE_ASSESSMENT

UPN = "ada.marsh@harborline.example"


@pytest.fixture
def decisions(tmp_path):
    path = tmp_path / "decision.json"
    path.write_text(json.dumps({
        "analyst": "Test Analyst",
        "decided_at": "2026-08-01T17:30:00Z",
        "verdict": "true_positive",
        "severity": "High",
        "rationale": "Proxy IP the user has never used.",
        "ai_actions": [
            {"action": "revoke_sessions", "target": UPN, "status": "approved", "reason": "Contain."},
            {"action": "block_ip", "target": "203.0.113.7", "status": "rejected", "reason": "Rotating proxy."},
        ],
    }), encoding="utf-8")
    return path


@pytest.fixture
def with_key(monkeypatch, fake_client):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    monkeypatch.setattr(cli, "_make_client", lambda: fake_client)
    return fake_client


def _triage(tmp_path, *extra):
    return main(["--runs-dir", str(tmp_path / "runs"), "--cases-dir", str(tmp_path / "cases"), "triage", str(SAMPLE_ALERT), *extra])


def test_triage_records_run_with_decision(tmp_path, with_key, decisions, capsys):
    assert _triage(tmp_path, "--decisions", str(decisions)) == 0
    run = load_run(tmp_path / "runs" / "sample-mfa-burst.json")
    assert run.assessment.model_dump() == SAMPLE_ASSESSMENT
    assert run.decision is not None and run.decision.analyst == "Test Analyst"
    assert run.enrichment["users"][0]["upn"] == UPN
    assert "agrees with" in capsys.readouterr().out


def test_triage_refuses_to_overwrite_a_run(tmp_path, with_key, decisions, capsys):
    assert _triage(tmp_path, "--decisions", str(decisions)) == 0
    assert _triage(tmp_path, "--decisions", str(decisions)) == 1
    assert "already exists" in capsys.readouterr().err
    assert len(with_key.calls) == 1
    assert _triage(tmp_path, "--decisions", str(decisions), "--force") == 0
    assert len(with_key.calls) == 2


def test_triage_without_decision_keeps_ai_output(tmp_path, with_key, monkeypatch):
    def walk_away(_prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", walk_away)
    assert _triage(tmp_path, "--analyst", "Test Analyst") == 2
    run = load_run(tmp_path / "runs" / "sample-mfa-burst.json")
    assert run.decision is None
    assert run.assessment.verdict == "true_positive"


def test_bad_decision_file_keeps_ai_output(tmp_path, with_key, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "analyst": "x", "verdict": "true_positive", "severity": "High", "rationale": "x",
    }), encoding="utf-8")
    assert _triage(tmp_path, "--decisions", str(bad)) == 1
    assert "undecided" in capsys.readouterr().err
    assert load_run(tmp_path / "runs" / "sample-mfa-burst.json").decision is None


def test_decide_applies_to_recorded_run(tmp_path, with_key, decisions, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _p: (_ for _ in ()).throw(EOFError))
    assert _triage(tmp_path, "--analyst", "x") == 2
    calls_before = len(with_key.calls)
    assert main(["--runs-dir", str(tmp_path / "runs"), "--cases-dir", str(tmp_path / "cases"), "decide", "sample-mfa-burst",
                 "--decisions", str(decisions)]) == 0
    assert len(with_key.calls) == calls_before  # no new model call
    assert load_run(tmp_path / "runs" / "sample-mfa-burst.json").decision is not None


def test_decide_unknown_case(tmp_path, capsys):
    assert main(["--runs-dir", str(tmp_path), "--cases-dir", str(tmp_path / "cases"), "decide", "nope"]) == 1
    assert "no recorded run" in capsys.readouterr().err


def test_triage_without_key_points_to_replay(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert _triage(tmp_path) == 1
    assert "casebook replay" in capsys.readouterr().err


def test_triage_missing_file(capsys, tmp_path):
    assert main(["triage", str(tmp_path / "nope.json")]) == 1
    assert "not found" in capsys.readouterr().err


def test_triage_invalid_alert(capsys, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"id": "x"}', encoding="utf-8")
    assert main(["triage", str(bad)]) == 1
    assert "not a valid alert" in capsys.readouterr().err


def test_command_required():
    with pytest.raises(SystemExit):
        main([])
