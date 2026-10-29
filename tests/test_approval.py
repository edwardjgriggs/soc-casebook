import json

import pytest

from casebook.approval import DecisionError, decide_from_file, decide_interactively
from casebook.records import Assessment
from conftest import SAMPLE_ASSESSMENT

ASSESSMENT = Assessment.model_validate(SAMPLE_ASSESSMENT)
UPN = "ada.marsh@harborline.example"


def _decision_file(tmp_path, **overrides):
    spec = {
        "analyst": "Test Analyst",
        "decided_at": "2026-08-01T17:30:00Z",
        "verdict": "true_positive",
        "severity": "High",
        "rationale": "Proxy IP the user has never used.",
        "ai_actions": [
            {"action": "revoke_sessions", "target": UPN, "status": "approved", "reason": "Contain."},
            {"action": "block_ip", "target": "203.0.113.7", "status": "rejected",
             "reason": "Rotating proxy; a block will not hold."},
        ],
        "added_actions": [
            {"action": "require_mfa_reregistration", "target": UPN, "reason": "Push fatigue."}
        ],
    }
    spec.update(overrides)
    path = tmp_path / "decision.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def test_decision_file_records_every_action(tmp_path):
    d = decide_from_file(ASSESSMENT, _decision_file(tmp_path))
    assert d.agrees_with(ASSESSMENT)
    assert [(a.action, a.source, a.status) for a in d.actions] == [
        ("revoke_sessions", "ai", "approved"),
        ("block_ip", "ai", "rejected"),
        ("require_mfa_reregistration", "analyst", "approved"),
    ]
    assert all(a.approver == "Test Analyst" for a in d.actions)


def test_decision_file_must_cover_every_ai_action(tmp_path):
    path = _decision_file(tmp_path, ai_actions=[
        {"action": "revoke_sessions", "target": UPN, "status": "approved", "reason": "Contain."}
    ])
    with pytest.raises(DecisionError, match="undecided: block_ip"):
        decide_from_file(ASSESSMENT, path)


def test_decision_file_rejects_unrecommended_ai_action(tmp_path):
    path = _decision_file(tmp_path, ai_actions=[
        {"action": "revoke_sessions", "target": UPN, "status": "approved", "reason": "x"},
        {"action": "block_ip", "target": "203.0.113.7", "status": "approved", "reason": "x"},
        {"action": "disable_account", "target": UPN, "status": "approved", "reason": "x"},
    ])
    with pytest.raises(DecisionError, match="not recommended by the AI"):
        decide_from_file(ASSESSMENT, path)


def test_decision_requires_a_reason(tmp_path):
    path = _decision_file(tmp_path, rationale="")
    with pytest.raises(ValueError):
        decide_from_file(ASSESSMENT, path)


def test_interactive_override(capsys):
    answers = iter([
        "false_positive",       # verdict
        "",                     # severity: accept AI default
        "",                     # rationale: empty, re-asked
        "Known travel; user confirmed by phone.",
        "n", "No compromise.",  # action 1
        "y", "Cheap to block.",  # action 2
        "y",                    # add an action
        "notify_user", UPN, "Tell her what happened.",
        "n",                    # no more
        "Exclude approved travel.",
    ])
    out: list[str] = []
    d = decide_interactively(ASSESSMENT, "Test Analyst", lambda _p: next(answers), out.append)
    assert d.verdict == "false_positive" and not d.agrees_with(ASSESSMENT)
    assert d.severity == "High"
    assert [a.status for a in d.actions] == ["rejected", "approved", "approved"]
    assert d.actions[2].source == "analyst"
    assert d.tuning_notes == ["Exclude approved travel."]
    assert any("overriding the AI" in line for line in out)
