import json
from datetime import UTC, datetime

import pytest

from casebook.assess import assess
from casebook.cli import main
from casebook.enrich import Context, enrich
from casebook.models import load_alert
from casebook.records import ActionDecision, Decision, Run, save_run
from casebook.render import render_case
from casebook.replay import replay
from conftest import SAMPLE_ALERT

SECTIONS = [
    "## 1. Verdict and summary",
    "## 2. Timeline",
    "## 3. Evidence",
    "## 4. AI assessment",
    "## 5. Human decision and rationale",
    "## 6. Actions",
    "## 7. ATT&CK mapping",
    "## 8. Detection tuning notes",
]
UPN = "ada.marsh@harborline.example"


@pytest.fixture
def run(fake_client) -> Run:
    alert = load_alert(SAMPLE_ALERT)
    enrichment = enrich(alert, Context.load())
    assessment, call = assess(alert, enrichment, fake_client)
    return Run(
        case_id=alert.id,
        recorded_at=datetime(2026, 8, 1, 17, 12, tzinfo=UTC),
        alert=alert.model_dump(mode="json"),
        enrichment=enrichment,
        model_call=call,
        assessment=assessment,
    )


def _decide(run: Run, verdict: str) -> Run:
    run.decision = Decision(
        analyst="Test Analyst",
        decided_at=datetime(2026, 8, 1, 17, 30, tzinfo=UTC),
        verdict=verdict,
        severity="High",
        rationale="Rationale | with a pipe.",
        actions=[
            ActionDecision(action="revoke_sessions", target=UPN, source="ai",
                           status="approved", reason="Contain.", approver="Test Analyst"),
            ActionDecision(action="block_ip", target="203.0.113.7", source="ai",
                           status="rejected", reason="Rotating proxy.", approver="Test Analyst"),
        ],
        tuning_notes=["Raise the threshold."],
    )
    return run


def test_sections_in_spec_order(run):
    text = render_case(_decide(run, "true_positive"))
    positions = [text.index(s) for s in SECTIONS]
    assert positions == sorted(positions)


def test_agreeing_case(run):
    text = render_case(_decide(run, "true_positive"))
    assert "Test Analyst agrees with the AI." in text
    assert "| block_ip | 203.0.113.7 | AI | **rejected** | Test Analyst | Rotating proxy. |" in text
    assert "[T1621](https://attack.mitre.org/techniques/T1621/)" in text
    assert "Rationale | with a pipe." in text  # prose, not a table cell


def test_override_is_called_out(run):
    text = render_case(_decide(run, "false_positive"))
    assert "**overrides the AI** (AI said: True positive, medium confidence)" in text


def test_pending_case_approves_nothing(run):
    text = render_case(run)
    assert "awaiting human decision" in text
    assert "None approved." in text
    assert "**approved**" not in text


def test_ai_output_is_verbatim(run):
    text = render_case(run)
    block = text.split("```json\n", 1)[1].split("\n```", 1)[0]
    assert json.loads(block) == json.loads(run.model_call.raw_output)


def test_subtechnique_url(run):
    run.assessment.attack_mapping[0].technique_id = "T1110.001"
    assert "https://attack.mitre.org/techniques/T1110/001/" in render_case(run)


def test_replay_writes_then_checks_clean(run, tmp_path):
    runs, cases = tmp_path / "runs", tmp_path / "cases"
    save_run(_decide(run, "true_positive"), runs / f"{run.case_id}.json")
    assert replay(runs, cases) == ["sample-mfa-burst.md", "README.md"]
    assert replay(runs, cases, check=True) == []
    assert replay(runs, cases) == []  # idempotent
    index = (cases / "README.md").read_text(encoding="utf-8")
    assert "[sample-mfa-burst](sample-mfa-burst.md)" in index and "| Agree |" in index


def test_replay_check_catches_hand_edits(run, tmp_path):
    runs, cases = tmp_path / "runs", tmp_path / "cases"
    save_run(run, runs / f"{run.case_id}.json")
    replay(runs, cases)
    (cases / "sample-mfa-burst.md").write_text("edited by hand\n", encoding="utf-8")
    assert replay(runs, cases, check=True) == ["sample-mfa-burst.md"]
    args = ["--runs-dir", str(runs), "--cases-dir", str(cases), "replay", "--check"]
    assert main(args) == 1


def test_replay_cli_with_no_runs(tmp_path, capsys):
    assert main(["--runs-dir", str(tmp_path), "--cases-dir", str(tmp_path), "replay"]) == 0
    assert "No recorded runs" in capsys.readouterr().out
