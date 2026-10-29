"""Shared fixtures: a stand-in for the Anthropic client so tests never touch the network."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_ALERT = ROOT / "tests" / "fixtures" / "sample-alert.json"

# A plausible assessment for the sample alert. Synthetic test data, not a model output.
SAMPLE_ASSESSMENT: dict[str, Any] = {
    "verdict": "true_positive",
    "confidence": "medium",
    "severity": "High",
    "summary": "Two MFA prompts for ada.marsh from a residential proxy she has never used.",
    "timeline": [
        {"time": "2026-08-01T17:00:00Z", "event": "First MFA interrupt from 203.0.113.7"},
        {"time": "2026-08-01T17:00:20Z", "event": "Second MFA interrupt from 203.0.113.7"},
    ],
    "key_evidence": ["203.0.113.7 is a suspicious residential proxy exit in NL"],
    "benign_explanations_considered": ["User travelling and retrying sign-in"],
    "recommended_actions": [
        {
            "action": "revoke_sessions",
            "target": "ada.marsh@harborline.example",
            "rationale": "Password appears known to an outside party.",
        },
        {
            "action": "block_ip",
            "target": "203.0.113.7",
            "rationale": "Proxy exit with no business use.",
        },
    ],
    "attack_mapping": [
        {
            "technique_id": "T1621",
            "technique_name": "Multi-Factor Authentication Request Generation",
            "tactic": "Credential Access",
        }
    ],
    "detection_tuning_notes": ["Two prompts is below the production threshold of eight."],
    "open_questions": ["Did ada.marsh approve any prompt?"],
}


class FakeMessages:
    def __init__(self, response: Any):
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self.response


class FakeClient:
    def __init__(self, response: Any):
        self.beta = SimpleNamespace(messages=FakeMessages(response))

    @property
    def calls(self) -> list[dict[str, Any]]:
        return self.beta.messages.calls


def fake_response(
    text: str | None = None, stop_reason: str = "end_turn", model: str = "claude-sonnet-5-5"
) -> Any:
    if text is None:
        text = json.dumps(SAMPLE_ASSESSMENT)
    return SimpleNamespace(
        content=[
            SimpleNamespace(type="thinking", thinking=""),
            SimpleNamespace(type="text", text=text),
        ],
        stop_reason=stop_reason,
        stop_details=None,
        model=model,
        usage=SimpleNamespace(input_tokens=1200, output_tokens=640),
        _request_id="req_test",
    )


@pytest.fixture
def fake_client() -> FakeClient:
    return FakeClient(fake_response())
