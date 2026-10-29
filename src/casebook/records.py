"""The AI assessment, the human decision, and the run record that ties them together.

`Assessment` mirrors prompts/triage-output.schema.json field for field; a test keeps
the two in step. A run record holds everything needed to rebuild a case file
without calling the model again.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["true_positive", "benign_true_positive", "false_positive", "needs_more_info"]
Confidence = Literal["low", "medium", "high"]
Severity = Literal["Low", "Medium", "High", "Critical"]
ActionKind = Literal[
    "disable_account",
    "revoke_sessions",
    "reset_password",
    "require_mfa_reregistration",
    "remove_oauth_grant",
    "block_ip",
    "notify_user",
    "no_action",
]

VERDICTS: tuple[str, ...] = Verdict.__args__  # type: ignore[attr-defined]
ACTIONS: tuple[str, ...] = ActionKind.__args__  # type: ignore[attr-defined]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- AI assessment -------------------------------------------------------------


class TimelineEntry(_Strict):
    time: str
    event: str


class RecommendedAction(_Strict):
    action: ActionKind
    target: str
    rationale: str


class AttackMapping(_Strict):
    technique_id: str
    technique_name: str
    tactic: str


class Assessment(_Strict):
    verdict: Verdict
    confidence: Confidence
    severity: Severity
    summary: str
    timeline: list[TimelineEntry]
    key_evidence: list[str]
    benign_explanations_considered: list[str]
    recommended_actions: list[RecommendedAction]
    attack_mapping: list[AttackMapping]
    detection_tuning_notes: list[str]
    open_questions: list[str]


# --- Human decision ------------------------------------------------------------


class ActionDecision(_Strict):
    action: ActionKind
    target: str
    source: Literal["ai", "analyst"]
    status: Literal["approved", "rejected"]
    reason: str = Field(min_length=1)
    approver: str


class Decision(_Strict):
    analyst: str = Field(min_length=1)
    decided_at: datetime
    verdict: Verdict
    severity: Severity
    rationale: str = Field(min_length=1)
    actions: list[ActionDecision]
    tuning_notes: list[str] = []

    def agrees_with(self, assessment: Assessment) -> bool:
        return self.verdict == assessment.verdict


# --- Run record ----------------------------------------------------------------


class Usage(_Strict):
    input_tokens: int
    output_tokens: int


class ModelCall(_Strict):
    model_requested: str
    model_served: str
    request_id: str | None
    stop_reason: str
    usage: Usage
    system_prompt: str
    output_schema: dict[str, Any]
    user_message: str
    raw_output: str


class Run(_Strict):
    schema_version: Literal[1] = 1
    case_id: str
    recorded_at: datetime
    alert: dict[str, Any]
    enrichment: dict[str, Any]
    model_call: ModelCall
    assessment: Assessment
    decision: Decision | None = None


def load_run(path: Path) -> Run:
    return Run.model_validate(json.loads(path.read_text(encoding="utf-8")))


def save_run(run: Run, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(run.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")
