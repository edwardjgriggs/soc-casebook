"""The human gate. Nothing the AI recommends counts until a named analyst approves it.

Two ways in:
- interactive: prompts at the terminal, one question at a time
- a decision file (decisions/<case-id>.json): the same answers written down ahead of
  time, so a decision can be reviewed in a diff and re-applied without re-calling the model
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from casebook.records import (
    ACTIONS,
    VERDICTS,
    ActionDecision,
    ActionKind,
    Assessment,
    Decision,
    Severity,
    Verdict,
)

SEVERITIES = ("Low", "Medium", "High", "Critical")

Ask = Callable[[str], str]
Say = Callable[[str], None]


class DecisionError(ValueError):
    pass


# --- Decision files --------------------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _AiActionAnswer(_Strict):
    action: ActionKind
    target: str
    status: str = Field(pattern=r"^(approved|rejected)$")
    reason: str = Field(min_length=1)


class _AddedAction(_Strict):
    action: ActionKind
    target: str
    reason: str = Field(min_length=1)


class DecisionFile(_Strict):
    analyst: str = Field(min_length=1)
    decided_at: datetime | None = None
    verdict: Verdict
    severity: Severity
    rationale: str = Field(min_length=1)
    ai_actions: list[_AiActionAnswer] = []
    added_actions: list[_AddedAction] = []
    tuning_notes: list[str] = []


def decide_from_file(assessment: Assessment, path: Path) -> Decision:
    spec = DecisionFile.model_validate(json.loads(path.read_text(encoding="utf-8")))

    answers = {(a.action, a.target): a for a in spec.ai_actions}
    recommended = [(r.action, r.target) for r in assessment.recommended_actions]

    missing = [k for k in recommended if k not in answers]
    extra = [k for k in answers if k not in recommended]
    if missing or extra:
        lines = [f"{path} does not match the AI's recommended actions."]
        lines += [f"  undecided: {a} -> {t}" for a, t in missing]
        lines += [f"  not recommended by the AI: {a} -> {t}" for a, t in extra]
        raise DecisionError("\n".join(lines))

    actions = [
        ActionDecision(
            action=a,
            target=t,
            source="ai",
            status=answers[(a, t)].status,  # type: ignore[arg-type]
            reason=answers[(a, t)].reason,
            approver=spec.analyst,
        )
        for a, t in recommended
    ]
    actions += [
        ActionDecision(
            action=x.action,
            target=x.target,
            source="analyst",
            status="approved",
            reason=x.reason,
            approver=spec.analyst,
        )
        for x in spec.added_actions
    ]

    return Decision(
        analyst=spec.analyst,
        decided_at=spec.decided_at or datetime.now(UTC),
        verdict=spec.verdict,
        severity=spec.severity,
        rationale=spec.rationale,
        actions=actions,
        tuning_notes=spec.tuning_notes,
    )


# --- Interactive -----------------------------------------------------------------


def _ask_required(ask: Ask, prompt: str) -> str:
    while True:
        answer = ask(prompt).strip()
        if answer:
            return answer


def _ask_choice(ask: Ask, say: Say, prompt: str, choices: tuple[str, ...], default: str) -> str:
    while True:
        answer = ask(f"{prompt} [{default}]: ").strip() or default
        if answer in choices:
            return answer
        say(f"  choose one of: {', '.join(choices)}")


def _ask_yes_no(ask: Ask, prompt: str) -> bool:
    while True:
        answer = ask(prompt).strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False


def decide_interactively(assessment: Assessment, analyst: str, ask: Ask, say: Say) -> Decision:
    say("")
    say("=== AI assessment ===")
    say(f"verdict    : {assessment.verdict} ({assessment.confidence} confidence)")
    say(f"severity   : {assessment.severity}")
    say(f"summary    : {assessment.summary}")
    if assessment.open_questions:
        say("open questions:")
        for q in assessment.open_questions:
            say(f"  - {q}")
    say("")
    say(f"=== Your decision ({analyst}) ===")

    verdict = _ask_choice(ask, say, "verdict", VERDICTS, assessment.verdict)
    severity = _ask_choice(ask, say, "severity", SEVERITIES, assessment.severity)
    if verdict != assessment.verdict:
        say(f"  You are overriding the AI ({assessment.verdict} -> {verdict}).")
    rationale = _ask_required(ask, "rationale (why this verdict): ")

    actions: list[ActionDecision] = []
    for i, rec in enumerate(assessment.recommended_actions, 1):
        say("")
        say(f"AI action {i}/{len(assessment.recommended_actions)}: {rec.action} -> {rec.target}")
        say(f"  why: {rec.rationale}")
        approved = _ask_yes_no(ask, "  approve? [y/n]: ")
        reason = _ask_required(ask, "  reason: ")
        actions.append(
            ActionDecision(
                action=rec.action,
                target=rec.target,
                source="ai",
                status="approved" if approved else "rejected",
                reason=reason,
                approver=analyst,
            )
        )

    say("")
    while _ask_yes_no(ask, "add an action the AI did not recommend? [y/n]: "):
        kind = _ask_choice(ask, say, "  action", ACTIONS, "revoke_sessions")
        target = _ask_required(ask, "  target: ")
        reason = _ask_required(ask, "  reason: ")
        actions.append(
            ActionDecision(
                action=kind,  # type: ignore[arg-type]
                target=target,
                source="analyst",
                status="approved",
                reason=reason,
                approver=analyst,
            )
        )

    tuning: list[str] = []
    note = ask("detection tuning note (optional, enter to skip): ").strip()
    if note:
        tuning.append(note)

    return Decision(
        analyst=analyst,
        decided_at=datetime.now(UTC),
        verdict=verdict,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        rationale=rationale,
        actions=actions,
        tuning_notes=tuning,
    )
