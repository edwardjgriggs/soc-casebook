"""Command-line entry point: `casebook triage`, `casebook decide`, `casebook replay`."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from casebook import __version__, paths
from casebook.approval import DecisionError, decide_from_file, decide_interactively
from casebook.assess import AssessmentError, assess
from casebook.enrich import Context, enrich
from casebook.models import load_alert
from casebook.records import Decision, Run, load_run, save_run


def _err(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)


def _default_analyst() -> str:
    try:
        name = subprocess.run(
            ["git", "config", "user.name"], capture_output=True, text=True, check=False
        ).stdout.strip()
    except OSError:
        name = ""
    return name or "analyst"


def _make_client() -> Any:
    import anthropic

    return anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])


def _apply_decision(run: Run, args: argparse.Namespace) -> Decision | None:
    """Return the decision, or None if the analyst walked away (EOF / Ctrl-C)."""
    if args.decisions:
        return decide_from_file(run.assessment, Path(args.decisions))
    try:
        return decide_interactively(run.assessment, args.analyst, input, print)
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def _finish(run: Run, run_path: Path, args: argparse.Namespace) -> int:
    try:
        decision = _apply_decision(run, args)
    except (DecisionError, ValidationError, FileNotFoundError) as exc:
        _err(str(exc))
        print(f"The AI assessment is saved in {run_path}; the case is awaiting a decision.")
        return 1
    if decision is None:
        print(f"No decision recorded. The AI assessment is saved in {run_path}.")
        print(f"Finish later with: casebook decide {run.case_id}")
        return 2

    run.decision = decision
    save_run(run, run_path)
    agree = "agrees with" if decision.agrees_with(run.assessment) else "OVERRIDES"
    approved = sum(a.status == "approved" for a in decision.actions)
    print(f"\nRecorded {run_path.name}: {decision.analyst} {agree} the AI "
          f"({decision.verdict}); {approved}/{len(decision.actions)} actions approved.")
    return 0


def _triage(args: argparse.Namespace) -> int:
    try:
        alert = load_alert(Path(args.alert))
    except FileNotFoundError:
        _err(f"alert file not found: {args.alert}")
        return 1
    except ValidationError as exc:
        _err(f"{args.alert} is not a valid alert:\n{exc}")
        return 1

    run_path = Path(args.runs_dir) / f"{alert.id}.json"
    if run_path.exists() and not args.force:
        _err(f"{run_path} already exists. Use `casebook decide {alert.id}` to change the "
             "decision, or --force to call the model again.")
        return 1

    enrichment = enrich(alert, Context.load())
    d = alert.detection
    print(f"{alert.id}  {alert.title}")
    print(f"  detection : {d.name} ({d.technique_id}, {d.tactic}, {d.severity})")
    print(f"  evidence  : {len(alert.evidence)} log rows")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        _err("ANTHROPIC_API_KEY is not set. Without a key, `casebook replay` rebuilds the "
             "committed cases from recorded runs.")
        return 1

    print("  assessing ...")
    try:
        assessment, call = assess(alert, enrichment, _make_client())
    except AssessmentError as exc:
        _err(str(exc))
        return 1

    run = Run(
        case_id=alert.id,
        recorded_at=datetime.now(UTC),
        alert=alert.model_dump(mode="json"),
        enrichment=enrichment,
        model_call=call,
        assessment=assessment,
    )
    save_run(run, run_path)  # the AI output is kept even if no decision follows
    return _finish(run, run_path, args)


def _decide(args: argparse.Namespace) -> int:
    run_path = Path(args.runs_dir) / f"{args.case_id}.json"
    try:
        run = load_run(run_path)
    except FileNotFoundError:
        _err(f"no recorded run at {run_path}. Run `casebook triage` first.")
        return 1
    return _finish(run, run_path, args)


def _replay(_args: argparse.Namespace) -> int:
    print("No recorded runs yet. Replay arrives with the renderer.")
    return 0


def _add_decision_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--decisions", metavar="FILE",
                   help="apply a decision file instead of prompting (see decisions/)")
    p.add_argument("--analyst", default=None,
                   help="name recorded as the approver (default: git user.name)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="casebook",
        description="AI first-pass alert triage with a human decision and a written case file.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--runs-dir", default=str(paths.RUNS), help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)

    triage = sub.add_parser("triage", help="enrich an alert, get the AI assessment, decide")
    triage.add_argument("alert", help="path to an alert JSON file")
    triage.add_argument("--force", action="store_true",
                        help="call the model again even if a run is already recorded")
    _add_decision_args(triage)
    triage.set_defaults(func=_triage)

    decide = sub.add_parser("decide", help="record or change the human decision on a recorded run")
    decide.add_argument("case_id", help="case id (the alert id)")
    _add_decision_args(decide)
    decide.set_defaults(func=_decide)

    replay = sub.add_parser("replay", help="rebuild case files from recorded runs (no API key)")
    replay.set_defaults(func=_replay)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "analyst", "unset") is None:
        args.analyst = _default_analyst()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
