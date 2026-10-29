"""Command-line entry point: `casebook triage` and `casebook replay`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pydantic import ValidationError

from casebook import __version__
from casebook.models import load_alert


def _triage(args: argparse.Namespace) -> int:
    try:
        alert = load_alert(Path(args.alert))
    except FileNotFoundError:
        print(f"error: alert file not found: {args.alert}", file=sys.stderr)
        return 1
    except ValidationError as exc:
        print(f"error: {args.alert} is not a valid alert:\n{exc}", file=sys.stderr)
        return 1

    d = alert.detection
    print(f"{alert.id}  {alert.title}")
    print(f"  detection : {d.name} ({d.technique_id}, {d.tactic}, {d.severity})")
    print(f"  fired at  : {alert.fired_at.isoformat()}")
    print(f"  users     : {', '.join(alert.entities.users) or '-'}")
    print(f"  ips       : {', '.join(alert.entities.ips) or '-'}")
    print(f"  evidence  : {len(alert.evidence)} log rows")
    print("\nAI triage is not wired up yet; this run only validated the alert.")
    return 0


def _replay(_args: argparse.Namespace) -> int:
    print("No recorded runs yet. Replay arrives with the triage pipeline.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="casebook",
        description="AI first-pass alert triage with a human decision and a written case file.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    triage = sub.add_parser("triage", help="triage one alert JSON file")
    triage.add_argument("alert", help="path to an alert JSON file")
    triage.set_defaults(func=_triage)

    replay = sub.add_parser("replay", help="rebuild case files from recorded runs (no API key)")
    replay.set_defaults(func=_replay)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
