"""Repo-relative locations. The CLI is meant to run from a clone, not an installed wheel."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

ALERTS = ROOT / "alerts"
CONTEXT = ROOT / "context"
PROMPTS = ROOT / "prompts"
RUNS = ROOT / "runs"
CASES = ROOT / "cases"
DECISIONS = ROOT / "decisions"

SYSTEM_PROMPT = PROMPTS / "triage-system.md"
OUTPUT_SCHEMA = PROMPTS / "triage-output.schema.json"
