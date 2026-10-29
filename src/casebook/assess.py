"""The single model call: alert + enrichment in, a schema-constrained assessment out."""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from casebook import paths
from casebook.models import Alert
from casebook.records import Assessment, ModelCall, Usage

MODEL = "claude-sonnet-5-5"
MAX_TOKENS = 16000
# If Sonnet's safeguards decline a request (security content can trip them), the API
# re-runs it on a fallback model in the same call. The run records which model served.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AssessmentError(RuntimeError):
    pass


def load_prompt() -> tuple[str, dict[str, Any]]:
    system = paths.SYSTEM_PROMPT.read_text(encoding="utf-8")
    schema = json.loads(paths.OUTPUT_SCHEMA.read_text(encoding="utf-8"))
    return system, schema


def build_user_message(alert: Alert, enrichment: dict[str, Any]) -> str:
    alert_json = json.dumps(alert.model_dump(mode="json"), indent=2, sort_keys=True)
    enrichment_json = json.dumps(enrichment, indent=2, sort_keys=True)
    return (
        "Triage this alert.\n\n"
        f"<alert>\n{alert_json}\n</alert>\n\n"
        f"<enrichment>\n{enrichment_json}\n</enrichment>"
    )


def assess(
    alert: Alert, enrichment: dict[str, Any], client: Any
) -> tuple[Assessment, ModelCall]:
    """Call the model once. `client` is an `anthropic.Anthropic` (or a test double)."""
    system, schema = load_prompt()
    user_message = build_user_message(alert, enrichment)

    response = client.beta.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=system,
        messages=[{"role": "user", "content": user_message}],
        output_config={"effort": "high", "format": {"type": "json_schema", "schema": schema}},
        betas=[FALLBACK_BETA],
        fallbacks="default",
    )

    if response.stop_reason == "refusal":
        details = getattr(response, "stop_details", None)
        category = getattr(details, "category", None) if details else None
        raise AssessmentError(f"model declined the request (category: {category})")
    if response.stop_reason == "max_tokens":
        raise AssessmentError("model output hit max_tokens before the assessment was complete")

    raw = next((b.text for b in response.content if b.type == "text"), None)
    if raw is None:
        raise AssessmentError(f"no text block in response (stop_reason: {response.stop_reason})")

    try:
        assessment = Assessment.model_validate_json(raw)
    except ValidationError as exc:
        raise AssessmentError(f"model output did not match the assessment schema:\n{exc}") from exc

    call = ModelCall(
        model_requested=MODEL,
        model_served=response.model,
        request_id=getattr(response, "_request_id", None),
        stop_reason=response.stop_reason,
        usage=Usage(
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        ),
        system_prompt=system,
        output_schema=schema,
        user_message=user_message,
        raw_output=raw,
    )
    return assessment, call
