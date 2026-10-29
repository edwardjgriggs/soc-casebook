"""Turn a run record into a case file. Pure function of the run: same run, same bytes."""

from __future__ import annotations

import json
from typing import Any

from casebook.records import Run

VERDICT_LABELS = {
    "true_positive": "True positive",
    "benign_true_positive": "Benign true positive",
    "false_positive": "False positive",
    "needs_more_info": "Needs more info",
}

DETECTION_REPO = "https://github.com/edwardjgriggs/detection-as-code"


def _cell(value: Any) -> str:
    if value is None or value == "" or value == []:
        return "-"
    if isinstance(value, (dict, list)):
        text = f"`{json.dumps(value, separators=(',', ':'))}`"
    elif isinstance(value, bool):
        text = "yes" if value else "no"
    else:
        text = str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(_cell(v) for v in row) + " |" for row in rows]
    return lines


def _bullets(items: list[str], empty: str = "None.") -> list[str]:
    return [f"- {i}" for i in items] if items else [empty]


def _attack_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def _verdict(v: str) -> str:
    return VERDICT_LABELS.get(v, v)


def render_case(run: Run) -> str:
    alert = run.alert
    det = alert["detection"]
    ai = run.assessment
    dec = run.decision
    call = run.model_call

    out: list[str] = [f"# Case {run.case_id}: {alert['title']}", ""]
    out.append(
        f"Detection **{det['name']}** ({det['technique_id']}, {det['severity']}) fired at "
        f"{alert['fired_at']}. Lab case: built from the detection's known-bad fixture, "
        "enriched against the fictional Harborline Federal directory."
    )
    out.append("")

    # 1. Verdict and summary
    out += ["## 1. Verdict and summary", ""]
    if dec is None:
        out += [
            "**Status: awaiting human decision.** The AI assessment below has not been "
            "reviewed. No action has been approved.",
            "",
        ]
    else:
        agreement = (
            "agrees with the AI"
            if dec.agrees_with(ai)
            else f"**overrides the AI** (AI said: {_verdict(ai.verdict)}, "
            f"{ai.confidence} confidence)"
        )
        out += _table(
            ["", "Verdict", "Severity"],
            [
                ["Final (human)", f"**{_verdict(dec.verdict)}**", dec.severity],
                ["AI first pass", f"{_verdict(ai.verdict)} ({ai.confidence} confidence)",
                 ai.severity],
            ],
        )
        out += ["", f"{dec.analyst} {agreement}.", ""]
    out += [ai.summary, ""]

    # 2. Timeline
    out += ["## 2. Timeline", ""]
    rows: list[list[Any]] = [[t.time, t.event, "AI, from evidence"] for t in ai.timeline]
    rows.append([alert["fired_at"], f"Detection fired: {det['name']}", "SIEM"])
    rows.append([run.recorded_at.isoformat(), f"AI assessment recorded ({call.model_served})",
                 "casebook"])
    if dec is not None:
        rows.append([dec.decided_at.isoformat(), f"Decision by {dec.analyst}: "
                     f"{_verdict(dec.verdict)}", "analyst"])
    out += _table(["Time (UTC)", "Event", "Source"], rows)
    out.append("")

    # 3. Evidence
    out += ["## 3. Evidence", "", "### Detection output", ""]
    out += _table(["Field", "Value"], [[k, v] for k, v in alert["detection_output"].items()])
    out += ["", f"### Log rows that fired ({det['source_table']}, {len(alert['evidence'])} rows)",
            ""]
    columns: list[str] = []
    for row in alert["evidence"]:
        columns += [c for c in row if c not in columns]
    out += _table(columns, [[row.get(c) for c in columns] for row in alert["evidence"]])
    out.append("")

    enr = run.enrichment
    out += ["### Enrichment", ""]
    if enr["users"]:
        out += _table(
            ["User", "In directory", "Title", "Admin", "MFA methods", "Usual countries",
             "Alert IPs new for user"],
            [
                [u["upn"], u["found"], u.get("title"), u.get("is_admin"), u.get("mfa_methods"),
                 u.get("usual_countries"), u.get("alert_ips_not_known_for_user")]
                for u in enr["users"]
            ],
        )
        out.append("")
    if enr["ips"]:
        out += _table(
            ["IP", "Known", "Country", "Owner", "Reputation", "Notes"],
            [
                [i["ip"], i["found"], i.get("country"), i.get("owner"), i.get("reputation"),
                 i.get("notes")]
                for i in enr["ips"]
            ],
        )
        out.append("")
    if enr["apps"]:
        out += _table(
            ["App ID", "In catalog", "Name", "Publisher", "Verified publisher", "Sanctioned"],
            [
                [a["app_id"], a["found"], a.get("display_name"), a.get("publisher"),
                 a.get("verified_publisher"), a.get("sanctioned")]
                for a in enr["apps"]
            ],
        )
        out.append("")

    # 4. AI assessment
    out += [
        "## 4. AI assessment",
        "",
        f"Model: `{call.model_served}`"
        + ("" if call.model_served == call.model_requested
           else f" (fallback; requested `{call.model_requested}`)")
        + f". Verdict **{_verdict(ai.verdict)}**, confidence **{ai.confidence}**, "
        f"severity **{ai.severity}**.",
        "",
        "**Key evidence**",
        "",
        *_bullets(ai.key_evidence),
        "",
        "**Benign explanations considered**",
        "",
        *_bullets(ai.benign_explanations_considered),
        "",
        "**Recommended actions**",
        "",
    ]
    out += _table(["Action", "Target", "Rationale"],
                  [[r.action, r.target, r.rationale] for r in ai.recommended_actions])
    out += ["", "**Open questions**", "", *_bullets(ai.open_questions), ""]
    out += [
        "<details><summary>Verbatim model output</summary>",
        "",
        "```json",
        json.dumps(json.loads(call.raw_output), indent=2, ensure_ascii=False),
        "```",
        "",
        "</details>",
        "",
    ]

    # 5. Human decision
    out += ["## 5. Human decision and rationale", ""]
    if dec is None:
        out += ["Pending.", ""]
    else:
        out += [
            f"**Analyst:** {dec.analyst}  ",
            f"**Decided:** {dec.decided_at.isoformat()}  ",
            f"**Verdict:** {_verdict(dec.verdict)} ({dec.severity})",
            "",
            dec.rationale,
            "",
        ]

    # 6. Actions
    out += ["## 6. Actions", ""]
    if dec is None:
        out += ["None approved. Every recommended action waits for a human decision.", ""]
    else:
        out += _table(
            ["Action", "Target", "Recommended by", "Decision", "Approver", "Reason"],
            [
                [a.action, a.target, "AI" if a.source == "ai" else "Analyst",
                 f"**{a.status}**", a.approver, a.reason]
                for a in dec.actions
            ],
        )
        out += ["", "The AI executed nothing. Approved actions are carried out by the analyst.", ""]

    # 7. ATT&CK mapping
    out += ["## 7. ATT&CK mapping", ""]
    mapping = [[f"[{det['technique_id']}]({_attack_url(det['technique_id'])})",
                det["technique_name"], det["tactic"], "Detection"]]
    mapping += [
        [f"[{m.technique_id}]({_attack_url(m.technique_id)})", m.technique_name, m.tactic, "AI"]
        for m in ai.attack_mapping
    ]
    out += _table(["Technique", "Name", "Tactic", "Mapped by"], mapping)
    out.append("")

    # 8. Detection tuning notes
    out += ["## 8. Detection tuning notes", ""]
    out += [f"Rule `{det['rule_id']}` lives in [detection-as-code]({DETECTION_REPO}).", ""]
    if dec is not None and dec.tuning_notes:
        out += ["**Analyst**", "", *_bullets(dec.tuning_notes), ""]
    out += ["**AI**", "", *_bullets(ai.detection_tuning_notes), ""]

    return "\n".join(out).rstrip("\n") + "\n"
