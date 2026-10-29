# soc-casebook

AI does the first-pass triage on a security alert, a human makes the call, and every alert ends in a written case file.

> Work in progress. v1 target: 2026-11-04.

## Quickstart

```bash
pip install -e ".[dev]"
casebook triage tests/fixtures/sample-alert.json   # validates and summarizes an alert
pytest
```

`casebook triage` will run the full AI triage and human-approval flow once the pipeline lands. `casebook replay` will rebuild every case file from recorded runs with no API key.

## Layout

| Path | What it holds |
|---|---|
| `alerts/` | One alert JSON per case: the log rows that fired plus the detection's output |
| `context/` | Offline enrichment for the fictional Harborline Federal: user directory and IP reputation |
| `src/casebook/` | The CLI |
| `tests/` | pytest suite |

All people, domains, and IPs are fictional. IPs come only from the RFC 5737 documentation ranges.
