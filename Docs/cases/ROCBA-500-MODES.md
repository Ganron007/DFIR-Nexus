# Pipeline modes (product contract)

Examiner-facing copies live **here** under `Docs/cases/<case_id>/reports/`.
`~/.nexus/cases/` is the runtime working store (SQLite, HMAC audit, full CSVs).
It is not temp, and it is not the deliverable.

Map: [TOOL-EVIDENCE-MAP.md](TOOL-EVIDENCE-MAP.md) (interpret/report + other surfaces).
Ship tests: [COMPLETE-TO-SHIP.md](../internal/COMPLETE-TO-SHIP.md) M6a–d.

## What each mode does (wired in the product)

| Mode | RAG | LLM | Parsers | Output |
|------|-----|-----|---------|--------|
| `tools` | no | no | YAML-present artifacts, **all user profiles** | `TOOL-RUN.md` only. No HITL. |
| `coverage` (`debug`) | yes (interpret) | interpret snippets | **same** mandatory lane | `REPORT.md` from APPROVED findings |
| `design` | yes (whole run) | extras + interpret | mandatory lane **first**, then ReAct may add | `REPORT.md` from APPROVED findings |
| `interpret` | yes | interpret | reuse existing ledger (`--from-case`) | `REPORT.md` |

SKIP = artifact absent on this pack (OK). FAIL = artifact present, tool broke.

Hypothesis / playbooks do not shrink the lane. They select extra design jobs
and how interpret reads the snippets.

## Historical Rocba-500 runs (2026-08-12 — before this wiring)

Those three cases (`INC-20260812165727` tools, `INC-20260812171906` coverage,
`INC-20260812173933` design) were produced by the **old** graphs (tools still
called interpret; first user only; design ReAct picked parsers). Do not treat
their finding counts as the product contract. Re-run after this wiring to
refresh examiner copies.
