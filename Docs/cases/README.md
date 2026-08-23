# Case docs (public)

Live investigation copies (`Docs/cases/INC-*/`) stay on the examiner host and
are gitignored. This folder publishes **maps and mode contracts** only.

| Path | Purpose |
|------|---------|
| [`../NEXUS-MODE.md`](../NEXUS-MODE.md) | Operator loop: collect → register → N1–N8 |
| [`../guide.md`](../guide.md), [`ARCHITECTURE.md`](../ARCHITECTURE.md), [`CLI.md`](../CLI.md), [`SETUP.md`](../SETUP.md), [`FAQ.md`](../FAQ.md) | Product docs |
| [`TOOL-EVIDENCE-MAP.md`](TOOL-EVIDENCE-MAP.md) | Evidence ↔ parser contract (N2) |
| [`TOOL-CATALOG-MAP.md`](TOOL-CATALOG-MAP.md) | Catalog vs YAML vs mandatory lane |
| [`ROCBA-500-MODES.md`](ROCBA-500-MODES.md) | Pipeline modes (`tools` / `coverage` / `design` / `interpret`) |

## Operator loop

```text
Stage 0  nexus collect run          CLI only (portable; freeze-gated)
Register nexus case init + evidence register
N2       nexus pipeline --mode tools
N1–N8    intake → query → interpret → HMAC → report
```

Collect does not run Hayabusa / Suzaku / Chainsaw. Those parse collected EVTX
at N2. Register is not an N1–N8 step.

Investigation UI (Examiner Portal) covers register, query, approve, timeline,
and report. Live harvest stays on the CLI.

## Pipeline modes

| Mode | LLM? | Output |
|------|------|--------|
| `tools` | **No** | `reports/TOOL-RUN.md` (OK/FAIL/SKIP ledger) |
| `coverage` | Interpret only | `REPORT.md` from APPROVED findings |
| `design` | Lane first, then optional ReAct extras | `REPORT.md` from APPROVED findings |
| `interpret` | Interpret existing ledger (`--from-case`) | `REPORT.md` |

`REPORT.md` is a **template from APPROVED findings**, not an LLM dump of every CSV.
SKIP = artifact absent. FAIL = artifact present, tool broke.
