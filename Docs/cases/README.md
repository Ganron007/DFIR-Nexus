# Case docs (public)

Live investigation copies (`Docs/cases/INC-*/`) stay on the examiner host and
are gitignored. This folder publishes **maps and mode contracts** only.

| Path | Purpose |
|------|---------|
| [`../NEXUS-MODE.md`](../NEXUS-MODE.md) | Operator loop: collect → register → N1–N8 & Investigation Modes |
| [`../guide.md`](../guide.md), [`ARCHITECTURE.md`](../ARCHITECTURE.md), [`CLI.md`](../CLI.md), [`SETUP.md`](../SETUP.md), [`FAQ.md`](../FAQ.md) | Product docs |
| [`TOOL-EVIDENCE-MAP.md`](TOOL-EVIDENCE-MAP.md) | Evidence ↔ parser contract (N2) |
| [`TOOL-CATALOG-MAP.md`](TOOL-CATALOG-MAP.md) | Catalog vs YAML vs mandatory lane |

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

## Investigation modes

| Mode | Driver | Output & Capabilities |
|------|--------|----------------------|
| **Mode 1 — LLM** | Examiner + LLM Scribe | Steer chat, live Elasticsearch query pushdown, `reports/REPORT.md` from APPROVED findings |
| **Mode 2 — Multi-role** | LangGraph Supervisor | Sequential work-order roles (plan → run → verify → stage), supervised DRAFT candidates |
| **Mode 3 — Multi-agent** | Concurrent team | Concurrent seats on shared Investigation Board with claim & dispute resolution |

*Note: `nexus pipeline --mode tools` executes the deterministic N2 parser lane alone (writing `reports/TOOL-RUN.md`).*

`REPORT.md` is a **template compiled from APPROVED findings**, not an unverified LLM dump.
SKIP = artifact absent. FAIL = artifact present, tool broke.
