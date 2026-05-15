# LangGraph + DFIR-Nexus — Integration Guide

How to drive the 97 DFIR-Nexus MCP tools from a LangGraph pipeline for stateful, auditable, human-in-the-loop DFIR investigations.

---

## 1. Why these two compose well

LangGraph gives you durable, checkpointed agent state and explicit control flow. DFIR-Nexus gives you an opinionated DFIR tool fleet in a single MCP server.

| LangGraph concept       | DFIR-Nexus provides                                   |
|-------------------------|-------------------------------------------------------|
| Tool calls              | 97 MCP tools in one server                            |
| State / persistence     | Case directory: `findings.json`, `timeline.json`, ... |
| Checkpoint log          | `audit/*.jsonl` per backend (SHA-256)                 |
| Human-in-the-loop gate  | DRAFT → APPROVED via `nexus approve` or Portal        |
| Provenance enforcement  | `record_finding` rejects unaudited `audit_id`s        |
| RAG / knowledge         | `forensic_rag_search`, `suggest_tools`                |

LangGraph is the *orchestrator*; DFIR-Nexus is the *substrate*. Graph state stays small (case_id, draft IDs, cursors) and the case directory is the source of truth.

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  LangGraph process (pipeline.py)                                │
│                                                                 │
│   StateGraph                                                    │
│    ├─ register_evidence ──┐                                     │
│    ├─ scope               │  langchain-mcp-adapters →           │
│    ├─ hunt                ├──► MultiServerMCPClient             │
│    ├─ stage_findings      │      └─ dfir-nexus (single server)  │
│    ├─ ▼ interrupt()   ◄───┼─── waits for human approval         │
│    └─ generate_report ────┘                                     │
│                                                                 │
│   SqliteSaver (graph checkpointer)                              │
└──────────────────────────┬──────────────────────────────────────┘
                           │ stdio (Lite) or HTTP (Full)
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│  DFIR-Nexus (single process, 97 tools)                         │
│                                                                 │
│   forensic ── case ── report ── sift ── windows                 │
│   rag ── triage ── opencti ── opensearch                        │
│                                                                 │
│   Case directory (shared state)                                 │
│    ├─ findings.json   (DRAFT/APPROVED)                          │
│    ├─ timeline.json                                             │
│    ├─ evidence.json                                             │
│    ├─ approvals.jsonl (HMAC-signed)                             │
│    └─ audit/*.jsonl                                             │
└─────────────────────────────────────────────────────────────────┘
                           ▲
                           │ password-gated approval
                  ┌────────┴────────┐
                  │  Examiner       │
                  │  (Portal /      │
                  │  nexus approve) │
                  └─────────────────┘
```

---

## 3. Quick Start

### Prerequisites

```bash
cd langgraph
pip install -r requirements.txt
```

You also need DFIR-Nexus installed and available on your PATH:
```bash
pip install -e ..[all]
```

### Run — Stdio Mode (Lite, simplest)

```bash
# Set your model (default: claude-sonnet-4)
export NEXUS_MODEL="claude-opus-4-7"

# Run fresh investigation against /evidence/
python pipeline.py --case /path/to/evidence
```

The graph runs nodes 1-4, then pauses at `await_approval`.

### Approve findings (separate terminal)

```bash
# Review what was staged
nexus review --findings

# Approve interactively
nexus approve
```

### Resume the graph

```bash
python pipeline.py --resume
```

The graph resumes at `generate_report`, produces the report, and ends.

### Run — HTTP Mode (Full)

```bash
# Start DFIR-Nexus in HTTP mode
nexus serve --http --port 4508

# In another terminal:
export NEXUS_GATEWAY_URL="http://localhost:4508/mcp"
export NEXUS_BEARER_TOKEN="..."
python pipeline.py --case /path/to/evidence
```

---

## 4. Graph Node Reference

| Node | Type | MCP tools used | What it does |
|------|------|---------------|--------------|
| `register_evidence` | Deterministic | `case_init`, `evidence_register` | Creates case, registers evidence, establishes chain of custody |
| `scope` | Deterministic | `idx_case_summary`, `suggest_tools`, `list_available_tools` | Surveys evidence, identifies hosts and artifact types |
| `hunt` | Agent (LLM-driven) | `idx_search`, `idx_aggregate`, `idx_timeline`, `forensic_rag_search`, `run_command` | Analyzes evidence — agent picks sub-tools |
| `stage_findings` | Deterministic | `record_finding`, `record_timeline_event` | Stages findings and timeline as DRAFT |
| `await_approval` | **interrupt()** | None | Pauses graph. Human reviews via Portal or `nexus approve` |
| `generate_report` | Deterministic | `generate_report`, `save_report` | Generates IR report from approved findings |

---

## 5. State Design

Minimal state — the case directory holds the real data:

```python
class InvestigationState(TypedDict):
    case_id: str
    evidence_path: str
    evidence_audit_ids: Annotated[list[str], add]
    hosts: list[str]
    draft_finding_ids: Annotated[list[str], add]
    draft_timeline_ids: Annotated[list[str], add]
    approved_finding_ids: list[str]
    rejected_finding_ids: list[str]
    report_path: str | None
    step_log: Annotated[list[str], add]
    error: str | None
```

If it lives in `findings.json`, it does NOT live in graph state. Store IDs only.

---

## 6. Human-in-the-Loop

The `await_approval` node uses LangGraph's `interrupt()` to pause the graph. The examiner reviews DRAFT findings out-of-band:

```bash
# Via browser (requires HTTP mode)
nexus serve --http  # then open http://localhost:4508/portal/

# Via CLI
nexus approve
```

When findings are approved, resume the graph:

```bash
python pipeline.py --resume
```

The resume payload carries approved IDs, but the `generate_report` node only includes findings whose status is actually `APPROVED` in `findings.json`. The resume payload is just an unblocker — trust is in the case directory.

---

## 7. Model Selection

Set `NEXUS_MODEL` env var:

```bash
# Claude (default)
export NEXUS_MODEL="claude-sonnet-4-20250514"

# OpenAI
export NEXUS_MODEL="openai/gpt-4o"

# Local via Ollama
export NEXUS_MODEL="ollama/qwen2.5:32b-instruct"
```

Because DFIR-Nexus handles the heavy lifting (RAG search, baseline validation, evidence parsing), the LLM's job shrinks to **pick the next tool and summarize results**. A 13B–32B local model is usually enough.

**Do not route real case data to a hosted model** unless your provider contract permits it. Run local for evidence; reserve hosted models for draft narrative writing on already-redacted output.

---

## 8. Provenance Guarantees

When LangGraph calls an MCP tool, DFIR-Nexus generates the `audit_id` and writes the JSONL audit record before returning. Graph state only needs to carry IDs forward. When `record_finding` validates artifacts, it checks that each `audit_id` exists in the audit log.

**LangGraph cannot weaken DFIR-Nexus's evidence guarantees.** The structural enforcement lives below it in the MCP server.

---

## 9. Trade-offs: LangGraph vs. Claude Code

| Aspect | Claude Code + DFIR-Nexus | LangGraph + DFIR-Nexus |
|--------|--------------------------|------------------------|
| Setup effort | `pip install dfir-nexus` | Write/run a graph |
| Determinism | LLM drives turn-by-turn | Explicit nodes, explicit edges |
| Restartability | Session is the unit | Checkpointed graph, resumable |
| Multi-case batch | Manual | Trivial (one thread per case) |
| Model choice | Claude only | Anything LangChain supports |
| Forensic controls | Same (in MCP server) | Same (in MCP server) |
| Debuggability | Read the chat | Inspect graph state per step |

Pick LangGraph when you want **repeatable investigations** (triage SOPs, scheduled hunts, regression tests) or **non-Claude models**. Stick with Claude Code for exploratory analyst-driven work.

You can also run both: LangGraph for the first-pass (ingest, enrich, surface anomalies as DRAFT), then hand off to an examiner in Claude Code or the Portal for the analyst-driven phase.

---

## 10. Files

| File | Purpose |
|------|---------|
| `pipeline.py` | Runnable 6-node StateGraph |
| `requirements.txt` | Python dependencies |
| `Makefile` | Build/run targets (venv, install, run-lite, run-full, resume) |
| `LANGGRAPH_INTEGRATION.md` | This file |
