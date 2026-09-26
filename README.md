# DFIR-Nexus

<p align="center">
  <img src="assets/dfir-nexus-logo.svg" alt="DFIR-Nexus Logo" width="620">
</p>

<p align="center">
  <strong>One audit chain. One process. AI-assisted. Examiner-approved.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Tests-1345%20passed-success.svg" alt="Tests: 1345 passed / 3 skipped">
  <img src="https://img.shields.io/badge/MCP%20Tools-135%20Win%20%7C%20132%20Linux-blue.svg" alt="MCP Tools: 135 Win | 132 Linux">
  <img src="https://img.shields.io/badge/Status-v2%20in%20development-yellow.svg" alt="Status: v2 in development">
</p>

Standalone release of the examiner-led DFIR capability developed within the [CADRE](https://github.com/Ganron007/CADRE) platform programme — consumes lab attack telemetry and host/network evidence for human-approved incident response.

> [!WARNING]
> **Version 2 is in active development.** DFIR-Nexus is a working product — live IR collection, custody-registered evidence, deterministic parsing, needle queries, and the examiner cockpit all run end-to-end today. But v2 is being rebuilt in the open: commands, APIs, and internal schemas can change — and anything can break — between commits. Do not deploy this branch in production environments.

> [!IMPORTANT]
> **Chain of Custody & Audit Integrity**
>
> - Every command run through SIFT, Zimmerman or Velociraptor is written to a tamper-evident **HMAC-SHA256 audit ledger** in real time.
> - Findings stay **DRAFT** until an examiner signs them with a password hashed using **PBKDF2-HMAC (600,000 iterations)**.
> - Automated agents may **draft** findings. They can never approve, alter or delete them.
> - A 3-strike, 15-minute lockout blocks brute-force approval attempts, and the chain is verifiable from the Transparency page.

**What's inside**

| Section | What you get |
| :--- | :--- |
| [Why DFIR-Nexus Exists](#why-dfir-nexus-exists) | The fragmentation problem and what this layer changes |
| [Architecture & Investigation Lifecycle](#architecture--investigation-lifecycle) | Collect → register → N1–N8 → ingest → report, plus the trust model |
| [Examiner Cockpit (Web UI)](#examiner-cockpit-web-ui) | Every portal page with its route |
| [Storage & Search Architecture](#storage--search-architecture) | SQLite as the source of truth vs the Elasticsearch index |
| [Core Capabilities](#core-capabilities) | Custody, audit, TI, RAG, Stage 0 collection, **the three modes** |
| [Quickstart](#quickstart) | Install → configure → collect → register → query → approve → report |
| [Project Structure & Documentation](#project-structure--documentation) | Which doc to open for what |
| [Verification & Testing](#verification--testing) | How the build is verified |

---

## Why DFIR-Nexus Exists

Digital Forensics and Incident Response (DFIR) routinely relies on a highly fragmented ecosystem of single-purpose command-line tools (such as Hayabusa, MFTECmd, chainsaw, Volatility, KAPE, and Velociraptor). Manually correlating tool outputs during high-pressure incidents introduces cognitive strain, compromises chain-of-custody, and limits auditability.

**DFIR-Nexus** solves this by providing a unified, secure, and cryptographically verified forensic integration layer:
- **Live IR Collection is a portable CLI** (`nexus collect`) — host-native, zero-model, no parsers on target, freeze-gated.
- **Evidence Registration** (`nexus case init` + `nexus evidence register`) establishes cryptographic chain-of-custody with SHA-256 evidence hashing before analysis starts.
- **Examiner Cockpit & CLI** provide an integrated workbench for the deterministic **N1–N8 Investigation Spine**: parsers extract structured CSVs, code searches for attack needles, an LLM scribe interprets retrieved hits, and human examiners cryptographically sign off before report compilation.

---

## Architecture & Investigation Lifecycle

Product flow (collect → register → N1–N8 → ingest → N4–N8 again → detection):  
See **[Docs/NEXUS-MODE.md](Docs/NEXUS-MODE.md)** for the full operator loop, and **[Docs/ARCHITECTURE.md](Docs/ARCHITECTURE.md)** for topology and tool index.

<p align="center">
  <a href="assets/dfir-nexus-architecture.svg">
    <img src="assets/dfir-nexus-architecture.svg" alt="DFIR-Nexus v2 Architecture &amp; Lifecycle: Stage 0 Collect → Register Custody → Examiner Cockpit &amp; N1-N8 Spine → HITL Gate → Storage &amp; Exporters" width="1000">
  </a>
</p>

**Trust model (offline-first, loopback-only):**
1. **Collect (CLI)** — Live IR pack on disk. No LLM, no parsers on target, freeze-gated. Stays portable; not a Portal harvest.
2. **Register** — `nexus case init` + `nexus evidence register`. Custody gate before analysis. Outside N1–N8.
3. **Examiner Cockpit / MCP** — Investigation desk for N1–N8, ingest, and detection. Intent-level tools; no arbitrary shell.
4. **Case ledger** — SQLite case state dual-written with an **HMAC-SHA256** audit chain.
5. **Human gate** — Findings stay **DRAFT** until examiner approval (PBKDF2-HMAC, 3-strike lockout).
6. **Reports** — Approved cases export as Markdown, HTML, STIX 2.0/2.1, DOCX, and ZIP.

---

## Examiner Cockpit (Web UI)

DFIR-Nexus features a web-based **Examiner Portal** (`nexus portal` on `http://127.0.0.1:4508`) with three surfaces:

| Surface | Route | Role |
| :--- | :--- | :--- |
| **Landing page** | `/` | Product identity, inline health chips, entry points |
| **Case Dashboard** | `/dashboard` | Totals (cases, evidence, findings, processed), cases table, health bar |
| **React Cockpit** | `/portal/app/*` | Full investigation workspace (N1–N8 workflow) |

**React Cockpit pages:**

| Desk | Route | Capability |
| :--- | :--- | :--- |
| **Case Setup** | `/portal/app/case-setup` | Create a case and choose the investigation mode |
| **Steer Chat** | `/portal/app/steer` | The Mode 1 LLM surface — SSE chat, suggestions, iterative loop, propose-DRAFT. Mode 2/3 cases get an Agent Run pointer here |
| **Briefing** | `/portal/app/briefing` | Question, run options, and the LLM run panel (Mode 1) |
| **Explore** | `/portal/app/explore` | Faceted DSL search, type-aware hit columns, host facets, histogram, bookmarking |
| **Timeline** | `/portal/app/timeline` | Per-family lanes, type-aware event panels, brush-zoom |
| **Agent Run** | `/portal/app/agent-run` | Mode-aware: multi-role lanes (plan → run → verify → stage) and the multi-agent Investigation Board |
| **Workbench** | `/portal/app/workbench` | Bookmark-to-DRAFT promotion |
| **Evidence** | `/portal/app/evidence` | Evidence registry, filesystem picker, parser-lane ledger |
| **Findings** | `/portal/app/findings` | Finding cards with status/confidence badges |
| **Approve** | `/portal/app/approve` | HMAC approval of DRAFT findings |
| **Report** | `/portal/app/report` | Report generation from APPROVED findings |
| **Entities** | `/portal/app/entities` | Entity pivots across families |
| **Transparency** | `/portal/app/transparency` | Audit-chain verification |
| **IOCs** | `/portal/app/iocs` | IOC list extracted from findings |
| **TODOs** | `/portal/app/todos` | Investigation TODO tracking |
| **Overview** | `/portal/app/` | In-cockpit dashboard with health strip |

---

## Storage & Search Architecture

DFIR-Nexus uses a dual-layer storage model separating immutable forensic state from high-scale log searching:

| Layer | Technology | Role & Behavior |
| :--- | :--- | :--- |
| **Forensic State & Ledger** | **SQLite (`cases.db`)** | **Permanent Single Source of Truth (SSoT)**. Stores case metadata, registered evidence SHA-256 hashes, finding states (`DRAFT` vs `APPROVED`), timeline events, investigator TODOs, and the tamper-evident cryptographic verification ledger (`transparency.jsonl`). Always local, zero-dependency, and offline-first. |
| **Case Search Backend** | **Elasticsearch (`nexus-es` / N3 Index)** | **High-Scale Query Acceleration Engine**. Indexes parsed log lines from `extractions/` for N4 needle search. Does *not* store findings or replace SQLite. The Mode 1 lane can produce CSVs with Elasticsearch down (examiner surfaces still work); interpretation and the Modes 2/3 agentic depths require the Elasticsearch digest and stop with an explicit reason when it is not the backend. |

---

## Core Capabilities

### Platform

| Dimension | What it gives you |
| :--- | :--- |
| **Case & evidence** | SQLite-backed cases holding findings, evidence records, timeline events and TODOs. SHA-256 at registration keeps integrity verifiable at any time. |
| **Tamper evidence** | Cryptographically chained HMAC-SHA256 audit ledger — editing a command log or a finding breaks chain verification. |
| **Hardened approval** | PBKDF2-HMAC password validation (600,000 iterations) with a 3-strike, 15-minute lockout. |
| **Threat intel** | Lookups across 10 providers (ThreatFox, MalwareBazaar, URLhaus, Yaraify, MISP, OTX, Shodan, VirusTotal, AbuseIPDB, CrowdStrike). Local-only unless you supply API keys. |
| **Semantic RAG** | 22,000+ IR records (SANS posters, Sigma, LOLBAS, GTFOBins, KAPE targets) in a local ChromaDB collection. Bring your own index, download the prebuilt release, or rebuild it; the embedding model is configurable (`NEXUS_RAG_MODEL`). |

### Stage 0 — live IR pack (CLI only)

- Authenticated **SSH / WinRM / local** collection: portable, no parsers on the target, freeze-gated.
- **Windows spine** (`--profile disk`): KAPE `!SANS_Triage` / `!EZParser` + Sysinternals + PersistenceSniper + wevtutil + Velociraptor `IRTriage`.
- **Linux spine**: POSIX volatile + journalctl + UAC `ir_triage` + Velociraptor `LinuxIRTriage`.
- Extra collectors (Kansa, DFIR-ORC, WinPmem/AVML, UAC `full`) live on `--profile full` and **skip with a reason** when missing or broken.
- **Hayabusa / Suzaku / Chainsaw are N2 parsers**, not Stage 0 collectors.
- Live Velociraptor hunts need the examiner `.env` MCP URL + key — [SETUP.md §2.6](Docs/SETUP.md#26-live-velociraptor-hunts-every-examiner-host).

### The three investigation modes

All three drive the same N1–N8 spine, the same `case_id` and the same HMAC lock. **The mode is fixed when the case is created**, and the server refuses a run started in another mode.

**Mode 1 — LLM** · the merged examiner + LLM surface

- Deterministic tool lane plus the code-based N4 query pack; the full-run scribe.
- Steer chat: the LLM plans N4 queries that push down to the per-case ES index (field filters, ES-native aggregations) and answers with cited rows, per-stage timings and audit IDs.
- Coverage and interpretation — interpretation never runs on a CSV fallback.
- Surfaces: **Briefing** and **Steer Chat**. Sign-off stays manual and cryptographic.

**Mode 2 — Multi-role** · one work order at a time

- A LangGraph supervisor runs scoped **read-only** roles: director → evidence / correlation / pattern workers → verifier / refuter → synthesis.
- KB skill procedures, bounded budgets, follow-up corroboration, and a no-new-evidence convergence stop.
- The examiner owns plan approval, live steering, pause / resume / **stop** and DRAFT staging (`nexus mode2 stage`); agents never stage or approve.
- Surfaces: **Agent Run** (`/portal/app/agent-run`) and `nexus mode2 plan|run|status|steer|pause|resume|stop|findings|stage|export`.

**Mode 3 — Multi-agent** · a concurrent team

- A supervisor — model-chosen seats, deterministic fallback — fans evidence / correlation / pattern seats out in one superstep.
- Every seat publishes **audit-backed claims only** on a shared board; the join opens disputes and can re-dispatch bounded; unresolved disputes stay gaps, never findings.
- Same read-only, audited, DRAFT-only rules.
- Surfaces: **Agent Run — Investigation Board** and `nexus mode3 run|status|board|steer|pause|resume|stop|stage|export`.

**Cockpit pages** (`/portal/app/*`): Case Setup, Overview, Briefing, Explore, Timeline, Steer Chat (Mode 1), Agent Run (Mode 2 lanes / Mode 3 board), Workbench, Findings, Approval, Report, Evidence, Entities, Transparency, IOCs, TODOs. The nav shows only the N5 surface that matches the case's stored mode.

---

## Quickstart

### 1. Installation
Install native dependencies and the Python package:

```powershell
# Windows
.\setup-windows.ps1

# Linux / macOS
./setup-linux.sh

# Manual install with all optional integrations
pip install dfir-nexus[all]
```

### 2. Configuration & operator loop

```bash
nexus config --examiner "Jane Doe"
nexus config --setup-password
nexus doctor                          # binaries + VR live status

# Stage 0 — collect only (CLI; freeze first)
nexus collect run --os windows --host <ip> --user <acct> --identity ~/.ssh/id

# Register (custody; separate from N1–N8)
nexus case init "IR host"
nexus evidence register <pack>

# N2 parsers (deterministic; no LLM)
# NOTE: --case is the EVIDENCE path; --from-case reuses your registered case
# (without --from-case the pipeline auto-creates a new INC-* case)
nexus pipeline --mode tools --from-case <CASE-ID> --case <pack>

# Mode 1 — LLM query desk (examiner + scribe + steer chat)
nexus case ask --question "Was sdelete used to wipe files?"
nexus case select --hits 1,3,5 --title "sdelete wipe on WS01"
nexus case findings --status DRAFT
nexus approve --examiner <id> F-001            # HMAC sign-off
nexus report generate                          # N8 from APPROVED only

# Mode 2 — Multi-role runs / Mode 3 — Multi-agent runs
nexus mode2 plan -q "Trace RDP activity and USB device use"
nexus mode3 run  -q "Trace RDP activity and USB device use"

# Or open the Examiner Cockpit for query / approve / timeline / report
nexus portal
```

Existing dumps: `nexus collect import` then register. Mental model: [Docs/NEXUS-MODE.md](Docs/NEXUS-MODE.md).

### 3. Running the Server & Cockpit
Expose the tools and interface locally:

```bash
# Boot the HTTP MCP server and Dashboard Portal on port 4508
nexus serve --http

# Open the Examiner Portal dashboard in your default browser
nexus portal
```

---

## Project Structure & Documentation

Detailed guidelines are grouped in the `Docs/` directory:

* 🧭 **[Docs/NEXUS-MODE.md](Docs/NEXUS-MODE.md):** Operator loop — collect → register → process → query → interpret → approve → export.
* 📚 **[Docs/guide.md](Docs/guide.md):** Step-by-step DFIR command guide.
* ⚙️ **[Docs/SETUP.md](Docs/SETUP.md):** Advanced installation, environment variables, and tool integration.
* 🔬 **[Docs/ARCHITECTURE.md](Docs/ARCHITECTURE.md):** High-level design, trust boundaries, and tool indexes.
* 💻 **[Docs/CLI.md](Docs/CLI.md):** Typer-based command-line reference.
* ❔ **[Docs/FAQ.md](Docs/FAQ.md):** Common operations and troubleshooting.

---

## Verification & Testing

DFIR-Nexus includes a rigorous testing suite covering unit, script, functional wiring, and blocker regression tests. The last full pytest run (2026-09-26, after the three-mode rename and legacy-artifact cleanup, the Mode 2 Elasticsearch refusal, and the mode-segregated N5 surfaces) recorded **1345 passed / 3 skipped**, plus the script suites and the E2E functional audit.

```bash
# 1. Run the pytest suite (Mode 1/2/3 + audit regression tests)
pytest

# 2. Run the individual script-based test suites
python tests/test_knowledge.py
python tests/test_detection.py
python tests/test_ti.py
python tests/test_ingest.py
python tests/test_integration.py
python tests/test_portal.py
python tests/test_hunt_parser.py

# 3. Run the E2E functional audit
python tests/functional_audit.py
```

---

## Knowledge-base data — attribution & roadmap

- The prebuilt **RAG index** (~22,000 IR records) and **Windows triage baselines** offered through `forensic_rag_download()` / `triage_download()` are built and published by [Applied Incident Response](https://github.com/AppliedIR/sift-mcp) under the **MIT License** (Copyright (c) 2026 AppliedIncidentResponse.com). Full credit to the AppliedIR team — DFIR-Nexus fetches those release assets as-is and does not redistribute them.
- **In progress:** we are building our own large-scale RAG and triage corpus (expanded DFIR knowledge sources, lab-derived Windows baselines, detection-oriented records).
- `forensic_rag_rebuild()` plus the `NEXUS_RAG_RELEASE_REPO` / `NEXUS_TRIAGE_RELEASE_REPO` overrides let you point DFIR-Nexus at our releases — or entirely at your own.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

> Copyright (c) 2026 DFIR-Nexus contributors.
