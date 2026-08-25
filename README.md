# DFIR-Nexus

<p align="center">
  <img src="assets/dfir-nexus-logo.svg" alt="DFIR-Nexus Logo" width="620">
</p>

<p align="center">
  <strong>One audit chain. One process. AI-assisted. Examiner-approved.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/Tests-609%20Passed-success.svg" alt="Tests: 609 Passed">
  <img src="https://img.shields.io/badge/MCP%20Tools-103%20Registered-blue.svg" alt="MCP Tools: 103 Registered">
  <img src="https://img.shields.io/badge/Status-v2%20in%20development-yellow.svg" alt="Status: v2 in development">
</p>

Standalone release of the examiner-led DFIR capability developed within the [CADRE](https://github.com/Ganron007/CADRE) platform programme — consumes lab attack telemetry and host/network evidence for human-approved incident response.

> [!WARNING]
> **Version 2 is in active development.** The product is being re-architected for operational reliability. **Live IR over SSH/WinRM** (`nexus collect`, default `--profile disk`) is a first-class product path: host-native collectors on current Windows 11 and modern Linux, no model in the collect path. Investigation then proceeds in an **examiner-led** loop: parse and query in code, optional language-model interpretation of *retrieved hits*, and cryptographic human approval before anything becomes official. Fully agentic collection and unconstrained LLM tool-selection remain **later** capabilities, not the current ship path.
>
> This repository is a **development snapshot**. Commands, APIs, and documentation below may change before a v2 release. Do not treat this tree as a stable public interface or a finished product.

> [!IMPORTANT]
> **Chain of Custody & Audit Integrity.** DFIR-Nexus enforces strict cryptographic data provenance. Every command executed through SIFT, Zimmerman, or Velociraptor is logged into a tamper-evident **HMAC-SHA256 audit ledger** in real time. To maintain forensic compliance, all draft findings must be verified and cryptographically signed using examiner passwords hashed with PBKDF2-HMAC (600,000 iterations). Automated AI agents are restricted to drafting findings and cannot authorize or alter forensic reports.

---

## Why DFIR-Nexus Exists

Digital Forensics and Incident Response (DFIR) routinely relies on a highly fragmented ecosystem of single-purpose command-line tools (such as Hayabusa, MFTECmd, chainsaw, Volatility, KAPE, and Velociraptor). Manually correlating tool outputs during high-pressure incidents introduces cognitive strain, compromises chain-of-custody, and limits auditability.

**DFIR-Nexus** solves this by providing a unified, secure, and cryptographically verified forensic integration layer. **Live IR collection is a portable CLI** (`nexus collect`) — no model, no parsers, freeze-gated. After the pack is **registered**, the same case is processed (parsers), queried in code, optionally interpreted by an LLM from *retrieved hits only*, and approved by an examiner. Native tools are also exposed as **103 Model Context Protocol (MCP) endpoints on Windows and 100 on Linux** for CLI, Portal, and (later) agent-driven analysis — never for unsigned reports.

---

## Architecture & Data Flow

Product flow (collect → register → N1–N8 → ingest → N4–N8 again → detection):
**[Docs/NEXUS-MODE.md](Docs/NEXUS-MODE.md)** · spine diagram also in **[Docs/ARCHITECTURE.md](Docs/ARCHITECTURE.md)**.

DFIR-Nexus operates as a single, platform-aware FastMCP process with strict cryptographic trust boundaries, evidence provenance rules (FD-001..007), and a mandatory human authorization gate:

<p align="center">
  <a href="assets/dfir-nexus-architecture.svg">
    <img src="assets/dfir-nexus-architecture.png" alt="DFIR-Nexus Architecture &amp; Data Flow: Clients → FastMCP Engine → Discipline &amp; Provenance → HITL Gate → Storage &amp; Exporters" width="1000">
  </a>
</p>

**Trust model (offline-first, loopback-only):**
1. **Collect (CLI)** — Live IR pack. No LLM, no parsers, freeze-gated. Stays portable; not a Portal harvest.
2. **Register** — `nexus case init` + `nexus evidence register`. Custody. Outside N1–N8.
3. **MCP / Portal** — Investigation desk for N1–N8, ingest, and detection. Intent-level tools; no arbitrary shell.
4. **Case ledger** — SQLite case state dual-written with an **HMAC-SHA256** audit chain.
5. **Human gate** — Findings stay **DRAFT** until examiner approval (PBKDF2-HMAC, 3-strike lockout).
6. **Reports** — Approved cases export as Markdown, HTML, STIX 2.0/2.1, DOCX, and ZIP.

---

## Core Capabilities

| Dimension | Feature Set |
| :--- | :--- |
| **Case & Evidence** | SQLite-backed cases containing findings, evidence records, timeline events, and case TODOs. SHA-256 hashing at registration provides verifiable integrity at any time. |
| **Tamper Evidence** | Cryptographically chained HMAC-SHA256 audit ledger. Any attempt to modify command logs or findings breaks the chain verification. |
| **Hardened Gate** | PBKDF2-HMAC password validation with 600,000 iterations. Features a **3-strike lockout** of 15 minutes to block automated brute-forcing. |
| **Threat Intel** | Integrated lookups across 10 TI providers (ThreatFox, MalwareBazaar, URLhaus, Yaraify, MISP, OTX, Shodan, VT, AbuseIPDB, and CrowdStrike). |
| **Semantic RAG** | Search over **22,000+ IR records** (SANS posters, Sigma, LOLBAS, GTFOBins, and KAPE targets) using a local ChromaDB collection. Bring your own index, download the prebuilt release, or rebuild from your own sources; embedding model is operator-configurable (`NEXUS_RAG_MODEL`). |
| **Live IR pack (Stage 0)** | Authenticated **SSH / WinRM / local** collection — **CLI only** (portable, no UI). Ship spine (`--profile disk`): Windows **KAPE** `!SANS_Triage`/`!EZParser` + Sysinternals + PersistenceSniper + wevtutil + Velociraptor `IRTriage`; Linux **POSIX volatile + journalctl + UAC `ir_triage` + Velociraptor `LinuxIRTriage`**. Extra *collectors* (Kansa, DFIR-ORC, WinPmem/AVML, UAC `full`) stay on `--profile full` and **skip with a reason** if missing or broken. **Hayabusa / Suzaku / Chainsaw are N2 parsers**, not Stage 0. Live Velociraptor needs examiner `.env` MCP URL + key — [SETUP.md §2.6](Docs/SETUP.md#26-live-velociraptor-hunts-every-examiner-host). |
| **Pipeline Agents** | Two analysis loops: an offline 6-agent heuristic graph (alert, cloud, network, endpoint, synthesis, timeline) and an **LLM-driven pipeline** (`nexus pipeline`) with four modes — **tools** (mandatory parsers only; no RAG, no LLM; `TOOL-RUN.md`), **coverage** (same lane, then LLM interprets), **design** (lane first, then ReAct may add corroboration), **interpret** (reuse a finished tool-run case; no re-parse). Coverage, design, and interpret stage DRAFT findings and pause at the human-approval gate. The LLM does not pick or skip parsers for artifacts that are present. |

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

# N2 parsers, then investigation (CLI, Portal, or MCP)
nexus pipeline --mode tools --case <pack>
nexus pipeline --mode interpret --from-case INC-...
nexus portal                          # examiner UI for register / query / approve / report
```

Existing dumps: `nexus collect import` then register. Mental model: [Docs/NEXUS-MODE.md](Docs/NEXUS-MODE.md).

### 3. Running the Server & Dashboard
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

DFIR-Nexus includes a rigorous testing suite covering unit, script, functional wiring, and blocker regression tests (**609 total checks**).

```bash
# 1. Run the pytest suite (290 tests, including blocker regressions)
pytest

# 2. Run Individual Script-Based Tests (202 tests)
python tests/test_knowledge.py
python tests/test_detection.py
python tests/test_ti.py
python tests/test_ingest.py
python tests/test_integration.py
python tests/test_portal.py
python tests/test_hunt_parser.py

# 3. Run the E2E Functional Audit (115 checks)
python tests/functional_audit.py
```

---

## Knowledge-base data — attribution & roadmap

The prebuilt **RAG index** (~22,000 IR records) and **Windows triage
baselines** currently offered through `forensic_rag_download()` /
`triage_download()` are built and published by
[Applied Incident Response](https://github.com/AppliedIR/sift-mcp) under the
**MIT License** (Copyright (c) 2026 AppliedIncidentResponse.com). Full credit
to the AppliedIR team for that corpus — DFIR-Nexus fetches those release
assets as-is and does not redistribute them.

**In progress:** we are building our own large-scale RAG and triage corpus
(expanded DFIR knowledge sources, lab-derived Windows baselines, and
detection-oriented records). As it lands, `forensic_rag_rebuild()` and the
`NEXUS_RAG_RELEASE_REPO` / `NEXUS_TRIAGE_RELEASE_REPO` overrides let you
point DFIR-Nexus at our releases — or at your own.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

> Copyright (c) 2026 DFIR-Nexus contributors.
