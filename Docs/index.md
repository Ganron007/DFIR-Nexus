# DFIR-Nexus Documentation

> Unified DFIR investigation platform — collect on the CLI, investigate with HITL, examiner-approved.

---

## Reading Guide

| Document | What it covers |
|----------|---------------|
| **[NEXUS-MODE.md](NEXUS-MODE.md)** | **Start here for the loop.** Stage 0 collect (CLI) → Register → N1–N8. Parsers are N2, not collect. |
| **[guide.md](guide.md)** | Step-by-step DFIR workflow — case, tools, findings, approve, report. |
| **[SETUP.md](SETUP.md)** | Installation — per-OS prerequisites, setup scripts, venv/pip/docker, client wiring, baselines. |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Product spine, trust boundaries, module layout, data flow. |
| **[CLI.md](CLI.md)** | Full CLI command reference — all `nexus` subcommands. |
| **[FAQ.md](FAQ.md)** | LLM requirements, data safety, collect vs parse, troubleshooting. |
| **[../CHANGELOG.md](../CHANGELOG.md)** | Release history. |

---

## Quick Start

```bash
# Install
.\setup-windows.ps1                  # Windows
./setup-linux.sh                     # Linux
pip install dfir-nexus[all]          # Manual

# Configure
nexus config --examiner "your-name"
nexus config --setup-password

# Live IR (CLI only — portable, freeze first)
nexus collect run --os windows --host <ip> --user <acct> --identity ~/.ssh/id

# Register (custody; not part of N1–N8)
nexus case init "IR host"
nexus evidence register <pack>

# Parse (N2), then Portal / interpret
nexus pipeline --mode tools --case <pack>
nexus serve --http
nexus portal
```

Existing dumps: `nexus collect import` then register. Full loop: [NEXUS-MODE.md](NEXUS-MODE.md).

---

## Key Concepts

| Concept | What it means |
|---------|--------------|
| **Case** | Container for one investigation — holds findings, evidence, timeline, IOCs, audit entries |
| **Finding** | A structured observation (title, severity, MITRE mapping, linked evidence). Always DRAFT until approved. |
| **HITL** | Human-In-The-Loop — only a human can approve findings (password-gated). LLM cannot approve. |
| **Audit Chain** | Every action is HMAC-chained. Tampering breaks the chain — detected on `verify`. |
| **Provenance** | Every finding must reference real audit_ids from tool runs. Fabricated IDs → rejected. |
| **Collect** | Live IR pack (`nexus collect`). CLI / SSH / WinRM. No LLM, no parsers. |
| **Register** | `nexus case init` + `nexus evidence register`. Custody. Not part of N1–N8. |
| **MCP Tools** | 103 Windows / 100 Linux forensic tools exposed through MCP (workstation + agents). |
| **RAG** | Semantic search over 22K forensic knowledge records (downloaded on first use, ~600 MB). |
| **Triage** | Windows baseline validation — legitimate vs suspicious vs LOLBin. |
| **MITRE** | Full ATT&CK v15 support — technique matching, threat actor profiles, Navigator layers, RBA scoring. |
