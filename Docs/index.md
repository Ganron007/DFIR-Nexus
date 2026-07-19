# DFIR-Nexus Documentation

> Unified DFIR investigation platform — AI-assisted, MCP-powered, human-in-the-loop.

---

## Reading Guide

| Document | What it covers |
|----------|---------------|
| **[guide.md](guide.md)** | **Start here.** Complete step-by-step DFIR workflow — what DFIR-Nexus does, how to create a case, run tools, record findings, approve, and generate reports. |
| **[SETUP.md](SETUP.md)** | Full installation guide — per-OS prerequisites, setup scripts, venv/pip/docker, client wiring, baselines download. |
| **[ARCHITECTURE.md](ARCHITECTURE.md)** | Module structure, security boundaries, trust model, tool inventory, data flow. |
| **[CLI.md](CLI.md)** | Full CLI command reference — all `nexus` subcommands. |
| **[FAQ.md](FAQ.md)** | Common questions — LLM requirements, data safety, troubleshooting, supported tools/formats. |
| **[CHANGELOG.md](CHANGELOG.md)** | Release history and changes. |

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

# Create first case
nexus case init "First Investigation"

# Register evidence
nexus evidence register /path/to/memory.dump

# Start the server (for LLM client)
nexus serve --http

# Or open the Examiner Portal
nexus portal
```

---

## Key Concepts

| Concept | What it means |
|---------|--------------|
| **Case** | Container for one investigation — holds findings, evidence, timeline, IOCs, audit entries |
| **Finding** | A structured observation (title, severity, MITRE mapping, linked evidence). Always DRAFT until approved. |
| **HITL** | Human-In-The-Loop — only a human can approve findings (password-gated). LLM cannot approve. |
| **Audit Chain** | Every action is HMAC-chained. Tampering breaks the chain — detected on `verify`. |
| **Provenance** | Every finding must reference real audit_ids from tool runs. Fabricated IDs → rejected. |
| **MCP Tools** | 97 forensic tools exposed as MCP (Model Context Protocol) tools that LLM clients can call. |
| **RAG** | Semantic search over 22K forensic knowledge records (downloaded on first use, ~600 MB). |
| **Triage** | Windows baseline validation — legitimate vs suspicious vs LOLBin. |
| **MITRE** | Full ATT&CK v15 support — technique matching, threat actor profiles, Navigator layers, RBA scoring. |
