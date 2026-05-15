# DFIR-Nexus — Examiner Workflow Guide

All-in-one DFIR investigation platform. 97 MCP tools, 19 CLI commands,
one install, one server. **Beta — see [FAQ](FAQ.md#is-this-production-ready)
on maturity and verification expectations.**

> **Related:** [SETUP.md](SETUP.md) — comprehensive setup guide ·
> [CLI.md](CLI.md) — full command reference ·
> [ARCHITECTURE.md](ARCHITECTURE.md) — provenance + security model ·
> [FAQ.md](FAQ.md) · [COMPARISON.md](COMPARISON.md) — vs. upstream

This guide is the **examiner walkthrough**: install, first case, the
provenance chain, deployment shapes, and the troubleshooting table.
For the full CLI surface look in [CLI.md](CLI.md).

---

## 1. Installation

> **Full setup guide → [SETUP.md](SETUP.md).** This section is the
> quick-reference; the setup guide has per-OS prerequisites, three
> install paths, identity/password configuration, multi-machine wiring,
> LLM client wiring for every client type, the Claude Code skill bundle,
> a verification checklist, and a flow matrix.

### Quick start (one command)

```bash
# Linux (SIFT, Ubuntu, REMnux)
./setup-linux.sh

# macOS
./setup-macos.sh

# Windows (PowerShell 7+)
.\setup-windows.ps1
```

Each script: verifies Python 3.12+, creates `.venv/`, runs
`pip install -e .[all]`, prompts for examiner + approval password,
and runs `nexus init`.

### Quick install (pip only)

```bash
pip install dfir-nexus[all]
nexus config --examiner "your-name"
nexus config --setup-password
nexus init
```

### Prerequisites

- Python 3.12+
- 4 GB RAM (stdio mode) or 8 GB RAM (HTTP mode)

---

## 2. Quick Start (5 Minutes)

### Step 1: Start the server

```bash
# Stdio mode — your LLM client spawns nexus automatically
nexus serve
```

Or for HTTP mode (multiple clients + web dashboard):
```bash
nexus serve --http --port 4508
```

### Step 2: Connect your LLM client

For Claude Code, Cursor, or Cline: see the
[5-minute quickstart](../README.md#5-minute-quickstart) in the project
README for the exact `.mcp.json` snippet. Or run the wizard:

```bash
nexus setup client          # Interactive wizard
nexus setup client --yes    # Auto with defaults
```

### Step 3: Run your first investigation

From your LLM client. The `audit_id` for `record_finding` is the value
returned by the tool call that produced the evidence — capture it from
step 4 and pass it into step 5:

```text
1. case_init("My First Investigation")
2. evidence_register(path="/evidence/", description="Triage collection")
3. list_available_tools()              # SIFT/Linux tools
4. run_command("fls -f ntfs /evidence/image.dd")
   → returns {"audit_id": "sift_exam-20260514-001", ...}
5. record_finding(
       title="Suspicious file detected",
       observation="MFT shows EVIL.EXE in AppData",
       interpretation="EVIL.EXE launching from user-writable AppData is consistent with initial access",
       confidence="MEDIUM",
       confidence_justification="MFT $STANDARD_INFORMATION + $FILE_NAME timestamps corroborate execution",
       event_timestamp="2026-01-15T14:32:00Z",
       artifacts=[{"audit_id": "sift_exam-20260514-001"}])  # from step 4
6. record_timeline_event(
       timestamp="2026-01-15T14:32:00Z",
       description="EVIL.EXE executed",
       event_type="execution")
```

If you skip step 4 and invent an `audit_id`, step 5 returns `REJECTED`
with `missing_audit_ids`. That's the provenance check working — see
[ARCHITECTURE.md](ARCHITECTURE.md) for why.

### Step 4: Approve findings (human only — terminal)

```bash
nexus approve                           # Password required — interactive review
nexus approve F-001 F-002 --note "verified"
nexus report --full --save report.json
```

---

## 3. Deployment Options

### Solo analyst (stdio — simplest)

```bash
nexus serve
```
LLM client connects via stdio. No ports, no auth, no network. Works offline.

### Multi-client (HTTP)

```bash
nexus serve --http --port 4508 --host 0.0.0.0
```
Connect multiple LLM clients. Web dashboard at `http://localhost:4508/portal`.

### Multi-machine (SIFT + Windows)

Run DFIR-Nexus on each machine — platform-gated registration ensures only
matching tools appear:

```bash
# On SIFT (Linux):
nexus serve --http --port 4508
# Registers: sift tools, case, forensic, report, rag, triage, opencti

# On Windows:
nexus serve --http --port 4508
# Registers: windows tools, case, forensic, report, rag, triage, opencti

# From the LLM client:
nexus setup client --sift 10.0.0.2:4508 --windows 10.0.0.5:4508
# Generates .mcp.json with both servers — LLM routes tools to the right machine
```

### With OpenSearch (scale)

For large volumes of evidence:

```bash
docker run -d -p 9200:9200 opensearchproject/opensearch:latest
export OPENSEARCH_HOST=127.0.0.1
nexus serve --http

# From LLM client:
idx_ingest(case_id="CASE-001", data_dir="/evidence/")
idx_search('event_id:4688')
idx_timeline(start="2026-01-01", end="2026-01-31", interval="1h")
```

---

## 4. Platform-Specific Tools

### On Linux (SIFT)

The `sift` module provides security-gated execution of forensic tools:

```
run_command("fls -f ntfs /evidence/image.dd")
run_command("bulk_extractor -o /out /evidence/image.dd")
run_command("strings /evidence/memory.dmp | grep -i password")
```

### On Windows

The `windows` module provides catalog-gated access to 31 forensic tools:

| Category | Tools |
|----------|-------|
| Zimmerman (14) | MFTECmd, PECmd, EvtxECmd, AmcacheParser, JLECmd, LECmd, RBCmd, RECmd, SBECmd, SQLECmd, SrumECmd, WxTCmd, bstrings, AppCompatCacheParser |
| Sysinternals (5) | autorunsc, sigcheck, strings64, handle64, procdump64 |
| Memory (4) | winpmem, dumpit, moneta64, hollows_hunter |
| Timeline (3) | Hayabusa, chainsaw, mactime.pl |
| Analysis (3) | capa, yara64, densityscout |
| Collection (1) | KAPE |
| Scripts (1) | Get-InjectedThreadEx.ps1 |

```
run_windows_command("MFTECmd -f C:\Evidence\$MFT --csv C:\Extractions")
list_kape_targets(list_type="targets")
batch_scan("MFTECmd", "C:\Evidence", filter_pattern="*.MFT")
```

---

## 5. CLI Reference

The complete CLI surface lives in **[CLI.md](CLI.md)** — single source
of truth, 19 top-level commands grouped by purpose, with the full
environment-variables table. This guide focuses on examiner workflow;
that doc is the lookup reference.

---

## 6. Tool Module Summary

For the module-by-module tool breakdown see the
[What's inside](../README.md#whats-inside) table in the project README.
The numbers (97 tools across 9 modules; platform-gating for `sift` and
`windows`) and the per-module purpose live in one place there.

---

## 7. Provenance Chain

Every investigation action is tracked:

```
1. run_command("fls image.dd")
   → returns {"audit_id": "sift_exam-20260514-001"}

2. record_finding(
       title="Suspicious file",
       artifacts=[{"audit_id": "sift_exam-20260514-001"}])
   → validates audit_id exists in audit/*.jsonl
   → classifies provenance (MCP/HOOK/SHELL/NONE)
   → grades provenance (FULL/PARTIAL)
   → auto-extracts IOCs from text
   → STAGED (or REJECTED if no audit trail)

3. nexus approve F-001
   → prompts for password (getpass — no echo)
   → PBKDF2-SHA256 verify
   → writes HMAC-SHA256 verification ledger entry
   → DRAFT → APPROVED
```

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `nexus: command not found` | Package not installed | `pip install dfir-nexus` |
| Tools not showing in client | Wrong MCP transport | Use stdio or check HTTP URL |
| Findings rejected | Missing `audit_id` in artifacts | Run a tool first, use returned audit_id |
| `VALIDATION_FAILED` on record_finding | Missing `confidence_justification` (FD-005) or `interpretation` | Provide both; `confidence_justification` is required, not optional |
| `REJECTED` with `missing_audit_ids` | Artifact references an audit_id not in the active case audit log | Make sure the tool that produced the audit_id ran while the same case was active |
| `sift tools` not available | Not running on Linux | Check `sys.platform` — SIFT tools are Linux-only |
| `windows tools` not available | Not running on Windows | Check `sys.platform` — Windows tools are Windows-only |
| RAG search fails | No index downloaded | Call `forensic_rag_download()` first |
| Triage returns UNKNOWN | No database installed | Call `triage_download()` first |
| Audit trail empty | No active case | Create case with `case_init()` first |
| Portal not loading | HTTP mode not enabled | Use `nexus serve --http` |
| Password not accepted | Locked out | Wait 15 minutes for lockout to expire |
| Claude Code hooks not firing | Hook scripts missing executable bit, or `$CLAUDE_PROJECT_DIR` not set | `chmod +x ~/.claude/skills/dfir-nexus/hooks/*.sh`; verify Claude Code resolved `$CLAUDE_PROJECT_DIR` to your install dir |
| Audit log empty after Bash invocations | Skill bundle installed but no active case | `nexus case init <name>` or `nexus case activate <id>` first; the `forensic-audit.sh` hook needs an active case to write to |
| `case_status` says `remnux: False` after wiring REMnux MCP | Server name doesn't contain "remnux" | DFIR-Nexus detects by name substring in your `.mcp.json` / `~/.claude.json`; name your MCP server `remnux-mcp` or `dfir-nexus-remnux` |
| `transparency_verify()` returns tampered index | Hash chain broken — investigate | Compare `~/.nexus/cases/<id>/transparency.jsonl` against the case audit log; restore from backup; do not ship the case report until reconciled |
| `nexus init` says baselines missing | Triage / RAG DBs not downloaded yet | From your LLM client: `triage_download()` and `forensic_rag_download()`; both pull from GitHub releases |
| `nexus export --encrypt` errors with `cryptography missing` | `cryptography` package not installed | `pip install dfir-nexus[encrypt]` (or `[all]`) |
