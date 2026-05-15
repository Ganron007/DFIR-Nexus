# DFIR-Nexus Setup Guide

> **Companion to** [guide.md](guide.md) (examiner workflow) · [CLI.md](CLI.md)
> (command reference) · [ARCHITECTURE.md](ARCHITECTURE.md) (trust model)

This guide walks you from a bare system to a running DFIR-Nexus
investigation. It covers every install path, client wiring option, and
verification step. Most readers can skip to their segment and stop
reading once the server starts.

---

## 0. Which reader are you?

| Reader | Goal | Sections needed |
|--------|------|-----------------|
| **Solo Linux examiner** (SIFT VM, Ubuntu desktop, REMnux) | Local stdio install, one analyst | 1 → 2 → 3 → 5a → 7 → 8 |
| **Solo Windows examiner** (analyst workstation) | Run on Windows, native Zimmerman / KAPE tools | 1 → 2 → 3 → 5a → 7 → 8 |
| **Multi-machine lab** (SIFT + Windows VMs, one LLM client) | One LLM, two `nexus serve --http` instances | 1 → 2 → 3 → 4 → 5b → 7 → 8 |
| **Headless / CI install** | Automated, no interactive prompts | 1 → 2 (`--skip-init --skip-password`) → 8 verification |
| **MCP integrator** (writing another agent) | Just the API surface | 1 → 2 → 5 (skip 7) → API exploration |

If you are a solo Linux or Windows examiner — ~80 % of readers — skip
§4 (multi-machine) and §6 (Claude Code skill). You can be at "first
case" in about 10 minutes.

---

## 1. System prerequisites

| Dependency | Minimum | Linux | macOS | Windows |
|-----------|---------|-------|-------|---------|
| Python | 3.12+ | `apt install python3.12 python3.12-venv` (Debian/Ubuntu); pre-installed on SIFT 2024+ | `brew install python@3.12` | `winget install Python.Python.3.12` or python.org installer (tick **Add to PATH**) |
| `pip` | bundled | bundled with Python | bundled | bundled |
| Git | any | `apt install git` | `xcode-select --install` | `winget install Git.Git` |
| build-essential | — | `apt install build-essential` | n/a (Xcode CLT) | n/a (wheels ship prebuilt) |
| Docker (optional) | any | `apt install docker.io` | Docker Desktop | Docker Desktop |
| PowerShell 7+ (optional) | 7.x | `apt install powershell` | `brew install powershell` | `winget install Microsoft.PowerShell` |

**Linux notes:**

- SIFT Workstation 2024+ ships Python 3.12 pre-installed. Verify with
  `python3 --version`.
- On Ubuntu 22.04 you may need the deadsnakes PPA:
  ```bash
  sudo apt install software-properties-common
  sudo add-apt-repository ppa:deadsnakes/ppa
  sudo apt install python3.12 python3.12-venv
  ```

**Windows notes:**

- The `winget` commands require Windows 10 1809+ with the App Installer
  package. Alternatively, download from python.org.
- The setup script (`setup-windows.ps1`) requires PowerShell 7+. Install
  with `winget install Microsoft.PowerShell` or from GitHub.

**macOS notes:**

- On Apple Silicon, Rosetta 2 is not needed — DFIR-Nexus runs natively
  on ARM. Python 3.12 is available via Homebrew.
- Xcode Command Line Tools provide Git and compilers.

**Exit condition:** `python3 --version` shows ≥ 3.12.

---

## 2. Install the package

### 2a. Setup script (recommended)

One command, per OS, from the repo root:

```bash
# Linux (SIFT, Ubuntu, REMnux, Debian — any Bash-capable host)
./setup-linux.sh

# macOS (Apple Silicon + Intel)
./setup-macos.sh

# Windows (PowerShell 7+, run from repo root)
.\setup-windows.ps1
```

**What each script does:**

1. Verifies Python 3.12+
2. Creates a virtual environment at `.venv/` (unless `--no-venv`)
3. Runs `pip install -e .[all]` — all optional extras included
4. Prompts for **examiner identity** (`nexus config --examiner "..."`)
5. Prompts for **approval password** (`nexus config --setup-password`)
6. Runs `nexus init` — connectivity test + LLM client config snippet

**Flags** (any order, all OSes):

| Flag | Effect |
|------|--------|
| `--skip-init` | Stop after install — useful for CI |
| `--skip-password` | Skip the password prompt; set later with `nexus config --setup-password` |
| `--no-venv` | Install into the active interpreter without creating `.venv/` |

### 2b. Pip install (for users who prefer manual control)

```bash
pip install dfir-nexus[all]
```

The `[all]` extras bundle:

| Extra | Pulls in | Typical size |
|-------|----------|-------------|
| `[http]` | Starlette + uvicorn (Examiner Portal) | ~5 MB |
| `[rag]` | ChromaDB + sentence-transformers | ~600 MB |
| `[triage]` | orjson + zstandard (`.tar.zst` baseline DBs) | ~2 MB |
| `[opensearch]` | opensearch-py | ~2 MB |
| `[opencti]` | pycti | ~3 MB |
| `[encrypt]` | cryptography (`nexus export --encrypt`) | ~8 MB |

Install à la carte if `[all]` is too heavy:

```bash
pip install dfir-nexus[http,rag]
```

Then set your identity and password:

```bash
nexus config --examiner "alice"
nexus config --setup-password    # required before you can approve
nexus init
```

### 2c. From source (contributors)

```bash
git clone https://github.com/Unallocated/DFIR-Nexus.git
cd DFIR-Nexus
python -m venv .venv
source .venv/bin/activate      # Linux / macOS
.venv\Scripts\activate.ps1     # Windows (PowerShell)

pip install -e .[all]
```

This installs in editable mode — any change to `src/` is reflected
immediately when you restart the server.

**Exit condition:** `nexus --version` prints a version string.

---

## 3. Configure identity + secrets

Both steps are required before the first case is opened. Both are
terminal-only for security — no web UI sets the password.

### Set your examiner name

```bash
nexus config --examiner "alice"
```

This writes `~/.nexus/config.yaml` with your examiner slug. The slug
is lowercased and sanitised (`Alice Smith` → `alicesmith`, `Al-ice`
→ `al-ice`). It is used in finding IDs (`F-alice-001`), timeline
event IDs, audit IDs, and the HMAC verification ledger.

### Set the approval password

```bash
nexus config --setup-password
```

You are prompted **twice** via `getpass` — no echo. The password:

- Must be at least **8 characters**.
- Is hashed with **PBKDF2-SHA256** (600 000 iterations, 32-byte random
  salt) and stored at `~/.nexus/passwords/<examiner>.json` (`0o600`).
- Is never stored in plaintext.

**Why this matters.** The approval password is the human-in-the-loop
trust boundary. Without it, `nexus approve` and the Portal commit
workflow refuse to run. No DRAFT finding can become APPROVED without
this password. The AI cannot bypass it.

### View current config

```bash
nexus config --show
```

Prints: examiner, password-set flag, cases root, data root, and server
settings.

### Rotate the password (optional)

```bash
nexus config --setup-password
```

Run the same command again. It prompts for the **old password** first,
then the new one. On success it re-signs every HMAC verification ledger
entry for this examiner with the new key — no existing approvals are
invalidated.

**Exit condition:** `nexus config --show` shows `password_set: true`.

---

## 4. Multi-machine wiring (skip if solo)

Only needed when you run DFIR-Nexus on **more than one host**. The
solo path (one machine) is actually a subset of this — just run
§1→§3→§5a (stdio) or §1→§3→§5a (HTTP) on a single host.

### Topology

```
                   ┌──────────────────────┐
                   │  LLM client          │
                   │  (Claude Code, etc.) │
                   └────┬──────────┬──────┘
                        │          │
         ┌──────────────┘          └──────────────┐
         ▼                                        ▼
┌──────────────────────┐                ┌──────────────────────┐
│ SIFT VM (Linux)      │                │ Windows analyst WM  │
│                      │                │                      │
│ nexus serve --http   │                │ nexus serve --http   │
│ --host 0.0.0.0       │                │ --host 0.0.0.0       │
│ :4508                │                │ :4508                │
│                      │                │                      │
│ Exposes: sift tools, │                │ Exposes: windows     │
│ case, forensic, rag, │                │ tools, case, forensic│
│ triage, opencti      │                │ rag, triage, opencti │
└──────────────────────┘                └──────────────────────┘
```

### Per-host bring-up

On **each** forensic host (SIFT VM, Windows workstation):

```bash
# 1. Install + configure (run §1–§3 on each machine)
./setup-linux.sh   # or .\setup-windows.ps1

# 2. Start the HTTP server (bind all interfaces)
nexus serve --http --host 0.0.0.0 --port 4508
```

Port 4508 is the convention but any port works.

### Authentication for network exposure

For any deploy beyond local loopback, set a bearer token per host:

```bash
# Generate a random token (Linux/macOS)
export NEXUS_BEARER_TOKEN="$(openssl rand -hex 32)"

# Or on Windows, set the env var manually before starting:
$env:NEXUS_BEARER_TOKEN = "your-generated-token-here"

nexus serve --http --host 0.0.0.0 --port 4508
```

### Generate the LLM client config

From your LLM client machine (could be a third host or one of the
two forensic hosts):

```bash
nexus setup client --sift 10.0.0.2:4508 --windows 10.0.0.5:4508
```

This writes `.mcp.json` with both servers and `~/.claude/settings.json`
with deny rules that protect case files from AI modification.

To also add the bearer token:

```bash
nexus setup client --sift 10.0.0.2:4508 --windows 10.0.0.5:4508 \
  --bearer "your-token"
```

**Exit condition:** `curl http://<host>:4508/mcp` returns HTTP 200
from each host, and your LLM client shows tools from all servers.

---

## 5. Wire your LLM client

### 5a. Single nexus (solo examiner)

#### Claude Code — stdio (zero config)

```json
{
  "mcpServers": {
    "dfir-nexus": { "command": "nexus", "args": ["serve"] }
  }
}
```

Place this in `.mcp.json` (project-level) or `~/.claude/settings.json`
(global). No port, no network, no config — Claude spawns nexus as a
subprocess.

#### Claude Code — HTTP (multi-client, Portal)

```json
{
  "mcpServers": {
    "dfir-nexus": {
      "type": "streamable-http",
      "url": "http://127.0.0.1:4508/mcp"
    }
  }
}
```

Requires `nexus serve --http --port 4508` running in another terminal
or as a service.

#### Cursor

`~/.cursor/mcp.json` (same JSON shape as Claude):

```json
{
  "mcpServers": {
    "dfir-nexus": { "command": "nexus", "args": ["serve"] }
  }
}
```

#### Cline (VS Code extension)

VS Code settings → `claude-dev.mcpServers`:

```json
{
  "claude-dev.mcpServers": {
    "dfir-nexus": { "command": "nexus", "args": ["serve"] }
  }
}
```

#### LibreChat

`librechat.yaml`:

```yaml
mcpServers:
  dfir-nexus:
    type: streamable-http
    url: http://127.0.0.1:4508/mcp
```

### 5b. Multi-nexus (lab / fleet)

After running `nexus setup client --sift ... --windows ...`, your
`.mcp.json` looks like this:

```json
{
  "mcpServers": {
    "dfir-nexus-sift": {
      "type": "streamable-http",
      "url": "http://10.0.0.2:4508/mcp"
    },
    "dfir-nexus-windows": {
      "type": "streamable-http",
      "url": "http://10.0.0.5:4508/mcp"
    }
  }
}
```

The same config generator also writes `~/.claude/settings.json` with
**deny rules** that prevent the AI from directly editing files in the
case directory:

```
Edit(**/CASE.yaml) …, Write(**/findings.json) …,
Bash(nexus approve*) …, Edit(**/.nexus/**) …
```

The LLM client automatically routes tool calls to the right server:
SIFT tools (`run_command`, `list_available_tools`) go to the Linux
host, Windows tools (`run_windows_command`, `list_windows_tools`) go
to the Windows host, and universal tools (case, report, RAG, triage,
OpenCTI) can go to either.

**Exit condition:** The LLM client shows `mcp__dfir-nexus*` tools
available in its tool list.

---

## 6. (Optional) Install the Claude Code skill bundle

Curates a tuned system prompt, hooks, and slash commands for Claude
Code. Two variants:

**Lite** (single-machine examiner):
```bash
cp -r claude-code/lite ~/.claude/skills/dfir-nexus
chmod +x ~/.claude/skills/dfir-nexus/hooks/*.sh
```

**Full** (multi-host, stricter sandbox):
```bash
cp -r claude-code/full ~/.claude/skills/dfir-nexus
chmod +x ~/.claude/skills/dfir-nexus/hooks/*.sh
```

Restart Claude Code, then verify from any project:

```text
/welcome
```

**What the skill gives you beyond vanilla MCP:**

| Asset | Purpose |
|-------|---------|
| `CLAUDE.md` | System prompt with "display plan before action" rule and DFIR discipline reminders |
| `forensic-audit.sh` | PostToolUse hook — every Bash command gets logged to `<case>/audit/claude-code.jsonl` with audit_id |
| `case-data-guard.sh` | PreToolUse hook — blocks `rm`, `mv`, `find -delete` on protected case files (findings.json, audit/*.jsonl, transparency.jsonl, etc.) |
| `/welcome` | Version check, baseline status, quickstart links |
| `/case` | Create or switch cases |
| `/approve` | Interactive finding approval (password prompt) |
| `/report` | Generate and save reports |
| Templates | `ACTIONS.md`, `FINDINGS.md`, `TIMELINE.md` for structured case notes |

See [claude-code/README.md](../claude-code/README.md) for the full
breakdown.

**Exit condition:** The skill is in `~/.claude/skills/dfir-nexus/`,
hooks are executable, and `/welcome` responds.

---

## 7. (Optional) Download baseline databases

Some modules are dormant until their data is downloaded. Do this from
your LLM client (not the terminal):

| Module | Tool to call | Size | What you get |
|--------|-------------|------|--------------|
| RAG (forensic knowledge) | `forensic_rag_download()` | ~600 MB | ChromaDB index with 23K+ records from 23 sources (Sigma, MITRE ATT&CK, Atomic Red Team, KAPE, LOLBAS, GTFOBins, …) |
| Windows triage baseline | `triage_download()` | ~2 GB | `known_good.db` + `context.db` — 2.6M+ records from clean Windows installs; LOLBins, vulnerable drivers, process rules, named pipes |
| OpenCTI (live) | n/a — needs env vars | depends on your instance | Connect to your OpenCTI server |
| OpenSearch (live) | n/a — needs env vars | depends on your cluster | Index and search evidence at scale |

**Environment variables for live modules:**

```bash
# OpenCTI
export OPENCTI_URL="https://your-cti.example.com"
export OPENCTI_TOKEN="your-token"

# OpenSearch
export OPENSEARCH_HOST="127.0.0.1"
export OPENSEARCH_PORT="9200"
# Optional: OPENSEARCH_USER, OPENSEARCH_PASSWORD, OPENSEARCH_SSL=true
```

**Check what's installed:**

From your LLM client:

```text
forensic_rag_status()    → "status": "ready" + record count
triage_status()          → "status": "present" + DB file sizes
opencti_status()         → "connected": true
idx_status()             → "connected": true + indices list
```

**Why this is §7 not §2:** Findings, case management, reporting, and
the approval chain all work without these databases. RAG and triage
are "richer queries / offline baseline validation" — valuable but
optional. Only install what you need.

**Exit condition:** The assets you want are downloaded; the ones you
skip are cleanly reported as `UNKNOWN` or `not_installed`.

---

## 8. Your first case (10‑minute walkthrough)

With the server running and your LLM client connected, run this
conversation:

```text
1. case_init("Ransomware-2026-001")
   → Creates INC-20260514091530 with platform capabilities listed

2. evidence_register(path="/evidence/triage/", description="EDR triage collection")
   → SHA-256 hashes each file, registers in evidence_registry.json

3. run_command("fls -f ntfs /evidence/image.dd")          # Linux / SIFT
   # OR
   run_windows_command("MFTECmd -f C:\Evidence\$MFT")     # Windows

   → Returns {"audit_id": "nexus-exam-20260514-001", ...}
   → ⚠ CAPTURE THIS audit_id — you need it for the next step

4. record_finding(
       title="EVIL.EXE launched from AppData",
       observation="MFT shows EVIL.EXE with timestamps consistent with execution",
       interpretation="User-writable directory execution consistent with initial access via phishing",
       confidence="MEDIUM",
       confidence_justification="MFT $STANDARD_INFORMATION + $FILE_NAME timestamps corroborate execution within the suspect window",
       event_timestamp="2026-01-15T14:32:00Z",
       artifacts=[{"audit_id": "nexus-exam-20260514-001"}]
   )
   → Returns {"status": "STAGED", "finding_id": "F-exam-001", "provenance_grade": "FULL", …}

   If you invented an audit_id instead of using the one from step 3:
   → Returns {"status": "REJECTED", "error": "Finding rejected: invalid or missing evidence trail"}
   → That's the provenance check working — not a bug.
```

Now approve as a human:

```bash
# Terminal (password required — blocks AI approval)
nexus approve --interactive
```

Walk through the DRAFT finding. Enter your approval password. The
finding moves to APPROVED, an HMAC entry is written to the verification
ledger, and a hash-chained entry is appended to the transparency log.

```bash
# Generate the report
nexus report --full --save report.json
```

The report reconciles every APPROVED finding against the HMAC ledger.
If a finding is APPROVED but missing from the ledger (or vice versa),
the report's `verification_alerts` will flag it.

**Provenance chain recap:**

```
run_command(...)
  → audit_id
    → record_finding(artifacts=[{audit_id}])
      → STAGED as DRAFT
        → nexus approve --interactive (terminal, password required)
          → APPROVED + HMAC ledger entry + transparency log entry
            → generate_report(profile="full")
```

---

## 9. Verification checklist + troubleshooting

### Verification checklist

Run through these steps to confirm the chain is working end-to-end:

```
[ ] nexus --version                      → version string
[ ] nexus config --show                  → examiner + password_set: true
[ ] nexus serve --http                   → starts on :4508
[ ] curl http://127.0.0.1:4508/mcp       → HTTP 200
[ ] LLM client shows mcp__dfir-nexus__* tools
[ ] case_init("test")                    → returns a case_id
[ ] log_external_action(command="echo test", purpose="verify")
    → returns an audit_id
[ ] record_finding(title="Test", observation="Verification",
    interpretation="Check", artifacts=[{"audit_id": "<from above>"}])
    → returns STAGED (not REJECTED)
[ ] nexus approve --interactive          → finds DRAFT, approves it
[ ] generate_report(profile="status")    → shows 1 approved finding,
    no verification_alerts
[ ] transparency_verify()                → returns "valid": true
```

If every box is ticked, the chain is working end-to-end.

### Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `nexus: command not found` | Package not installed or venv not activated | `pip install dfir-nexus` or activate `.venv/bin/activate` |
| Tools not showing in LLM client | Wrong MCP transport or server not running | Check stdio vs HTTP config; verify `nexus serve` (stdio) or `nexus serve --http` |
| Findings rejected (`REJECTED`) | Missing `audit_id` in artifacts | Run a tool first, capture its returned `audit_id`, pass it in `artifacts` |
| `VALIDATION_FAILED` on record_finding | Missing `confidence_justification` or `interpretation` | Both are required — provide a one-sentence justification |
| `REJECTED` with `missing_audit_ids` | `audit_id` references entries from a different case | Ensure the tool ran while the current case was active |
| SIFT tools not available | Not running on Linux | `sift.py` registers only when `sys.platform == "linux"` |
| Windows tools not available | Not running on Windows | `windows.py` registers only when `sys.platform == "win32"` |
| RAG search fails | No index downloaded | Call `forensic_rag_download()` from your LLM client |
| Triage returns UNKNOWN | No database installed | Call `triage_download()` from your LLM client |
| Audit trail empty | No active case | Create case with `case_init()` first |
| Portal not loading | HTTP mode not enabled | Use `nexus serve --http` instead of stdio |
| Password not accepted | Locked out after 3 failures | Wait 15 minutes for lockout to expire |
| `nexus export --encrypt` errors | `cryptography` not installed | `pip install dfir-nexus[encrypt]` (or `[all]`) |
| `transparency_verify()` returns tampered index | Hash chain broken — investigate | Compare `~/.nexus/cases/<id>/transparency.jsonl` against case audit log; restore from backup; do not ship report until reconciled |
| Claude Code hooks not firing | Scripts not executable or `$CLAUDE_PROJECT_DIR` not set | `chmod +x ~/.claude/skills/dfir-nexus/hooks/*.sh` |
| Audit log empty after Bash invocations | Skill bundle installed but no active case | `nexus case init <name>` first — the hook needs an active case to write to |
| `nexus init` says baselines missing | RAG / triage DBs not downloaded yet | From LLM client: `triage_download()` and `forensic_rag_download()` |
| Service won't start | PID file from a previous run | `nexus service stop <name>` clears stale PID files |

---

## 10. Where am I, what's next

### Linear decision tree

```
Have Python 3.12+?
  no  → §1 Prerequisites
  yes ↓
Have nexus on PATH?
  no  → §2 Install (recommend setup-*.sh script)
  yes ↓
nexus config --show confirms password_set: true?
  no  → §3 Configure (examiner + password)
  yes ↓
Single host?
  yes → §5a Wire one nexus (stdio or HTTP)
  no  → §4 Multi-machine + §5b Multi-nexus config
Want Claude Code skill bundle?
  yes → §6 Install skill (copy hooks + CLAUDE.md)
  no  ↓
Want RAG / triage baselines?
  yes → §7 Download optional databases
  no  ↓
⟶  §8 Run your first case
Something broken ⟶ §9 Verify + troubleshoot
```

### State → action table

| Current state (what's true) | Next action | Section |
|---|---|---|
| Fresh repo clone, nothing installed | Run `./setup-linux.sh` (or OS equivalent) | §2a |
| `pip install` done, no examiner set | `nexus config --examiner "..." && nexus config --setup-password` | §3 |
| Examiner + password set, single host | Wire LLM client (stdio or HTTP config) | §5a |
| Examiner + password set, multi-host | Per-host bring-up + token → `nexus setup client` | §4 + §5b |
| LLM client wired, tools showing | Run `case_init("test")` or `/welcome` (if skill installed) | §6 → §8 |
| `record_finding` returns REJECTED | You invented an audit_id — run a tool first, capture the real ID | §8 |
| Findings stuck in DRAFT | Terminal: `nexus approve --interactive` (password required) | §8 |
| Report shows `verification_alerts` | Ledger drift — `transparency_verify()` and reconcile | §9 |

---

## 11. What this guide does NOT cover

Some topics are deliberately excluded to keep the setup guide focused.
Each has a canonical home elsewhere in the docs:

| Topic | Where it lives |
|-------|---------------|
| Full 97-tool catalog | `get_tool_help(name)` per-tool · `README.md` summary table |
| 14 forensic discipline rules | `get_rules()` MCP tool · `claude-code/lite/FORENSIC_DISCIPLINE.md` |
| Architecture diagram | `ARCHITECTURE.md` |
| Comparison vs upstream | `COMPARISON.md` |
| Per-CLI-command reference | `CLI.md` (single source of truth) |
| Examiner workflow / walkthrough | `guide.md` |
| LangGraph pipeline | `langgraph/LANGGRAPH_INTEGRATION.md` |
| Security / vulnerability disclosure | `SECURITY.md` |
| Contributing / PR flow | `CONTRIBUTING.md` |

The setup guide's tone is "do this, then this, then this." Reference
material goes elsewhere.
