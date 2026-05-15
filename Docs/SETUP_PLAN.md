# Setup guide — content plan

> **This is a planning skeleton, not the final guide.** Each section lists
> *purpose / what to write / sources / flow-state*. Expand each into prose
> in a follow-up pass. The structure is opinionated; the content is yours.
>
> When ready, fold the expanded version into `Docs/guide.md` §1–§3, or
> spin off as `Docs/SETUP.md` if it grows past ~400 lines.

---

## 0. Reader segmentation (write this near the top)

Different visitors land with different needs. Decide on the matrix
**before writing the guide** so each reader knows which sections apply.

| Reader | Their goal | Phases they need |
|---|---|---|
| Solo Linux examiner (SIFT VM, Ubuntu desktop, REMnux) | Local stdio install, one analyst | 1 → 2 → 3 → 5a → 7 → 8 |
| Solo Windows examiner (analyst workstation) | Run on Windows, native Zimmerman/KAPE tools | 1 → 2 → 3 → 5a → 7 → 8 |
| Multi-machine lab (SIFT + Windows VMs, single LLM client) | One LLM, two `nexus serve --http` instances | 1 → 2 → 3 → 4 → 5b → 7 → 8 |
| Headless / CI install | Automated, no interactive prompts | 1 → 2 (`--skip-init --skip-password`) → 8 verification |
| MCP integrator (writing another agent) | Just the API surface | 1 → 2 → 5 (skip 7) → API exploration |

**Why this matters:** the Linux + Windows examiners ~80% of visitors,
both finish at "run your first case" in ~10 minutes. The lab path is
2–3× longer; CI path is shortest. Don't make the simple readers
scroll through multi-machine wiring before they hit their happy path.

---

## 1. System prerequisites

| Dep | Why | Min version | Linux | macOS | Windows |
|---|---|---|---|---|---|
| Python | Everything is Python | 3.12 | `apt install python3.12 python3.12-venv` (Debian/Ubuntu); pre-installed on SIFT 2024+ | `brew install python@3.12` | `winget install Python.Python.3.12` or python.org installer (tick "Add to PATH") |
| `pip` | Package install | comes w/ Python | bundled | bundled | bundled |
| Git | Source install / `nexus update` | any | `apt install git` | `xcode-select --install` | `winget install Git.Git` |
| (Linux) build-essential | Some wheels build from source on niche distros | — | `apt install build-essential` | n/a | n/a (`cryptography` ships wheels on Windows) |
| (Optional) Docker | OpenSearch backend | any | `apt install docker.io` | Docker Desktop | Docker Desktop |
| (Optional) Bash | Skill bundle hooks | any | native | native | Git Bash or WSL |
| (Optional) PowerShell 7+ | `setup-windows.ps1` only | 7.x | `apt install powershell` | `brew install powershell` | `winget install Microsoft.PowerShell` |

**What to write:** one paragraph per OS, in-place commands users can
copy-paste. Don't link out to python.org's installer page — paste the
literal `winget` / `brew` / `apt` line.

**Source to pull from:** `setup-linux.sh` line 38–47 (Python version
check logic) tells you which versions to recommend.

**Flow-state:** before any `pip install`. Reader exits this section
with: working `python3 --version` ≥ 3.12 on PATH.

---

## 2. Install the package

Three install paths — present in this order, recommend the first.

### 2a. Setup script (recommended)

| OS | Command | What it does |
|---|---|---|
| Linux | `./setup-linux.sh` | Verifies Python, creates `.venv/`, runs `pip install -e .[all]`, prompts examiner + password, runs `nexus init` |
| macOS | `./setup-macos.sh` | Same, prefers `python3.12` → `python3.13` → `python3` |
| Windows | `.\setup-windows.ps1` | PowerShell 7+, otherwise same flow |

Flags: `--skip-init` (CI), `--skip-password`, `--no-venv` (install
into active interpreter).

### 2b. Pip install (for users who don't want a setup script)

```bash
pip install dfir-nexus[all]
```

What `[all]` pulls in:

- `[http]` — Starlette + uvicorn (Examiner Portal at `/portal`)
- `[rag]` — ChromaDB + sentence-transformers (~600 MB)
- `[triage]` — orjson + zstandard (`.tar.zst` baseline DBs)
- `[opensearch]` — opensearch-py
- `[opencti]` — pycti
- `[encrypt]` — cryptography (`nexus export --encrypt`)

If `[all]` is overkill, install à la carte:
`pip install dfir-nexus[rag,encrypt]` etc.

### 2c. From source (contributors)

```bash
git clone https://github.com/Unallocated/DFIR-Nexus.git
cd DFIR-Nexus
python -m venv .venv && source .venv/bin/activate
pip install -e .[all]
```

**What to write:** the three paths, side-by-side. Bold path 2a; treat
2b as "the manual equivalent"; treat 2c as "contributors only."

**Flow-state:** reader exits with `nexus --version` working and the
`nexus` binary on PATH (or accessible via the venv).

---

## 3. Configure identity + secrets

Both required before the first case is opened, both terminal-only.

| Step | Command | What gets written | Notes |
|---|---|---|---|
| Set examiner | `nexus config --examiner "alice"` | `~/.nexus/config.yaml` (`examiner: alice`) | Slug-lowercased + sanitised. Show what's stored. |
| Set approval password | `nexus config --setup-password` | `~/.nexus/passwords/<examiner>` (PBKDF2-SHA256, `0o600`) | Prompted twice via `getpass` — no echo. Re-run to rotate; the HMAC ledger is re-signed in place. |
| (Optional) View config | `nexus config --show` | reads + prints `config.yaml`, examiner, password-set flag | Sanity check. |

**What to write:** Explain *why* the password matters here — this is
where the human-in-the-loop trust boundary lives. Without it,
`nexus approve` won't run, and DRAFT findings can't be promoted.

**Source:** `src/nexus/auth.py` (PBKDF2 params, lockout policy);
`Docs/ARCHITECTURE.md` Security Model row 2.

**Flow-state:** reader exits with `~/.nexus/passwords/<examiner>`
existing and `nexus config --show` confirming `password_set: true`.

---

## 4. Multi-machine wiring (skip if solo)

Only readers running on >1 host need this section. Make it a clear
sub-page if it bloats §3.

### Topology

```
                  ┌─────────────────┐
                  │  LLM client     │
                  │  (Claude Code)  │
                  └────┬───────┬────┘
                       │       │
        ┌──────────────┘       └──────────────┐
        ▼                                     ▼
┌───────────────────┐                ┌──────────────────┐
│ SIFT VM (Linux)   │                │ Windows analyst  │
│ nexus serve --http│                │ nexus serve --http│
│ --host 0.0.0.0    │                │ --host 0.0.0.0   │
│ :4508             │                │ :4508            │
└───────────────────┘                └──────────────────┘
```

### Per-host bring-up

1. **On each host**: run §1–§3 locally.
2. **On each host**: `nexus serve --http --host 0.0.0.0 --port 4508`
   (port 4508 by convention; pick whatever you want).
3. **On LLM client machine** (could be a third host or one of the two):
   `nexus setup client --sift <linux-ip>:4508 --windows <win-ip>:4508`.
   This writes `.mcp.json` with both servers under separate keys.

### Auth (production)

For any deploy beyond local loopback, **set a bearer token** per host:

```bash
export NEXUS_BEARER_TOKEN="$(openssl rand -hex 32)"
nexus serve --http --port 4508 --host 0.0.0.0
```

Add the token to the LLM client config (`headers.Authorization: Bearer <token>`).
`nexus setup client --bearer <token>` writes this for you.

**Flow-state:** reader exits with `curl http://<host>:4508/mcp` returning
200 from both hosts, and the LLM client's `.mcp.json` listing both
servers.

---

## 5. Wire your LLM client

Two sub-paths. Default to 5a unless reader said they're in multi-host.

### 5a. Single nexus, your LLM client points at it

#### Claude Code (stdio — zero config)

`~/.claude/settings.json` or `<project>/.mcp.json`:

```json
{
  "mcpServers": {
    "dfir-nexus": { "command": "nexus", "args": ["serve"] }
  }
}
```

#### Claude Code (HTTP)

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

#### Cursor / Cline / LibreChat

Each client has its own config path:

| Client | Config file | Format |
|---|---|---|
| Cursor | `~/.cursor/mcp.json` | same shape as Claude |
| Cline | VS Code: `claude-dev.mcpServers` setting | JSON in settings.json |
| LibreChat | `librechat.yaml` → `mcpServers:` block | YAML, different keys |

**TODO when writing:** verify exact keys/paths for each client; this
table is a placeholder.

### 5b. Multi-nexus (lab)

`.mcp.json` after `nexus setup client --sift ... --windows ...`:

```json
{
  "mcpServers": {
    "dfir-nexus-sift":    { "url": "http://<linux-ip>:4508/mcp", ... },
    "dfir-nexus-windows": { "url": "http://<win-ip>:4508/mcp",   ... }
  }
}
```

The LLM client picks the right server per tool call (SIFT tools route
to the Linux host, Windows tools to the Windows host, universals can
go to either).

**Flow-state:** reader exits with the LLM client showing
`mcp__dfir-nexus*` tools available.

---

## 6. (Optional) Install the Claude Code skill bundle

Curated experience — system prompt, hooks, slash commands.

```bash
# Lite (single-machine examiner)
cp -r claude-code/lite ~/.claude/skills/dfir-nexus
chmod +x ~/.claude/skills/dfir-nexus/hooks/*.sh

# Or Full (multi-host, sandbox + stricter)
cp -r claude-code/full ~/.claude/skills/dfir-nexus
chmod +x ~/.claude/skills/dfir-nexus/hooks/*.sh
```

Restart Claude Code. Then in any project run `/welcome` to verify.

**What this gives you that vanilla MCP doesn't:**

- A CLAUDE.md system prompt with the "display plan before action" rule
- `forensic-audit.sh` PostToolUse hook — every Bash command audited
- `case-data-guard.sh` PreToolUse hook — blocks `rm/mv/find-delete`
  on protected case files (`findings.json`, `audit/*.jsonl`,
  `transparency.jsonl`, etc.)
- Slash commands: `/welcome`, `/case`, `/approve`, `/report`
- Case templates (`ACTIONS.md`, `FINDINGS.md`, `TIMELINE.md`)

See `claude-code/README.md` for the full breakdown.

**Flow-state:** reader exits with the skill in `~/.claude/skills/`,
hooks executable, Claude Code restarted.

---

## 7. Optional baselines + data (do this once)

Some modules are dormant until their data is downloaded. From your
LLM client (not the terminal):

| Module | Tool to call | Size | Source |
|---|---|---|---|
| RAG (forensic knowledge) | `forensic_rag_download()` | ~600 MB | GitHub release |
| Windows triage baseline | `triage_download()` | ~2 GB | GitHub release |
| OpenCTI (live) | n/a — needs `OPENCTI_URL` + `OPENCTI_TOKEN` env vars | depends | your OpenCTI instance |
| OpenSearch (live) | n/a — needs `OPENSEARCH_HOST` + port env vars | depends | your OpenSearch cluster |

Check status: `triage_status()`, `get_knowledge_stats()`.

**Why this is §7 not §2:** these are *optional*. Findings, case
management, reporting, audit chain all work without them. RAG +
triage are "I want richer queries / offline baseline validation."

**Flow-state:** reader exits with the assets they want, leaves the
others uninstalled.

---

## 8. Your first case (10-minute walkthrough)

This is the existing `Docs/guide.md` §2 content — keep it.
Re-numbered, but no new content needed. Maybe tighten with
screenshots of the Examiner Portal.

Critical pattern to emphasise:

```
run_command(...) → audit_id → record_finding(artifacts=[{audit_id}])
                              → STAGED as DRAFT
                              → nexus approve --interactive (terminal)
                              → APPROVED + HMAC ledger entry
                              → generate_report(profile="full")
```

If they invent an `audit_id`, `record_finding` returns `REJECTED`.
That's the provenance check working; not a bug.

---

## 9. Verification + troubleshooting

Keep the existing `Docs/guide.md` §8 troubleshooting table — it's
current and covers 13 symptoms. Possibly add a "Verification
checklist" sub-section here:

```
[ ] `nexus --version` returns
[ ] `nexus config --show` lists examiner + password_set: true
[ ] `nexus serve --http` starts and `curl localhost:4508/mcp` 200s
[ ] LLM client shows `mcp__dfir-nexus__*` tools
[ ] `case_init("test")` returns a case_id
[ ] `log_external_action(command="echo test", purpose="setup verify")` returns an audit_id
[ ] `record_finding(...)` with that audit_id returns STAGED
[ ] `nexus approve --interactive` finds the DRAFT and approves it
[ ] `generate_report(profile="status_brief")` shows 1 approved finding, no verification_alerts
[ ] `transparency_verify()` returns verified: true
```

If every box is ticked, the chain is working end-to-end.

---

## 10. Flow matrix — "where am I, what's next"

Two presentations, side-by-side in the final guide.

### Linear decision tree (text)

```
Have Python 3.12+?
  no  → §1 Prerequisites
  yes ↓
Have nexus on PATH?
  no  → §2 Install (recommend `setup-*.sh`)
  yes ↓
`nexus config --show` confirms password_set?
  no  → §3 Configure
  yes ↓
Single host?
  yes → §5a Wire one nexus
  no  → §4 Multi-machine + §5b Multi-nexus config
Want Claude Code skill bundle?
  yes → §6 Install skill
  no  ↓
Want RAG / triage baselines?
  yes → §7 Download baselines
  no  ↓
Run your first case  → §8
Something doesn't work → §9 Verify + troubleshoot
```

### State table — current state → next action

| Current state (what's true) | Next action | Section |
|---|---|---|
| Fresh repo clone, nothing installed | Run setup script for your OS | §2a |
| `pip install` done, no examiner set | `nexus config --examiner "..." && nexus config --setup-password` | §3 |
| Examiner + password set, single host | Pick a transport (stdio / HTTP), wire LLM client | §5a |
| Examiner + password set, multi host | Per-host bring-up + token | §4 + §5b |
| LLM client wired, MCP tools showing | Run `/welcome` (if skill) or `case_init("test")` | §6 → §8 |
| `record_finding` returns REJECTED | You invented an audit_id; check the flow | §8 + §9 |
| Findings stuck in DRAFT | Terminal: `nexus approve --interactive` | §8 |
| Report shows `verification_alerts` | Ledger drift — `transparency_verify()` and reconcile | §9 |

---

## 11. What to keep on the cutting room floor

Things that bloat a setup guide and should live elsewhere:

- **The 14 discipline rules** — already in `FORENSIC_DISCIPLINE.md`,
  knowledge YAML, and the `get_rules()` MCP tool. Don't restate.
- **The 97-tool catalog** — already in `README.md` (summary) and
  `get_tool_help()` (per-tool). Don't restate.
- **Architecture diagram** — in `ARCHITECTURE.md`. Link.
- **Comparison vs upstream** — in `COMPARISON.md`. Link.
- **Per-CLI-command reference** — in `CLI.md`. Link.

Setup-guide tone is *do this, then this, then this*. Reference
material goes elsewhere.

---

## 12. Open questions for the writer (you)

When expanding this into the real guide, decide:

1. **Single doc or split?** `guide.md` is already 280 lines. If setup
   bloats past ~500 lines combined, spin `SETUP.md` off as its own
   doc and have `guide.md` cover *workflow only*. Recommend split if
   you want screenshots in either.
2. **Screenshots vs text-only?** Examiner Portal benefits massively
   from 1–2 screenshots. Setup flow benefits from a terminal
   recording / `asciinema` cast. Pick one or accept text-only.
3. **Per-LLM-client sub-pages?** `.mcp.json` shape differs by client.
   Either one section with a table (Cursor/Cline/Claude/LibreChat) or
   separate pages. Recommend table unless one client gets enough
   examiner traction to deserve its own page.
4. **Where to put `nexus init` description?** Currently it's both in
   the setup scripts (they call it) and as a standalone command. Pick
   one canonical mention to avoid two-source drift.
5. **Where does `transparency_verify()` live in the flow?** It's a
   verification step (§9) but also a "before shipping a report"
   pre-flight (§8). Decide which is primary.

---

## 13. How to use this outline

1. Copy this file to `Docs/SETUP.md` (or expand `guide.md` §1–§2 in
   place).
2. For each section, replace `[What to write]` / `[Sources]` / etc.
   with prose.
3. Delete §12 "Open questions" once decided.
4. Delete this outline file once the real guide ships — keeping both
   creates drift surface.

Estimated final length: **400–600 lines** for a single combined
guide, **250 + 250** if you split.

---

## 14. Token budget note

This outline is ~370 lines and intentionally light on prose. When
expanding, the **highest-leverage sections to write first** are:

1. **§0 Reader segmentation** — orients everyone in 30 seconds.
2. **§2 Install** — the actual install commands; most readers stop
   reading once they see their OS.
3. **§5 Wire LLM client** — the failure point for ~half of first-time
   users.
4. **§10 Flow matrix** — the "I'm stuck, where am I?" quick lookup.

Everything else is filler that can wait for v2 of the guide.
