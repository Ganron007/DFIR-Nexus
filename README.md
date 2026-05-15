# DFIR-Nexus

**One audit chain. One process. AI-assisted. Examiner-approved.**

> ⚠️ **Status: Beta.** The provenance chain, HMAC ledger, transparency
> log, and discipline validation are tested (123 passing tests). The
> project has not yet undergone third-party security review. Findings
> produced by DFIR-Nexus should be **independently verified** before
> being used in legal proceedings. See [SECURITY.md](SECURITY.md) for
> vulnerability disclosure and [Docs/FAQ.md](Docs/FAQ.md) for the
> full honest read on maturity.

---

## Why DFIR-Nexus exists

Digital forensics and incident response leans on a fleet of single-
purpose tools — Hayabusa, MFTECmd, chainsaw, bulk_extractor, Zimmerman,
KAPE — and a separate set of conventions for findings, timelines,
chain-of-custody, and report generation. Stitching these together
across a SIFT box and a Windows analyst workstation, by hand, in the
middle of an incident, is where mistakes happen.

DFIR-Nexus is one process that:

- **Wraps the tool fleet** as 97 Model Context Protocol (MCP) tools an
  LLM client (Claude Code, Cursor, Cline, LibreChat) can call directly.
- **Logs every tool call** to a SHA-256 audit chain rooted in the case
  directory.
- **Refuses to record a finding** that doesn't reference a real
  `audit_id` from that chain.
- **Holds every finding at DRAFT** until a human with the password
  signs it into an HMAC-verified ledger. The LLM cannot approve.
- **Mirrors approvals into a hash-chained transparency log** so a
  tampered case directory is detectable without trusting the
  verification dir.
- **Generates reports** that reconcile against the ledger and surface
  any drift as `verification_alerts`.

If the LLM hallucinates, the worst that can happen is a DRAFT finding
that fails validation or never gets approved.

## Who it's for

- **DFIR examiners and IR responders** who want AI assistance on tool
  selection, parsing, and narrative — without giving the AI the final
  word on what becomes evidence.
- **Lab / homelab analysts and forensic students** who want a coherent
  workspace across Linux (SIFT) and Windows tooling without standing
  up seven separate MCP servers and a gateway.
- **MCP / agent developers** building DFIR or SOC integrations who
  want a single battle-tested target instead of a heterogeneous fleet.

---

## 5-minute quickstart

### 1. Install (one command per OS)

```bash
# Linux (SIFT, Ubuntu, REMnux, etc.)
./setup-linux.sh

# macOS
./setup-macos.sh

# Windows (PowerShell 7+)
.\setup-windows.ps1
```

Each script verifies Python 3.12+, creates a venv at `.venv/`, installs
`pip install -e .[all]`, prompts for examiner identity + approval
password, and runs `nexus init`. Use `--skip-init` for CI.

Manual install if you'd rather skip the script:

```bash
pip install dfir-nexus[all]
nexus config --examiner "your-name"
nexus config --setup-password    # required before you can approve findings
nexus init
```

The setup scripts run `nexus init` for you at the end — that step
checks optional dependencies, reports baseline-database status, and
writes a `nexus-config.json` snippet you can paste into your LLM
client.

> **Full setup guide → [Docs/SETUP.md](Docs/SETUP.md)** covers all
> install paths (setup script, pip, from source), multi-machine wiring,
> LLM client configuration for every client type, the Claude Code skill
> bundle, optional baseline databases, verification checklist, and a
> flow matrix for "where am I, what's next."

### 2. Start the server

```bash
# Stdio mode — the LLM client spawns nexus directly (zero config)
nexus serve

# Or HTTP mode — for multi-client + Examiner Portal at /portal
nexus serve --http --port 4508
```

### 3. Wire your LLM client

**Claude Code** — paste this into `.mcp.json` or `~/.claude/settings.json`:

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

For stdio mode the binary is launched directly:

```json
{
  "mcpServers": {
    "dfir-nexus": { "command": "nexus", "args": ["serve"] }
  }
}
```

**Want a complete Claude Code experience?** Copy our curated skill bundle:

```bash
cp -r claude-code/lite ~/.claude/skills/dfir-nexus
chmod +x ~/.claude/skills/dfir-nexus/hooks/*.sh
```

The skill ships a tuned system prompt (CLAUDE.md), tool-selection
reference, hooks that audit every Bash command to the case audit log,
a destructive-command guard that protects case data, slash commands
(`/welcome`, `/case`, `/approve`, `/report`), and case-file templates.
See [claude-code/README.md](claude-code/README.md). A stricter
`full/` variant is available for multi-host fleets.

### 4. Run your first investigation

From your LLM client:

```text
case_init("Demo Investigation")
evidence_register(path="/evidence/", description="Triage collection")

run_command("fls -f ntfs /evidence/image.dd")           # Linux / SIFT
run_windows_command("MFTECmd -f C:\\Evidence\\$MFT")    # Windows

record_finding(
    title="EVIL.EXE launched from AppData",
    observation="MFT shows EVIL.EXE with $STANDARD_INFORMATION and $FILE_NAME timestamps consistent with execution",
    interpretation="Initial access via user-writable directory — consistent with phishing",
    confidence="MEDIUM",
    confidence_justification="MFT timestamp pair corroborates execution within the suspect window",
    event_timestamp="2026-01-15T14:32:00Z",
    artifacts=[{"audit_id": "<id returned by the run_command call>"}]
)
```

### 5. Approve as a human (terminal, password required)

```bash
nexus approve --interactive     # walk every DRAFT, password-gated
nexus report --full --save report.json
```

---

## Deployment options

| Shape | Command | When to use |
|-------|---------|-------------|
| **Solo, stdio** | `nexus serve` | One analyst, one LLM client, no network. Simplest. |
| **Multi-client, HTTP** | `nexus serve --http --port 4508` | Multiple LLM clients, web Examiner Portal. |
| **Multi-machine** | One `nexus serve` per OS + `nexus setup client --sift HOST:PORT --windows HOST:PORT` | One instance on each forensic VM. Platform-gated registration means each only exposes its native tools. |

---

## What's inside

| Module | Tools | Purpose |
|--------|------:|---------|
| `forensic` | 23 | Findings, timeline, TODOs, 14 discipline tools (rules, playbooks, anti-patterns, confidence, corroboration) |
| `case` | 15 | Case lifecycle, evidence registry, export / import, backup |
| `report` | 6 | Report generation across 6 profiles, IOC + MITRE aggregation, ledger reconciliation |
| `sift` | 5 | Linux forensic tool execution (Linux-gated) — denylist, path/arg validation, 65+ catalog entries |
| `windows` | 9 | Windows forensic tool execution (Windows-gated) — catalog-gated, 31 catalog entries, LRU caching |
| `rag` | 5 | ChromaDB semantic search across ~23K forensic records + pre-built index download |
| `opencti` | 11 | IOC / actor / malware / report / MITRE lookup, recent indicators, relationships |
| `triage` | 15 | Offline Windows baseline validation (2.6M-record SQLite) + download tool |
| `opensearch` | 8 | Evidence indexing, search, term aggregations, timeline histograms (real query DSL) |

**Total: 97 MCP tools.** Universal modules register on every OS;
`sift` and `windows` register only on matching OS.

For the full CLI surface (19 top-level commands), see
[Docs/CLI.md](Docs/CLI.md). For the architecture and trust model, see
[Docs/ARCHITECTURE.md](Docs/ARCHITECTURE.md). For an examiner walkthrough,
see [Docs/guide.md](Docs/guide.md).

---

## Documentation

| Doc | What it covers |
|-----|----------------|
| [Docs/SETUP.md](Docs/SETUP.md) | Comprehensive setup — prerequisites, install, identity, multi-machine wiring, client config, baselines, verification |
| [Docs/guide.md](Docs/guide.md) | Examiner workflow — install, first case, approval, reporting |
| [Docs/CLI.md](Docs/CLI.md) | Complete CLI reference (single source of truth) |
| [Docs/ARCHITECTURE.md](Docs/ARCHITECTURE.md) | Topology, provenance chain, security model |
| [Docs/COMPARISON.md](Docs/COMPARISON.md) | Side-by-side vs. upstream (`sift-mcp`, `wintools-mcp`, `Valhuntir`), with roadmap |
| [Docs/FAQ.md](Docs/FAQ.md) | Maturity, scope, common gotchas |
| [Docs/CHANGELOG.md](Docs/CHANGELOG.md) | Per-release change history |
| [claude-code/README.md](claude-code/README.md) | Curated Claude Code skill bundle (lite + full): CLAUDE.md, hooks, slash commands, case templates |
| [tests/README.md](tests/README.md) | How to run the test suites |
| [langgraph/LANGGRAPH_INTEGRATION.md](langgraph/LANGGRAPH_INTEGRATION.md) | Optional LangGraph automated investigation pipeline |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure, threat model |
| [CONTRIBUTING.md](CONTRIBUTING.md) | PR flow and how to run tests |
| `mkdocs.yml` | MkDocs Material site config; deploys to GitHub Pages via `.github/workflows/pages.yml` |

---

## License

MIT — see [LICENSE](LICENSE).
