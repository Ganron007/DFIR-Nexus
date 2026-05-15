# DFIR-Nexus

**One audit chain. One process. AI-assisted. Examiner-approved.**

!!! warning "Beta"
    The provenance chain, HMAC ledger, transparency log, and discipline
    validation are tested (123 passing tests). The project has not yet
    undergone third-party security review. Findings produced by
    DFIR-Nexus should be **independently verified** before being used
    in legal proceedings. See [FAQ](FAQ.md#is-this-production-ready)
    for the full read on maturity.

---

## What it is

DFIR-Nexus is one FastMCP process that:

- **Wraps 97 forensic tools** (Hayabusa, MFTECmd, chainsaw, Zimmerman,
  KAPE, bulk_extractor, …) as Model Context Protocol (MCP) tools an
  LLM client (Claude Code, Cursor, Cline, LibreChat) can call.
- **Logs every tool call** to a SHA-256 audit chain rooted in the
  active case directory.
- **Refuses to record a finding** without a real `audit_id` from that
  chain.
- **Holds every finding at DRAFT** until a human with the password
  signs it into an HMAC-verified ledger. The LLM cannot approve.
- **Mirrors approvals into a hash-chained transparency log** so a
  tampered case directory is detectable.
- **Reconciles reports against the ledger** — any drift surfaces as
  `verification_alerts`.

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

## Where to start

| You want to… | Read |
|---|---|
| Install and run your first case | [Workflow guide](guide.md) §1–§2 |
| Look up a CLI command | [CLI reference](CLI.md) |
| Understand the trust model | [Architecture](ARCHITECTURE.md) |
| See how this compares to `sift-mcp` / `wintools-mcp` / `Valhuntir` | [Comparison](COMPARISON.md) |
| Ask a "is this for me?" question | [FAQ](FAQ.md) |
| Track what changed when | [Changelog](CHANGELOG.md) |

For the curated Claude Code skill bundle, the LangGraph pipeline, and
contribution instructions, see the
[GitHub repository](https://github.com/Unallocated/DFIR-Nexus).
