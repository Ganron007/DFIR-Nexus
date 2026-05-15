# FAQ

Short answers to the questions that arrive most often.

## Is this production-ready?

**Beta.** The provenance chain, HMAC ledger, hash-chained transparency
log, and discipline validation are tested (123 passing tests across
three suites) and the parity audit against the upstream `sift-mcp` /
`wintools-mcp` / `Valhuntir` projects is documented in
[COMPARISON.md](COMPARISON.md). That said:

- Findings produced by DFIR-Nexus should be **independently verified**
  before being used in legal proceedings.
- The project has not yet undergone third-party security review.
- The LangGraph pipeline is functional but the hunt agent's
  finding-quality is bounded by the LLM you point at it.

If you find a defect affecting the trust model (audit, approval,
ledger, or transparency log), please follow [SECURITY.md](../SECURITY.md).

## How is this different from `sift-mcp` / `wintools-mcp` / `Valhuntir`?

DFIR-Nexus consolidates those three projects into a single FastMCP
process with one audit hierarchy. See [COMPARISON.md](COMPARISON.md)
for the side-by-side.

Short version:

- **Same tool surface** (97 tools vs ~83 upstream).
- **Fewer moving parts** — one process, not seven servers + a gateway
  + a separate dashboard.
- **One audit log** under the case directory instead of seven.
- **Net-new** — a hash-chained transparency log, ledger reconciliation
  in reports, and 8 OpenSearch tools the upstream didn't ship.

The honest trade-off: upstream's gateway is stronger when you need
one URL fronting many backends with per-IP rate limiting. We chose
direct multi-server connections instead. Either is defensible — see
COMPARISON.md §3.2.

## Does this replace Velociraptor / KAPE / Autopsy / my SIEM?

No. DFIR-Nexus is an **investigation surface** — it wraps existing
tools (Hayabusa, MFTECmd, chainsaw, bulk_extractor, the Zimmerman
suite, KAPE, …) in an audit-logged MCP server and pairs them with
findings / approval / reporting workflow. It does not collect
evidence on its own, it does not correlate alerts at SIEM scale, and
it does not replace a forensic suite like Autopsy.

What it does add: a single AI-assistable workspace with a strict
human-in-the-loop gate, so the LLM's output never silently becomes a
finding.

## What's MCP? What's LangGraph?

**MCP** — [Model Context Protocol](https://modelcontextprotocol.io/).
The standard for exposing tools to LLM clients (Claude Code, Cursor,
Cline, LibreChat, …). DFIR-Nexus is one MCP server that exposes 97
forensic tools.

**LangGraph** — Anthropic / LangChain's library for stateful, graph-
based LLM workflows with checkpointing and human-in-the-loop
interrupts. `langgraph/pipeline.py` is an optional automated
investigation pipeline; you can also drive nexus interactively from
any MCP-aware client.

## Why does `record_finding` reject my finding with `REJECTED`?

It can't verify the `audit_id` you passed. Every finding must
reference a tool call that ran **while the same case was active**.
The fix: run a tool first (`run_command`, `run_windows_command`, or
`log_external_action` for tools executed outside nexus), capture the
returned `audit_id`, and pass it back in `artifacts`.

See [guide.md](guide.md) §8 Troubleshooting for the full error table.

## I got `VALIDATION_FAILED` complaining about `confidence_justification`.

Forensic discipline rule **FD-005**: a confidence claim without a
justification is an error, not a warning. Include
`confidence_justification` — one sentence on what corroborates the
confidence level — in every `record_finding` call.

## Is this really vibe-coded?

The first integration pass was, and an integrity-review pass on
2026-05-14 (see [CHANGELOG.md](CHANGELOG.md)) caught regressions the
first pass had hidden behind passing tests. The fixes restored strict
provenance, ledger reconciliation, and the FD-005 hard error.

The history is in the changelog; the current code is honest about
what it enforces. The 123 tests gate every change.

## Can I run this on macOS?

The platform-universal modules (forensic, case, report, RAG, triage,
OpenCTI, OpenSearch — **83 tools**: 23 + 15 + 6 + 5 + 11 + 15 + 8)
run on macOS. The platform-gated modules — `sift` (Linux only, 5
tools) and `windows` (Windows only, 9 tools) — don't register on
macOS. For full coverage, run an instance on each target OS and
let the LLM client connect to both; see Multi-Machine Setup in
[guide.md](guide.md).

## How big is the install?

The base pip install is a few hundred MB. Optional baseline databases:

| Asset | Size | How to fetch |
|-------|-----:|--------------|
| RAG ChromaDB index (~23K records) | ~600 MB | `forensic_rag_download()` from your LLM client |
| Triage `known_good.db` + `context.db` (~2.6M records) | ~2 GB | `triage_download()` from your LLM client |

Both are pulled from GitHub releases on demand. Nothing large is
bundled in the pip install.

## Why am I being asked for a password to approve?

By design. The approval gate (DRAFT → APPROVED) is the boundary
between AI suggestion and examiner judgment. The password is verified
with PBKDF2-SHA256 and the approval is signed into an HMAC ledger
(`~/.nexus/verification/`). This is what makes findings traceable
back to a human decision; if the LLM could approve, the provenance
chain would be meaningless.

A 15-minute lockout protects against password brute-force.

## Where do I file bugs / request features?

GitHub Issues on the repository. For security defects see
[SECURITY.md](../SECURITY.md) — don't post those publicly.

## Why not pytest?

The test suites were written as scripts because the script form is
faster to read at a glance and trivial to invoke in CI without
configuration. A pytest migration is welcome — see
[CONTRIBUTING.md](../CONTRIBUTING.md).
