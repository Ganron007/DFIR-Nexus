## DFIR-Nexus vs. Upstream — Scope, Parity, and Roadmap

This document is the canonical comparison of **DFIR-Nexus** against the
three upstream projects it consolidates:

- `DFIR-mcp/sift-mcp-main/` — 9 packages: forensic-mcp, case-mcp,
  report-mcp, forensic-rag, opencti, windows-triage, sift-mcp,
  sift-gateway, case-dashboard, plus the `forensic-knowledge` PyPI
  bundle.
- `DFIR-mcp/wintools-mcp-main/` — Windows tool execution server.
- `DFIR-mcp/Valhuntir-main/` — `vhir` CLI: approval / evidence / case
  lifecycle / multi-host setup orchestration.
- `DFIR-mcp/LangGraph_integration/` — a 305-line reference pipeline that
  wires the fleet into a 6-node graph.

The aim is honest: where we are ahead, stay ahead and codify the
advantage; where the upstream is still richer, log it and convert into
a roadmap. **We do not gain anything by overstating parity.**

---

## 1. Project scope (one screen)

| Dimension | Upstream (DFIR-mcp + Valhuntir + wintools) | DFIR-Nexus |
|---|---|---|
| Repos / packages | 3 repos, 11 Python packages | 1 repo, 1 package |
| Processes | 7 MCP servers + 1 gateway + 1 dashboard + CLI | 1 FastMCP process (+ optional dashboard mounted in-process) |
| Knowledge base | `forensic-knowledge` PyPI package | 91 YAML files vendored under `src/nexus/knowledge/data/` |
| LLM orchestration | Reference 6-node LangGraph pipeline (305 lines, generic) | First-party 6-node LangGraph pipeline (541 lines) with `_REQUIRED_TOOLS` boot validation, MCP transport auto-detect, and approval-file fallback |
| Multi-host fan-out | `sift-gateway` REST + auth + rate limit + join protocol | `nexus setup client` generator → LLM client connects to *N* nexus instances directly |
| Approval surface | CLI (`vhir approve`) + Examiner Portal `/api/commit` HMAC challenge | CLI (`nexus approve`) + Portal `/portal/api/commit` HMAC challenge (parity — Web Crypto in browser, HMAC ledger identical) |
| CLI surface | 38 top-level `vhir` commands | 19 top-level `nexus` commands (12 groups + 6 direct + reopen) |
| Knowledge tools | 14 discipline tools in forensic-mcp | 14 discipline tools (parity) |
| Total MCP tools | ~83 across 7 servers | 97 in one server (parity + 8 OpenSearch + 6 extras) |

The headline trade we made: **fewer moving parts, the same tool count,
broader knowledge surface, with one process to operate**. The
upstream-only feature gap that mattered most (browser-based approval
via `/api/commit`) was closed by `/portal/api/commit` — see §4 item 12
and §5.1.

---

## 2. Tool-surface parity (MCP)

Numbers below come from grepping `@server.tool()` / `name="..."` in
the upstream sources against `src/nexus/tools/*` and
`src/nexus/triage/server.py`.

| Source | Upstream tools | Nexus tools | Status |
|---|---:|---:|---|
| forensic-mcp (findings, timeline, todos, 14 discipline) | 23 | 23 | **Parity** |
| case-mcp (case lifecycle, evidence, export/import, audit, reasoning, dashboard) | 15 | 15 | **Parity** |
| report-mcp (generation, profiles, metadata) | 6 | 6 | **Parity** — + ledger reconciliation (§4) |
| forensic-rag | 3 (`search_knowledge`, `list_knowledge_sources`, `get_knowledge_stats`) | 5 (+ `forensic_rag_download`, full response envelope) | **Ahead** |
| opencti | 8 (`get_health`, `search_threat_intel`, `search_entity`, `lookup_ioc`, `get_recent_indicators`, `get_entity`, `get_relationships`, `search_reports`) | 11 (+ 3 convenience wrappers: `search_threat_actor`, `search_malware`, `search_mitre_technique`) | **Ahead** |
| windows-triage | 13 (`check_file`, `check_process_tree`, `check_service`, `check_scheduled_task`, `check_autorun`, `check_registry`, `check_hash`, `analyze_filename`, `check_lolbin`, `check_hijackable_dll`, `check_pipe`, `get_db_stats`, `get_health`) | 15 (13 + `triage_status` + `triage_download`) | **Ahead** |
| sift-mcp (Linux exec) | 5 (`list_available_tools`, `get_tool_help`, `check_tools`, `suggest_tools`, `run_command`) | 5 | **Parity** (Linux only — gated) |
| wintools-mcp | 10 (`scan_tools`, `list_windows_tools`, `list_missing_windows_tools`, `check_windows_tools`, `get_windows_tool_help`, `suggest_windows_tools`, `get_share_info`, `list_kape_targets`, `batch_scan`, `run_windows_command`) | 9 (parity minus `get_share_info` — not needed without SMB) `suggest_windows_tools` is ported | **Parity** (minus SMB-specific tool) |
| OpenSearch | — | 8 (`idx_ingest`, `idx_search`, `idx_aggregate`, `idx_timeline`, `idx_enrich_triage`, `idx_enrich_intel`, `idx_status`, `idx_case_summary`) | **Net-new (ours)** |

**Net:** ~83 upstream → **97** nexus tools. No upstream MCP tool is
missing; the 8 OpenSearch tools and the download/status tools on RAG
and triage are additive. `suggest_windows_tools` is functionally
covered by `suggest_tools` for the cross-platform path.

---

## 3. Data and control flow

### 3.1 Provenance chain (the core flow)

Both projects implement the same conceptual chain:
`tool execution → audit_id → record_finding(artifacts=[{audit_id}]) →
approve (HMAC ledger) → generate_report`.

Where they differ:

| Step | Upstream | DFIR-Nexus |
|---|---|---|
| Where audit logs live | `~/.sift/` per server, plus `~/.vhir/cases/<id>/audit/` | `~/.nexus/cases/<id>/audit/<mcp>.jsonl` — single hierarchy |
| `record_finding` rejects bad audit_ids | Yes (`forensic_mcp/case/manager.py:795`) | Yes — now enforced in `case_manager.py:325` after the integrity-review pass |
| `confidence_justification` enforcement | FD-005 error | FD-005 error (matched) |
| Cross-process audit visibility | Requires every server to know shared `audit_dir` | Single process, single resolver in `audit.py:_get_audit_dir()` |
| Approval signing | HMAC via `vhir_cli/verification.py` | HMAC via `nexus.auth.write_verification_entry` (same key derivation) |
| Ledger reconciliation in reports | Implicit | Explicit — `report.py:_reconcile_verification` surfaces `APPROVED_WITHOUT_LEDGER` and `LEDGER_WITHOUT_APPROVAL` as `verification_alerts` |

**Verdict:** Same semantics, our path is tighter (one process, one
audit hierarchy) and our report layer surfaces ledger drift, which
upstream did not.

### 3.2 Transport / fan-out

```
Upstream                                  Nexus
──────────                                ─────
LLM ──► sift-gateway :4508                LLM ──► nexus (SIFT)  :4508
        ├─► sift-mcp        (stdio)               nexus (Win)   :4508
        ├─► forensic-mcp    (stdio)               nexus (REMnux):4508
        ├─► case-mcp        (stdio)
        ├─► report-mcp      (stdio)       Client config from
        ├─► forensic-rag    (stdio)       `nexus setup client --sift … --windows …`
        ├─► opencti         (stdio)
        └─► windows-triage  (stdio)       Each nexus exposes /mcp + /portal
                                          on its own host.
```

Upstream's gateway pattern is **stronger when you want a single
endpoint** the LLM client knows: it terminates auth, rate-limits per
IP, and brokers across multiple backend servers from one URL. Ours is
**stronger when you want fewer moving parts**: the LLM client knows
each host directly, no broker to maintain, and platform-gating happens
at registration.

This is a real architectural choice, not a clear win for either side.
See §5 — we should ship an optional gateway mode to cover the centralised
deployment story without losing the simple direct mode.

### 3.3 Approval flow

```
Upstream                                  Nexus
──────────                                ─────
Examiner Portal /api/commit/challenge     CLI: `nexus approve`
  ↓ HMAC(password_hash, challenge)        Portal: read-only (today)
/api/commit  ─► HMAC ledger entry
                                          HMAC ledger entry is byte-equivalent.
CLI also supports: `vhir approve`         CLI is the only signed-write path today.
```

The upstream **dashboard does signed writes in the browser**
(`get_commit_challenge` / `post_commit` in
`case_dashboard/routes.py:1215+`). That is the most visible feature
gap. The HMAC primitives we already have (`nexus.auth.compute_hmac`,
`write_verification_entry`) are the same as upstream's — we just don't
expose them via an HTTP endpoint yet.

### 3.4 LangGraph orchestration

| Aspect | Upstream reference | DFIR-Nexus pipeline |
|---|---|---|
| File / size | `LangGraph_integration/pipeline.py` — 305 lines | `langgraph/pipeline.py` — 541 lines |
| MCP transport | Reads `VHIR_MODE=lite|full` → either 5 stdio subprocesses or one HTTP URL | Reads `NEXUS_GATEWAY_URL` → HTTP, else single stdio `nexus serve` |
| Tool resolution | `MultiServerMCPClient`, no validation | `MultiServerMCPClient` + `_REQUIRED_TOOLS` boot check; logs missing tools |
| Nodes | 6 (`register_evidence`, `scope`, `hunt`, `stage_findings`, `await_approval`, `generate_report`) | Same 6 nodes, named identically |
| `stage_findings` body | Placeholder with `title="Suspicious activity (placeholder)"` | Same — also a placeholder; the hunt agent is supposed to emit candidates |
| Resume after approval | Caller passes JSON resume payload by hand | Auto-recovers approved IDs by reading `<case>/approvals.jsonl` if the resume payload is empty |
| Checkpointer | `AsyncSqliteSaver` from sqlite.aio | `AsyncSqliteSaver` from sqlite |
| Model selection | env `VHIR_MODEL` (anthropic / ollama / openai) | env `NEXUS_MODEL`, same three providers |

**Verdict:** structural parity, two concrete advantages on our side
(boot-time tool validation; ledger-aware resume). The shared weakness
is `stage_findings` — both pipelines stage a placeholder rather than
loop the hunt agent's structured output. This is the single highest-
leverage LangGraph improvement available (§5).

---

## 4. What we already do better

1. **One process, one audit hierarchy.** Whole-fleet provenance is
   coherent without coordinating an `audit_dir` env var across seven
   servers. (`src/nexus/audit.py`)
2. **Knowledge base is vendored.** 91 YAML files under
   `src/nexus/knowledge/data/` instead of an external PyPI dependency.
   No drift between server version and knowledge version.
3. **Ledger reconciliation on report generation.** `report.py` raises
   `verification_alerts` for findings approved without a ledger entry
   (or ledger entries with no approved finding). Upstream's report
   path does not surface this.
4. **OpenSearch tool-set (net-new).** 8 tools (`idx_ingest`,
   `idx_search`, `idx_aggregate`, `idx_timeline`, `idx_enrich_triage`,
   `idx_enrich_intel`, `idx_status`, `idx_case_summary`) the upstream
   never shipped. Real query DSL, term aggregations, date histograms.
5. **Triage and RAG ship with `*_download` tools.** Pre-built baseline
   databases and the ChromaDB index can be pulled from GitHub releases
   without writing scripts.
6. **LangGraph pipeline validates the tool list at boot.** Missing
   required tools log a warning before the graph runs, not when the
   first node fails.
7. **LangGraph pipeline auto-recovers approval state.** If the user
   forgets the `--resume` payload, we read `<case>/approvals.jsonl`
   and reconstruct it. Upstream errors out.
8. **Stricter `record_finding` semantics.** Findings are now rejected
   when no audit_id can be verified in the active case, even when
   artifacts are attached (the upstream behaviour we accidentally
   weakened and have since restored — see CHANGELOG 2026-05-14
   "Integrity review pass").

9. **Password rotation (reset-password).** `nexus config --setup-password`
   detects existing passwords and offers rotation; verifies current password,
   hashes new password, re-signs all HMAC verification ledger entries.
   The upstream had this feature; we now match it.

10. **Conflict detection in `record_finding`.** When a new finding would
    contradict an existing APPROVED finding (same host, same time window,
    incompatible type/confidence), the response includes a `conflicts_with`
    field describing the conflict. The upstream did not have this — it's an
    **original advantage**.

11. **Corroboration suggestions on weak provenance.** When `record_finding`
    returns a provenance grade of NONE or PARTIAL, and a finding type is
    specified, the response includes `corroboration_suggestions` from the
    knowledge base. The upstream had the FK data but didn't wire it into
    `record_finding`.

12. **Browser-based approval (Portal `/api/commit`).** The Examiner Portal
    now supports the full challenge-response commit workflow from the
    upstream: `GET /portal/api/commit/challenge` issues a nonce + salt,
    the browser HMACs with the PBKDF2-derived key via Web Crypto API,
    `POST /portal/api/commit` verifies the HMAC, approves findings, and
    writes the HMAC verification ledger. Lockout after 3 failures. This
    closes the only upstream feature gap in the approval surface.

13. **Portal REST API (JSON).** 8 JSON endpoints at `/portal/api/*`:
    `findings`, `timeline`, `evidence`, `iocs`, `todos`, `audit/{id}`,
    `summary`, `transparency`. The upstream had these; we now match.

14. **Granular service control.** `nexus service start/stop/restart <name>`
    with a configurable service registry in `~/.nexus/services.json`.

15. **OpenTelemetry tracing.** `nexus/telemetry.py` with `trace_tool_call()`
    context manager. Enabled via `NEXUS_OTEL_ENABLED=true`.

16. **Hash-chained transparency log.** `nexus/transparency.py` appends every
    commit to a hash chain (`previous_hash` → `hash`). `transparency_verify()`
    walks the chain and detects tampering. The upstream did not have this.
    Portal has `/portal/api/transparency` endpoint.

17. **Encrypted case bundles.** `nexus export --encrypt` and
    `nexus merge --decrypt` with PBKDF2 + Fernet (requires `cryptography`).

18. **LangGraph `stage_findings` loops real hunt output.** `_parse_hunt_candidates()`
    extracts structured findings from hunt agent messages (JSON + markdown code blocks).
    Loops `record_finding` over each. Falls back to placeholder if none found.

---

## 5. What upstream still does better — and our plan

These are concrete deficits. Each has an owner-able next step.

### 5.1 ~~Browser-side approval (Portal `/api/commit`)~~ — **Done**

Upstream: `case_dashboard/routes.py:1215` issues a `commit_challenge`,
the browser HMACs it with the examiner password hash, posts to
`/api/commit`, the server writes the HMAC ledger entry.

**Status — done.** `src/nexus/dashboard/app.py` ships
`GET /portal/api/commit/challenge` (nonce + salt) and
`POST /portal/api/commit` (HMAC verification → approve findings →
write HMAC ledger entry). `/portal/approve` is the HTML page that
performs PBKDF2 + HMAC in the browser via Web Crypto, so the password
is never sent to the server. Lockout after 3 failed attempts.
Captured as §4 item 12.

### 5.2 Gateway mode (single endpoint with auth + rate limit) — **MEDIUM**

Upstream: `sift-gateway` provides a single bearer-token-authenticated
HTTP endpoint that fans out to multiple backend MCP servers, with a
60 req/min sliding-window per-IP rate limiter and a join protocol for
distributing tokens.

Ours: each `nexus serve --http` instance is its own endpoint. There is
no built-in rate limiter and no fleet-wide join.

**Plan:** add an optional `nexus gateway` command that mounts the same
ASGI app but proxies `/mcp` to a configurable list of nexus instances,
reuses `nexus.auth` for bearer auth, and includes a sliding-window
rate limiter copied from `sift-gateway/rate_limit.py`. Roadmap P1-2.

### 5.3 ~~Dashboard REST API~~ — **Done (delta editing still deferred)**

Upstream's case-dashboard exposes 19 routes including:

- `GET /api/findings`, `/api/findings/{id}`, `/api/timeline`,
  `/api/evidence`, `/api/iocs`, `/api/todos`, `/api/summary`
- `GET /api/audit/{finding_id}` — provenance chain viewer
- `GET /api/delta`, `POST /api/delta`, `DELETE /api/delta/{id}` —
  examiner annotations layered on top of case data
- `POST /api/evidence/{path}/verify` — re-hash from the portal

**Status — JSON API done.** 8 endpoints under `/portal/api/*`:
`findings`, `timeline`, `evidence`, `iocs`, `todos`,
`audit/{finding_id}`, `summary`, `transparency`. Captured as §4
item 13.

Still missing: **delta editing** (`GET/POST/DELETE /api/delta`) and
**evidence re-verify from portal** (`POST /api/evidence/{path}/verify`).
Low priority — examiners can `nexus evidence verify` from the CLI;
delta annotations could ride on top of TODOs for now. Re-open as a
frontier item if the workflow demands it.

### 5.4 Valhuntir CLI commands we did not port — **LOW**

`vhir` exposes 38 top-level commands; `nexus` exposes 19. Still missing:

- `vhir join` / `vhir join-code` — token-distributed remote setup.
  Belongs with the gateway story (5.2); deferred with that work.
- `vhir migrate` / `vhir prune-manifests` — case-format migration. Low
  priority until we ship a v2 case schema.
- ~~`vhir reset-password` — password rotation.~~ **Done** — `nexus config --setup-password` detects existing password and offers rotation; re-signs HMAC ledger.
- ~~`vhir reopen` — re-open a closed case.~~ **Done** — `nexus case reopen`.
- ~~`vhir start` / `vhir stop` / `vhir restart` (per-service) — granular
  service control.~~ **Done** — `nexus service start/stop/restart <name>`
  honours a per-name `~/.nexus/services.json` registry; PID-file tracked
  per service so you can bounce one backend without taking the others
  down. See `src/nexus/cli/service.py`.

**Plan:** nothing actionable left in §5.4. `join` / `migrate` stay
deferred behind §5.2 (gateway) and a v2 case schema, both intentional
scope choices, not unmet commitments.

### 5.5 OpenCTI client resilience — **LOW**

Upstream `opencti` package wraps pycti in a 112KB `OpenCTIClient` with
circuit breakers, rate limiting, and adaptive metrics. We call pycti
directly. For lab use this is fine; for a production SOC pulling
threat intel constantly, it is not.

**Plan:** roadmap P2 — wrap pycti calls in a small retry/backoff
helper. Full circuit-breaker port is overkill for our current scale.

### 5.6 LangGraph `stage_findings` is still a placeholder — **HIGH**

Both pipelines short-circuit `stage_findings` to a synthetic finding.
The hunt agent's structured output is dropped on the floor.

**Plan:** make `hunt` emit a list of `FindingCandidate` dicts into
state; `stage_findings` loops `record_finding` over them; downgrade
candidates whose audit IDs do not verify rather than silently dropping
them. Roadmap P0 — this is the single biggest LangGraph win because
it makes the pipeline actually useful for triage, not just a demo.

---

## 6. Improvement opportunities (beyond parity)

Things that would put us decisively ahead of any forked version of
the upstream:

### 6.1 LangGraph-first features
- **Streaming progress over MCP.** Pipeline nodes are async; expose
  intermediate state via MCP server-sent events so the LLM client can
  show "scoping → hunting → staging" without polling.
- **Parallel hunt sub-agents.** Replace the single `create_react_agent`
  in `hunt` with a fan-out: one sub-agent per host or per artifact
  type, joined back in `stage_findings`. LangGraph's `Send` API is
  built for this.
- **Plan validation node.** Before `hunt`, add a `plan` node that
  emits an investigation plan as structured output, validates each
  step references a real tool, and lets the human approve the *plan*
  rather than the findings. Cheaper to course-correct early.
- **Cost/latency dashboard.** Capture token counts and node latencies
  in `step_log`; surface them in the portal. Examiners learn which
  prompts are expensive.

### 6.2 Forensics correctness
- **Conflict detection in `record_finding`.** If a new finding
  contradicts an existing APPROVED one (same host, same time window,
  inconsistent verdict), surface a `conflicts_with` field instead of
  silently appending.
- **Auto-corroboration suggestions.** `_score_provenance` already
  classifies sources; extend it to suggest a corroborating tool when
  grade is `PARTIAL`. The knowledge base has `get_corroboration_suggestions`
  — wire it into the response.
- **Evidence chain-of-custody timeline.** Render the audit JSONL as a
  per-evidence timeline in the portal, not just per-case.

### 6.3 Operational
- **Sigstore-style transparency log.** Mirror the HMAC ledger to a
  hash-chained append-only log so a tampered case directory is
  detectable without trusting `~/.nexus/verification/`.
- **Encrypted at-rest case bundles.** `nexus export` writes plain
  JSON; offer `--encrypt` with a passphrase or recipient key.
- **OpenTelemetry traces.** One span per MCP tool call, with the
  `audit_id` as the trace attribute. Drops into any SOC observability
  stack.

### 6.4 Community / DX
- **Replayable demo case.** Ship a tiny synthetic evidence bundle
  (one MFT, one EVTX, one prefetch) that ends with a clean approved
  report. Lowers the activation cost for security students.
- **`nexus init` quickstart.** Today the quickstart is `serve` →
  `case_init`. A `nexus init` that runs the connectivity test,
  downloads the small baselines, and prints the LLM config snippet
  would cut onboarding to one command.
- **Per-tool examples in the help text.** Most MCP tools have one-line
  docstrings. Where the call is non-obvious (e.g. `idx_search` query
  DSL), include a worked example in the description.

---

## 7. Status tracker — what shipped, what's deferred, what's frontier

The original parity roadmap (P0–P3 items derived from §5) is complete: every
upstream-vs-nexus gap is either closed or has an explicit deferral with a
named reason. What remains is the **frontier** documented in §6 — beyond-parity
opportunities that would put us decisively ahead. Nothing here is a regression
or an unmet commitment; the "Not started" rows are next-leverage work, not debt.

**Shipped (closed parity gaps + original advantages):**

| §ref | Item | Effort | Notes |
|------|------|--------|-------|
| 5.1  | Browser-side approval (Portal `/api/commit`) | M | §4 #12 |
| 5.3  | Portal REST API (JSON endpoints) | M | §4 #13 |
| 5.4  | `nexus case reopen` | S | §4 #9 family |
| 5.4  | Password rotation + HMAC ledger re-sign | S | §4 #9 |
| 5.4  | Granular per-service start/stop/restart | S | §4 #14 |
| 5.6  | LangGraph `stage_findings` parses hunt output | M | §4 #18 |
| 6.2  | Conflict detection in `record_finding` | S | §4 #10 |
| 6.2  | Corroboration suggestions in `record_finding` | S | §4 #11 |
| 6.3  | Hash-chained transparency log | M | §4 #16 |
| 6.3  | Encrypted at-rest case bundles (`--encrypt`) | S | §4 #17 (now in `[encrypt]` extra, included in `[all]`) |
| 6.3  | OpenTelemetry tracing | S | §4 #15 |
| —    | Claude Code skill bundle (lite + full) | M | net-new: one-MCP allowlist, cross-platform hooks, slash commands, case templates |
| —    | OS-native setup scripts (`setup-linux.sh` / `-macos.sh` / `-windows.ps1`) | S | net-new: one-command install + examiner + password + `nexus init` |
| —    | MkDocs Material docs site + GitHub Pages workflow | S | net-new: publishes `Docs/` on every push to `main` |

**Deferred (intentional, with named reason):**

| §ref | Item | Reason |
|------|------|--------|
| 5.2  | Gateway mode (single endpoint + rate limit + fan-out) | Architectural choice — direct multi-server is simpler and we have no current SOC-scale deployment. Revisit when fleet size or rate-limit needs justify the proxy. |
| 5.3  | Dashboard delta editing (`/api/delta` CRUD) | Low priority — examiner annotations can ride on TODOs for now. Re-open if a workflow specifically demands layered annotations on top of case data. |
| 5.4  | `vhir join` / `join-code` | Couples to §5.2; ship together. |
| 5.4  | `vhir migrate` / `prune-manifests` | Wait for v2 case schema. |
| 5.5  | Full OpenCTI circuit-breaker port | Overkill for lab use. Small retry/backoff wrapper is enough; revisit if production SOC needs surface. |

**Frontier (beyond-parity opportunities from §6, ordered by leverage):**

| §ref | Opportunity | Effort | Status |
|------|-------------|--------|--------|
| 6.1  | Parallel hunt sub-agents with `Send` fan-out | M | Not started — sequential hunt works for current scale |
| 6.1  | Plan validation node (examiner approves plan, not findings) | M | Not started |
| 6.1  | Streaming progress over MCP server-sent events | M | Not started |
| 6.1  | Cost/latency dashboard in portal | M | Not started |
| 6.2  | Evidence-level chain-of-custody timeline in portal | S | Not started |
| 6.4  | Replayable demo case (synthetic MFT/EVTX/prefetch) | S | Not started |
| 6.4  | Per-tool worked-example docstrings | S | Partial — key tools updated; long tail remains |

Effort key: **S** = under a day, **M** = 1–3 days, **L** = a week+.

When a frontier item ships, move its row up into "Shipped" and add the
matching §4 entry with a one-line note.

---

## 8. Where to read more

- Per-fix history of the integration: [CHANGELOG.md](./CHANGELOG.md)
- Architecture diagrams and provenance chain: [ARCHITECTURE.md](./ARCHITECTURE.md)
- LangGraph node design and run modes: `langgraph/LANGGRAPH_INTEGRATION.md`
- Examiner workflow: [guide.md](./guide.md)

This document is the authoritative parity tracker. When a roadmap item
ships, move it out of §7 and into §4 with a one-line note.
