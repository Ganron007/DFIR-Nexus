# DFIR-Nexus v2 — Wiring Plan (single source of truth for build order)

> **Status:** Active plan. This file supersedes `Docs/internal/OLD-VS-NEW.md`,
> `IMPROVEMENT-PLAN.md`, and `COMPARISON.md` as the forward-looking build plan.
> Those documents (plus INTERPRET-HITL-CONTEXT-PLAN, CORPUS-CHECKLIST, and
> point-in-time reports) are archived under
> `Docs/internal/archive/2026-09-v2-transition/` — historical context only,
> do not implement from them.
>
> **Product definition:** `Docs/NEXUS-MODE.md` (Mode 1/2/3 = control-depth
> presets on one Case Analysis Cockpit). Architecture: `Docs/ARCHITECTURE.md`.
> Ship ledger: `Docs/internal/COMPLETE-TO-SHIP.md` (the only file whose `[x]`
> means proved).

---

## 1. Where we are (verified 2026-09-06)

| Area | State |
|------|-------|
| Mode 1 (CLI + Portal) | Wired and demo-verified — ask -> select -> scribe -> DRAFT -> HMAC -> report ran end-to-end on a real EVTX case |
| Mode 2 | Docs only. No iterative query loop, no corroboration engine, no proposal cards |
| Mode 3 | Docs only. No agent tool-selection, no plan-approval prompts, no case-file HMAC |
| Playbooks | Done — 22 playbooks, 341 query terms, 170 caveats, corpus-reviewed |
| UI | Server-rendered HTML cockpit (Explore / Ask / Approve / Findings) — functional, not enterprise |
| N1-N8 spine | Wired and audited; 6 blocking bugs fixed; CI green |
| Setup / deployment | Not release-ready — ES / RAG / embedding model / SIFT are manual prerequisites |
| Plaso | Opt-in env var only (`NEXUS_SIFT_PLASO=1`), not a first-class timeline source |

## 2. Guiding principles

1. **API contracts before UI skin.** The `/portal/api/*` surface is the product;
   the HTML is disposable until Phase 4.
2. **The deterministic spine never changes:** N1-N8, immutable runs, HMAC
   approval, FD-001..007, no-auto-approve — re-asserted in every phase's tests.
3. **One cockpit, three control depths.** Modes 1/2/3 are who-initiates-the-next-action
   presets, not separate products (see `Docs/NEXUS-MODE.md`).
4. **Deterministic fallbacks always.** Every LLM capability keeps a heuristic path.
5. **Smoke tests inside every phase; formal case validation at the end.**
   Integration bugs surface only against real runs (six found in the pre-case audit).

---

## Phase 0 — Foundation hardening

| WP | Item | Exit criteria |
|----|------|---------------|
| 0.1 | README quickstart fix (`--from-case` vs `--case` trap), stale `main.py` docstrings, export/merge double-nesting | Docs match actual CLI |
| 0.2 | SIFT sync kill-switch (`NEXUS_SIFT_SYNC=0`) | Tools lane runs offline-clean, no 2-min scp timeout |
| 0.3 | Cases-root hygiene — archive stale `CASE-*` test dirs | `cases/` holds only real cases |
| 0.4 | Examiner password setup non-interactive option | Approve flow testable headlessly |

**Gate 0:** demo case runs the full loop; CI green.

## Phase 1 — Complete Mode 1 (backend first, then UI surface)

| WP | Item | Notes |
|----|------|-------|
| 1.1 | N4 query DSL: boolean (AND/OR/NOT), column filters (host/user/event-id), regex, aggregations (family/host/hour), cursor pagination | Engine for everything later — do first |
| 1.2 | ES default backend: auto-index after tools lane, staleness detection, CSV fallback | Kills the stale-index footgun |
| 1.3 | Workbench: server-side bookmarks (`workbench.json`), `/portal/workbench`, bookmark -> promote | Replaces client-side-only selection |
| 1.4 | Steer chat v1 + persistence: per-case `chat.jsonl`, audit-logged actions (ask / drill / corroborate-stub) | Transcript survives reload; audit trail for Mode 2 |
| 1.5 | Timeline v2: per-family lanes, brush-to-zoom, click-to-filter | Server-rendered + JS is fine |
| 1.6 | Entity pivot: extract user/host/file/IP/process from hits; click-to-filter | Minimal Socrates-style pivot |
| 1.7 | Report upgrade: audit_ids + file:line as first-class evidence-table columns | Audit-found gap |
| 1.8 | Plaso first-class: auto-suggest on disk image, psort CSV into N3, timeline reads Plaso | Today hidden behind `NEXUS_SIFT_PLASO=1` |

**Gate 1:** full N1->N8 loop drivable UI-only, zero CLI, on the demo case
(checklist pass, 12-pass style).

### Phase 2 — Mode 2: LLM-guided analysis

| WP | Item | Notes |
|----|------|-------|
| 2.1 | Iterative query engine: propose -> validate -> re-query loop with hard caps (max iterations / queries / tokens); every proposal logged | Core Mode 2 loop |
| 2.2 | Corroboration engine: cross-family correlation, FD-006 (single-source stays LOW) | Uses playbook caveats as constraints |
| 2.3 | Proposal protocol: structured cards (query / correlation / DRAFT) with accept / reject / redirect; examiner actions audited | The steering contract |
| 2.4 | LLM-drafted findings with provenance; examiner edits/rejects; HMAC unchanged | Reuses record_finding + FD validation |
| 2.5 | UI: proposal cards in chat, iteration progress, stop button | Same cockpit |

**Gate 2:** Mode 2 demo — every LLM action has an audit_id, examiner rejected at
least one proposal, HMAC gate untouched.

### Phase 3 — Mode 3: Agentic

| WP | Item | Notes |
|----|------|-------|
| 3.1 | ReAct agent over the 115 MCP tools, mandatory-lane-first guard (cannot skip N2) | Absorbs the old plan |
| 3.2 | Plan-approval prompts: agent proposes tool runs/extras; examiner approves before execution | Agent adds parsers, never skips the lane |
| 3.3 | Case-file HMAC option (per-finding HMAC still available) | Per NEXUS-MODE.md |
| 3.4 | Agent run ledger + replay | Every decision stored, replayable |

**Gate 3:** agent completes lane -> extras -> iterative queries -> DRAFT proposals
with an unbroken audit chain; examiner steers only at defined checkpoints.

### Phase 4 — Enterprise UI rewrite
*Only after the API contracts are frozen by three modes of real usage.*

| WP | Item |
|----|------|
| 4.1 | API contract freeze — document every `/portal/api/*` endpoint as stable |
| 4.2 | Framework scaffold (React or Vue) + cockpit shell (nav, case switcher, auth) |
| 4.3 | Explore: virtualized tables (100k+ hits), facets, real histogram |
| 4.4 | Timeline: D3 lanes, brush-zoom, drill-down |
| 4.5 | Steer chat: websocket/SSE streaming, proposal cards, session history |
| 4.6 | Workbench: drag-and-drop finding builder, undo/redo |
| 4.7 | Approve desk + report viewer + admin; parity checklist vs Phases 1-3; retire HTML pages |

**Gate 4:** parity checklist signed off; old HTML pages removed.

### Phase 5 — Deployment & setup revamp (public-release prerequisite)

| WP | Item |
|----|------|
| 5.1 | Interactive setup (Windows/Linux): asks ES on/off + URL, RAG download, embedding model, LLM provider, examiner -> writes `.env`, validates each |
| 5.2 | `nexus doctor` expansion: ES reachable+indexed, RAG index present, model cached, parser binaries on PATH, SIFT reachability (optional) |
| 5.3 | Optional Docker Compose for per-case ES (never the CADRE `.50` SIEM — guard enforced) |
| 5.4 | From-scratch deployment test on a clean machine |
| 5.5 | SETUP.md rewrite + one-page prerequisites ToDo for users |

**Gate 5:** fresh machine -> setup -> demo case -> full Mode 1 loop, no manual env fiddling.

### Phase 6 — Formal case validation
- CADRE Campaign H / ws01 evidence through Mode 1 -> 2 -> 3 sequentially
- `Docs/internal/COMPLETE-TO-SHIP.md` 12-pass ledger updated per gate
- Then: RAG corpus upgrade (deferred) and public-release polish

---

## Order rationale

1. **N4 query DSL first (1.1)** — Mode 2's loop and the enterprise UI both consume
   it; changing it later means rework in three places.
2. **Mode 1 complete before Mode 2** — Mode 2 is Mode 1 + autonomy; gaps inherit.
3. **Mode 3 after Mode 2** — the agent reuses the proposal protocol and corroboration engine.
4. **UI rewrite after Modes 2-3** — the pane map is proven by real usage; the rewrite
   becomes a skin change, not a re-architecture.
5. **Setup revamp before formal validation** — the case test runs the near-production config.
6. **Smoke tests every phase, formal validation last** — integration bugs surface cheaply.

## Top risks

1. **Phase 4 scope creep** — the parity checklist is the defense.
2. **Mode 2 LLM-dependence** — every capability keeps a deterministic fallback.
3. **Invariant erosion** — HMAC / FD-001..007 / no-auto-approve / immutable runs
   re-asserted in every phase's tests. One "convenient" bypass in Mode 3 undermines
   the product.

## Immediate next step

Phase 0 (one session), then **Phase 1.1 (N4 query DSL)** — highest leverage in the
plan: it unblocks the workbench, timeline, Mode 2 iteration, and the enterprise UI
simultaneously.
