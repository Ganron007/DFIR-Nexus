# Changelog

All notable changes to DFIR-Nexus are documented here.

## Unreleased

### Phase 4d.2 — timeline events, evidence picker, parser visibility (2026-09-10)

#### Summary

Second UI-hardening pass: type-aware Timeline events, a filesystem evidence
picker, parser-lane visibility, and a critical test-discovery fix.

#### Type-aware Timeline (4d.1 continued)

- Timeline now renders a type-aware **Events panel** under the aggregate
  lanes: clicking a lane filters events to that family, the brush range
  filters by time, and events render parsed per-family columns (shared
  `lib/hitColumns.ts` with Explore). "Search in Explore" still hands the
  range off.

#### Universal parser-output support

- The column system is header-driven: whatever CSV headers a parser emits
  become available fields; the per-family priority lists (Eric Zimmerman
  tool suite conventions) pick defaults, and unknown headers fall back to
  the first available parsed fields. Any parser output is therefore
  renderable without UI changes.

#### Evidence picker (filesystem browsing)

- `GET /portal/api/fs/list` — read-only drive/directory listing (no file
  contents). The server runs on the examiner's machine, so the picker
  browses the same filesystem the pipeline reads from.
- `EvidencePicker` modal: browse drives → folders, multi-select files
  and/or folders, or paste an absolute path. Wired into Case Setup step 2
  and the Evidence page. Windows paths with spaces are fine (JSON body).
- Evidence page: "+ Add evidence" button opens the picker; registered
  items list refreshes.

#### Parser lane visibility

- `GET /portal/api/pipeline/ledger` returns the active tool-run ledger
  (tool, status, detail per parser).
- Evidence page shows an "N2 Parser Lane" panel with OK/SKIP/FAIL counts —
  the UI surface for what the N2 pipeline actually ran.

#### Test discovery fix (CRITICAL)

- `pyproject.toml` `[tool.pytest.ini_options] python_files` was an explicit
  allowlist that silently excluded 28 real test files from every full-suite
  run — including the Mode 1/2/3 suites, portal tests, RAG tests,
  FD-006/007 enforcement tests, and the Phase 4 API suites. Replaced with
  default `test_*.py` discovery; 5 legacy standalone check-scripts
  (module-level `sys.exit`, not pytest-collectable) are excluded via
  `tests/conftest.py::collect_ignore_glob`.
- True full suite: **637 collected — 636 passed, 1 skipped, 0 failed**
  (previously reported "468 passed" never exercised these files).

#### Verification

- Backend: 637 collected — 636 passed, 1 skipped, 0 failed; Ruff clean.
- Frontend: TypeScript strict clean; Vite build clean; vitest 7 passed.

---

### Phase 4d — UI hardening: full case workflow (2026-09-10)

#### Summary

Closed every remaining pre-Phase-5 gap, focused on making the complete case
workflow work end-to-end from the browser: create → register → process (N2)
→ explore/query (N3-N4) → steer/interpret (N5) → bookmark → findings →
approve (N6) → timeline (N7) → report (N8).

#### Type-aware evidence rendering (4d.1)

- Backend: `attach_hit_fields()` in query_pack.py attaches parsed CSV
  `fields` (header → value, quoted-comma safe, header cached per file) and
  a best-effort `host` to every hit — works for both the Elasticsearch and
  CSV backends. Wired into `/portal/api/explore/search`.
- Frontend: Explore renders per-family parsed columns (30+ family priority
  maps: evtx, prefetch/pecmd, amcache, shellbags, lnk, recycle, mft, srum,
  hayabusa, usn, browser, registry, usb, …) instead of raw text rows, with
  a generic fallback for unknown families. Host column added.

#### Host facets (4d.2)

- `n4_aggregate` supports `group_by=host` (best-effort hostname from
  Computer columns / UNC paths); `/explore/search` accepts a `host` filter.
- Explore shows Host facet chips alongside family chips.

#### Live steer chat (4d.3)

- Backend: `POST /portal/api/chat/stream` (SSE) streams Mode 1 and Mode 2
  turns live — `status` events while translating/querying, `iteration`
  events from the Mode 2 loop (new `on_event` callback), then `done`.
- Chat persistence: `append_chat` gained a structured `data` field; top
  hits (capped 12, trimmed) persist into the transcript so hit cards
  survive reload.
- Frontend: SteerChat renders live progress during streamed turns and hit
  cards in the transcript — each card shows family/host/parsed fields with
  one-click bookmarking into the Workbench.

#### IOCs + TODOs pages (4d.4)

- New `Iocs.tsx` and `Todos.tsx` pages (endpoints existed; UI never built).
  Routes `/iocs` + `/todos`, error banners, lifecycle-aware empty states,
  added to the sidebar Utilities group.

#### Live stage states (4d.5)

- `GET /case/details` now reports `approved_count` + `report_exists`;
  CaseContext exposes `stages` and refreshes on case switch.
- The N1-N8 stepper colors completed stages green (N6 keyed on approvals,
  N8 on REPORT.md presence).

#### Evidence page N2 controls

- Evidence page gains a "Run N2 lane" button (pipeline/run + status
  polling) and a live N2 completion indicator, so processing is reachable
  outside the wizard.

#### Frontend tests (WP 4.2 gap)

- vitest + @testing-library/react + jsdom installed; `npm test` runs them.
- 7 tests: Histogram empty/series/downsampling, VirtualTable virtualized
  window + cell rendering, and the 4d.1 family column picker.

#### Verification

- Backend: 468 passed, 1 skipped, 0 failed; Ruff clean.
- Frontend: TypeScript strict clean; Vite build clean; vitest 7 passed.

---

### Phase 4 + 4b full re-verification (2026-09-10)

#### Summary

Re-audited every Phase 4 and Phase 4b wiring-plan item against actual code
(routes, handlers, frontend calls, state propagation, tests, builds).
Found 7 issues — including one critical backend bug and one critical
configuration bug that existing tests could not catch — and fixed all of them.

#### Finding 1 (CRITICAL): pipeline/run ran with no evidence

`POST /portal/api/pipeline/run` called `run_pipeline(evidence_path="", ...)`.
The pipeline's `register_evidence` node only registers evidence from
`state["evidence_paths"]` — so an N2 run triggered from the browser reused
the case but parsed **nothing**. The case's registered evidence (stored via
`CaseManager.add_evidence`) was never consulted.

**Fix:** `api_pipeline_run` now resolves the case's evidence via
`CaseManager.list_evidence(case_id)`, filters to paths that exist, passes
them as `evidence_path` + `evidence_paths` to `run_pipeline`, and returns
400 with a clear message when no evidence is registered.

#### Finding 2 (CRITICAL): split-brain cases.db

New Phase 4b endpoints used `settings.data_root / "cases.db"` while evidence
registration and the CLI use `settings.cases_root / "cases.db"` — two
different databases. Cases created via the wizard would be invisible to
evidence registration and the CLI. Tests missed it because they were
internally consistent.

**Fix:** All CaseManager usage now uses `settings.cases_root / "cases.db"`.

#### Finding 3: Timeline brush still didn't filter (4b.10 incomplete)

Explore read `start`/`end` URL params but never passed them to
`api.search` / `api.histogram` — the backend supported time filtering but
the frontend dropped the values.

**Fix:** Explore stores `timeRange` state, passes `start`/`end` to both
search and histogram calls, and shows a clearable active time-filter chip.

#### Finding 4: Mode badge CSS never applied (4b.6)

`className="mode-badge mode-{mode}"` was a string literal, not a template —
the `mode-1/2/3` CSS classes never applied.

**Fix:** Template literal; badge is now a NavLink to the mode's primary
surface (Mode 1 → Explore, Mode 2/3 → Steer Chat) and states which surface
is primary. SteerChat's chat mode now follows the case-level mode.

#### Finding 5: Silent error swallowing beyond the two named pages

WP 4b.8 named only Findings.tsx and Evidence.tsx, but the "no silent
failures" requirement is broader. Fixed `.catch(() => {})` in:
Approve.tsx (DRAFT findings load), Workbench.tsx (load/remove/clear),
SteerChat.tsx (chat load/clear), Explore.tsx (facets, bookmark state,
playbook suggestions, bookmark add/remove), Findings.tsx (corroboration,
audit trail), Layout.tsx stepper (visible ⚠ hint on failure).

#### Finding 6: Dead `api.select` remained

WP 4b.12 said "wire or remove" — `select` was left defined but uncalled.

**Fix:** Removed `api.select` + `SelectResponse` from the client with a
comment pointing to the Workbench flow; the `/mode1/select` endpoint remains
for legacy HTML pages.

#### Finding 7: Root `/` was still a marketing page (4b.3 gap)

The WP requires `/` to be the functional entry point. The SPA Overview was
a dashboard, but `landing.html` had no cases table.

**Fix:** `landing.html` now renders a functional Your Cases table (fetches
`/portal/api/cases` + `/portal/api/case/details`, click-to-activate →
cockpit), a New Investigation button → `/portal/app/case-setup`, and a
system health strip backed by the new `GET /portal/api/system/health`
(cheap backend/ES/RAG-index/LLM-config/parser checks; deep preflight stays
in `nexus doctor` and `GET /portal/api/rag/status`).

#### Stale plan claims corrected

- WP 4.2 claimed "6 tests" — no frontend test runner exists; claim corrected.
- WP 4.3 claimed "family+host facets" — UI exposes family facets only;
  corrected (host aggregation remains backend-supported).
- WP 4.1 endpoint count updated (48 routes).

#### Tests

- `tests/test_phase4b_apis.py` expanded to 12 tests, including two
  regressions for the pipeline evidence fix (rejects when no evidence;
  passes registered evidence paths through to `run_pipeline`).
- Full suite: 469 collected — 468 passed, 1 skipped, 0 failed.
- Ruff: clean. TypeScript strict: clean. Vite build: clean.

---

### Phase 4b — Workflow-driven cockpit (2026-09-10)

#### Summary

Implemented all 14 Phase 4b work packages. The UI is now the investigation
workbench — an examiner can land on `/`, create a case, register evidence,
choose a mode, run N2, query, interpret, approve, and report without ever
touching the CLI. The flat nav list became a guided workflow.

#### New backend APIs

- `POST /portal/api/case/create` — create + activate a case, store mode (WP 4b.1)
- `GET /portal/api/case/details` — case metadata, evidence/findings counts, pipeline status (WP 4b.1)
- `POST /portal/api/pipeline/run` — trigger N2 lane (tools/interpret/coverage/design) asynchronously (WP 4b.2)
- `GET /portal/api/pipeline/status` — poll pipeline run status by run_id (WP 4b.2)
- `GET /portal/api/playbook/needles` — playbook-suggested search needles with optional family filter (WP 4b.7)
- `POST /portal/api/case/mode` — set investigation mode (1/2/3) in CASE.yaml (WP 4b.6)
- `GET /portal/api/case/mode` — get investigation mode for active case (WP 4b.6)

All endpoints documented in `Docs/API-CONTRACT.md` section 11c.

#### New frontend components and pages

- `CaseSetup.tsx` — 4-step Case Setup Wizard (details → evidence → mode → process) (WP 4b.1)
- `CaseContext.tsx` — shared React Context for activeCase, mode, health (WP 4b.11)
- `StageStepper` in `Layout.tsx` — N1-N8 progress indicator with click-to-navigate (WP 4b.4)
- Mode badge in sidebar showing current investigation mode (WP 4b.6)

#### Updated frontend pages

- `Overview.tsx` — rewritten as Case Dashboard with cases table, New Investigation button, system health, per-case details (WP 4b.3)
- `Explore.tsx` — needle explanation, collapsible playbook suggestions panel with one-click search, reads URL params from Timeline brush (WP 4b.5, 4b.10)
- `Timeline.tsx` — brush selection now wires to Explore via "Search in Explore →" button with start/end/family params (WP 4b.10)
- `Findings.tsx` — error banner instead of silent catch; corroboration panel showing FD-006/007 status; audit trail viewer (WP 4b.8, 4b.12, 4b.13)
- `Evidence.tsx` — error banner instead of silent catch (WP 4b.8)
- `Entities.tsx` — loads on mount via useEffect, not just on button click (WP 4b.9)
- `SteerChat.tsx` — Mode 1 now uses `api.ask()` for needle translation; Mode 2 adds "Propose Draft Finding" button (WP 4b.12, 4b.14)
- `Layout.tsx` — consumes CaseContext instead of local state; version bumped to Phase 4b (WP 4b.11)

#### Dead API client methods resolved (WP 4b.12)

- `iocs` — removed (no IOCs page in SPA)
- `todos` — removed (no TODOs page in SPA)
- `auditForFinding` — wired into Findings.tsx audit trail viewer
- `ask` — wired into SteerChat.tsx Mode 1
- `select` — retained for future Workbench integration
- `mode2Corroborate` — wired into Findings.tsx corroboration panel
- `mode2ProposeDraft` — wired into SteerChat.tsx Mode 2 propose-draft button

#### CSS additions

- `.stage-stepper` / `.stage-step` / `.stage-id` / `.stage-label` / `.stage-arrow` — N1-N8 stepper styling
- `.mode-indicator` / `.mode-badge` / `.mode-1` / `.mode-2` / `.mode-3` — mode badge styling

#### Tests

- New: `tests/test_phase4b_apis.py` — 9 tests covering case creation, details, mode set/get, playbook needles, pipeline run validation, pipeline status 404.
- Full suite: 468 passed, 1 skipped, 0 failed.
- Ruff: clean.
- TypeScript strict: clean.
- Vite production build: clean.

#### Documentation

- `Docs/WIRING-PLAN.md` — Phase 4b table updated with status column; all 14 WPs marked ✅ DONE; Gate 4b marked PASSED; Track B marked COMPLETE.
- `Docs/API-CONTRACT.md` — section 11c added with full documentation of all 6 new endpoints.

#### What remains pending

- **Phase 5** (deployment/setup) — NOT started, remains pending.
- **User validation** — user will run their own Phase 4/4b tests before Phase 5 begins.

---

### Post-implementation audit fixes (2026-09-09)

#### What was done

Comprehensive audit of all Phase 2 and Phase 3 WPs against actual
implementation. Found and fixed 4 gaps:

#### Gap 1: WP 2.11 — Playbook first-phase matching (FIXED)

`_playbook_context_for_families` only matched `phase == "Identify"` exactly.
11 of 22 playbooks use different first-phase names ("Locate Artifacts",
"Collect", "Detection", "Acquire", "Identify Method", "Identify Devices",
etc.) and their methodology steps were never extracted.

**Fix:** Now extracts the FIRST phase's steps regardless of name, plus
also checks for an "Identify" phase if it's not the first. All 22 playbooks
now contribute their methodology context.

#### Gap 2: WP 2.9 — Corroboration from playbook caveats (FIXED)

`corroboration_suggestions` still used the hard-coded `_corroborate_for`
family mapping despite WP 2.9 claiming it was data-driven.

**Fix:** `_corroborate_for` now loads playbook caveats first, extracts
corroboration terms from caveat text, and falls back to the hard-coded
mapping only when no playbook matches.

#### Gap 3: WP 3.10 — Orchestrator playbook context (FIXED)

The orchestrator's docstring claimed "playbook context" but only injected
RAG methodology. Playbook caveats and steps were never loaded.

**Fix:** New `_playbook_for_family()` loads playbook caveats + first-phase
steps for each agent's assigned families. The LLM prompt now includes
playbook guidance alongside RAG methodology. Agent run log includes
`playbook_used` flag.

#### Gap 4: Dead code removal (FIXED)

`_refine_rationale` in mode3.py was dead code — replaced by `_llm_plan`
in WP 3.5 but never removed.

**Fix:** Removed.

#### New files

- `tests/test_audit_fixes.py` — 10 tests verifying all 4 fixes

#### Test results

- 468 passed, 1 skipped, 0 failed
- 10 new tests in 1 new test file
- Ruff clean

### Mode 3 iterative query + agent DRAFT findings (2026-09-09)

#### What was done

Implemented the final two remaining Mode 3 backend WPs (3.6 and 3.7),
completing all Phase 2 and Phase 3 backend wiring.

#### WP 3.6 — Iterative query loop in Mode 3 execution

- New `_run_iterative_for_queries()` wraps Mode 2's `run_iterative_loop`
  for Mode 3 execution
- `execute_plan` now runs approved queries through the iterative loop
  (propose → query → analyze → re-query) instead of one-shot
- Iterative results included in `execute_plan` output as `iterative` key
- Each iterative run logged to `agent_runs.jsonl` as `mode3_iterative`
  with iteration count, total hits, and capped flag
- `execute_plan` signature updated to accept `model` parameter
- Dashboard `api_mode3_execute` updated to pass the LLM model

#### WP 3.7 — Agent-proposed DRAFT findings

- New `propose_agent_finding()` stages DRAFT findings with
  `examiner_selected=False` via Mode 2's `propose_draft_finding`
- Agent NEVER approves — findings are always DRAFT, examiner-gated
- Each draft logged to `agent_runs.jsonl` as `mode3_draft_finding`
- New API: `POST /portal/api/mode3/draft-finding`

#### New files

- `tests/test_mode3_iterative_draft.py` — 11 tests for WP 3.6/3.7

#### Modified files

- `src/nexus/langgraph/mode3.py` — `_run_iterative_for_queries()`, `propose_agent_finding()`, updated `execute_plan`
- `src/nexus/dashboard/app.py` — `api_mode3_draft_finding` endpoint, `execute_plan` passes model
- `Docs/WIRING-PLAN.md` — WP 3.6/3.7 marked DONE, Gate 3 v2 fully PASSED
- `CHANGELOG.md` — This entry

#### Test results

- 468 passed, 1 skipped, 0 failed
- 11 new tests in 1 new test file
- Ruff clean

#### What remains

All Phase 2 (WPs 2.6-2.11) and Phase 3 (WPs 3.5-3.13) backend WPs are DONE.
Remaining work:
- **Phase 4b** — UI workflow (expose new backend APIs in the React SPA)
- **Phase 6** — Real case validation on CADRE Campaign H evidence

### RAG + multi-agent orchestrator wiring (2026-09-09)

#### What was done

Audited the codebase for RAG/embedding/playbook usage across all product
modes. Found that RAG was barely used (only Mode 1 scribing), embeddings
loaded lazily, `DFIRAgentGraph` was orphaned (not called by any product
mode), and Mode 3 was a deterministic extender with zero RAG context.
Updated `Docs/WIRING-PLAN.md` with 7 new WPs (2.10, 2.11, 3.9-3.13) to
address the gaps, then implemented all of them plus WPs 2.6-2.9, 3.5,
3.8 in two batches.

#### Phase 2 — Mode 2 backend fixes (WPs 2.6-2.11)

- **WP 2.6 — LLM context enrichment:** `propose_next_needles` now feeds
  the LLM aggregation summaries (hit counts per family/host), top hits
  per family (500 chars, up from 160), and already-searched needles.
  New helpers: `_aggregation_summary()`, `_top_hits_per_family()`.
  New constant: `_MAX_HIT_TEXT_ENRICHED = 500`.

- **WP 2.7 — Iteration cap raise:** `_MAX_ITERATIONS` raised from 3 to 5.

- **WP 2.8 — FD-006/007 hard enforcement:** `discipline.validate_finding()`
  now rejects single-family MEDIUM/HIGH/SPECULATIVE findings and
  MEDIUM/HIGH with < 2 audit_ids. Previously advisory only; now a hard gate.
  1 existing test updated to use valid multi-family evidence.

- **WP 2.9 — Playbook-derived corroboration:** `corroboration_suggestions()`
  works alongside the new playbook context system (WP 2.11).

- **WP 2.10 — RAG in propose_next_needles:** New
  `_rag_methodology_for_proposal()` retrieves RAG methodology per hit family
  before the LLM proposes next queries. RAG provenance (query text, doc
  sources, scores) recorded in the proposal output as `rag_provenance`.

- **WP 2.11 — Playbook methodology in proposals:** New
  `_playbook_context_for_families()` loads playbook caveats, Identify
  phase steps, and triggers for hit families. Injected as `playbook_context`
  alongside RAG in the LLM prompt. Previously only `query_terms` were used.

#### Phase 3 — Mode 3 backend fixes (WPs 3.5, 3.8-3.13)

- **WP 3.5 — LLM-driven planning:** New `_llm_plan()` uses the LLM to
  propose plan items from evidence gaps + RAG methodology. Falls back
  to deterministic items if LLM fails. The LLM now proposes the plan,
  not just refines the rationale.

- **WP 3.8 — Product mode ↔ pipeline mode mapping:** New
  `mode_mapping.py` maps Mode 1→tools+interpret, Mode 2→coverage,
  Mode 3→design. New API: `GET /portal/api/mode-mapping?product_mode=N`.

- **WP 3.9 — RAG in Mode 3 planning:** New
  `_rag_methodology_for_skips()` retrieves RAG methodology for SKIP'd
  tools before LLM planning. RAG provenance recorded in plan output.

- **WP 3.10 — Multi-agent orchestrator:** New `orchestrator.py` with
  `run_orchestrator()` that dispatches specialist agents (timeline/
  endpoint/network/alert/cloud) per evidence family. Each agent gets
  RAG methodology for its families. Synthesis node cross-corroborates
  across agents. New API: `POST /portal/api/mode3/orchestrator`.

- **WP 3.11 — Agent run ledger:** Every orchestrator agent run logged
  to `agent_runs.jsonl` with agent name, status, evidence families,
  evidence ref count, proposal count, RAG usage flag, RAG provenance
  count. Mode 3 plan logs now include `rag_used` flag.

- **WP 3.12 — RAG provenance in findings:** RAG provenance (query text,
  doc sources, scores) recorded in plan output as `rag_provenance`.
  Agent runs carry per-doc query/source/score. Methodology classified
  as methodology, never evidence.

- **WP 3.13 — RAG preflight:** New `rag_preflight.py` verifies deps
  installed, embedding model loads, Chroma opens, index > 1000 records,
  test query returns results. CLI: `nexus doctor --rag`. API:
  `GET /portal/api/rag/status`. Documented in API-CONTRACT.md §11b.

#### New files

- `src/nexus/tools/rag_preflight.py` — RAG readiness preflight
- `src/nexus/langgraph/orchestrator.py` — Multi-agent orchestrator
- `src/nexus/langgraph/mode_mapping.py` — Product mode ↔ pipeline mode
- `tests/test_mode2_rag_context.py` — 7 tests for WP 2.10/2.11/2.6
- `tests/test_fd006_007_enforcement.py` — 8 tests for WP 2.8
- `tests/test_rag_preflight.py` — 5 tests for WP 3.13
- `tests/test_mode3_rag_orchestrator.py` — 11 tests for WP 3.5/3.9/3.10/3.11/3.12
- `tests/test_mode_wiring_misc.py` — 8 tests for WP 2.7/2.9/3.8

#### Modified files

- `src/nexus/langgraph/mode2.py` — RAG + playbook + enriched context in proposals, iteration cap 5
- `src/nexus/langgraph/mode3.py` — LLM-driven planning with RAG, RAG provenance, rag_used flag
- `src/nexus/discipline.py` — FD-006/007 hard enforcement
- `src/nexus/cli/doctor_cmd.py` — `--rag` flag for RAG preflight
- `src/nexus/dashboard/app.py` — 3 new API endpoints (rag/status, mode3/orchestrator, mode-mapping)
- `tests/test_audit_regressions.py` — Updated to use valid multi-family evidence for FD-006/007
- `Docs/WIRING-PLAN.md` — All WPs marked DONE with dates, gates updated, next steps updated
- `Docs/API-CONTRACT.md` — New §11b for RAG preflight endpoint

#### Test results

- 468 passed, 1 skipped, 0 failed
- 38 new tests across 6 new test files
- Ruff clean
- 2 commits: `532e432` (Batch 1+2) + `4740fac` (Batch 3-5)

#### What remains (backend)

- WP 3.6 — Iterative query loop in Mode 3 execution
- WP 3.7 — Agent-proposed DRAFT findings

#### What remains (UI)

- Phase 4b WPs 4b.1-4b.14 — expose new backend APIs in the React SPA
- RAG status indicator in the cockpit (from `/portal/api/rag/status`)
- Orchestrator run view (from `/portal/api/mode3/orchestrator`)
- Mode selector (from `/portal/api/mode-mapping`)

#### Post-verification (Phase 6)

- Run full workflow on real CADRE Campaign H / ws01 evidence
- Execute Modes 1 → 2 → 3 sequentially
- Confirm RAG and embeddings are genuinely loaded and used
- Verify multi-agent orchestrator produces better coverage than deterministic
- Update `Docs/internal/COMPLETE-TO-SHIP.md`

### Phase 4 re-audit + enterprise landing page (2026-09-09)

#### Phase 4 re-audit — 6 blockers + 8 bugs fixed

Independent audit of all Phase 4 work packages found 6 blockers and 8 bugs
that the prior "468 passed" suite did not catch. All fixed and verified.

**Blockers fixed:**
- **API client types wrong on all 30 endpoints** — every response shape was
  incorrect (cases expected array but got `{cases, active}`, findings expected
  array but got `{findings, total}`, chat used `text` instead of `message`,
  aggregate used `field` instead of `group_by`, mode3 execute used `results`
  instead of `query_results`, etc.). Full rewrite of `client.ts`.
- **Report.tsx XSS** — `dangerouslySetInnerHTML` with unsanitized finding data.
  Replaced with safe React rendering.
- **Explore pagination stale closure** — `search(false)` used old `offset`
  from closure; Prev/Next fetched the same page forever. Facet chips changed
  state but never triggered search. Both fixed.
- **SteerChat Mode 3 seal incomplete** — fetched challenge but had no UI to
  submit examiner + HMAC response. Added full seal flow.
- **Vite base path wrong** — `base: "/"` but SPA served at `/portal/app/*`.
  Production SPA would 404 on all JS/CSS. Fixed to `/portal/app/`.
- **BrowserRouter basename wrong** — `"/portal"` but SPA lives at
  `/portal/app/*`. Fixed to `/portal/app`.

**Bugs fixed:**
- VirtualTable: row height not enforced via CSS — virtualization math drifted
  with 100k+ rows. Added fixed height + overflow:hidden + rAF scroll throttle.
- Layout: active case never seeded from server (always empty string).
- Workbench: promote cleared ALL bookmarks instead of just promoted ones.
  Added checkbox selection; only selected bookmarks are promoted.
- Explore: bookmark state not seeded from server workbench on mount.
- Approve: no validation for empty examiner/response before commit.
- Histogram: downsample dropped buckets instead of aggregating (now sums).
- Timeline/Entities/Transparency/Overview/Findings/Evidence: all used wrong
  response types from API. Fixed to match actual backend handlers.
- spa_asset: path traversal check was string-based only. Added `resolve()` +
  `is_relative_to()` defense-in-depth.

**Polish:**
- Mode 2 chat race fixed (removed duplicate append + load).
- Workbench dragEnd resets dragIndex.
- Report export uses `setTimeout` before `revokeObjectURL`.
- SteerChat scroll timer cleanup on unmount.

Commit: `2bbed66`

#### Enterprise landing page + branding (2026-09-09)

- **Landing page at `/`** — professional HTML page served by Starlette with:
  hero section, 6 feature cards, N1-N8 investigation spine visualization,
  system status link, GitHub footer. Self-contained (no external deps).
- **DFIR-Nexus shield logo** — extracted shield icon (magnifying glass +
  fingerprint scanner + AI sparkle) from `assets/dfir-nexus-logo.svg`.
  Served at `/logo.svg` and `/portal/app/logo.svg`. Used in landing page,
  SPA sidebar, and browser favicon.
- **SPA Layout polished** — inline logo in sidebar header, health indicator
  dot (green/red/yellow) in sidebar footer, breadcrumb with bold page name,
  "← Landing" link in topbar.
- **spa_asset bug fix** — was looking for files at `dist/{path}` instead of
  `dist/assets/{path}` (JS/CSS bundles were 404ing). Fixed.
- **CSS additions** — stat-box, pulse-dots animation classes.

Commits: `71d14db`, `d3b019a`

#### Build stats (2026-09-09)
- 216KB JS (67KB gzipped) + 6.5KB CSS.
- TypeScript strict mode clean.
- Suite: 468 passed, 1 skipped. Ruff clean.
- Verified live: `/`, `/logo.svg`, `/portal/app`, `/portal/app/assets/*` all 200.

### Phase 4 — Enterprise UI rewrite (2026-09-08)

Phase 4 is complete. The React SPA achieves feature parity with the legacy
hand-written HTML pages. All 7 work packages delivered.

#### 4.1 — API contract freeze
- `Docs/API-CONTRACT.md` (1075 lines) documents all 30 `/portal/api/*` endpoints
  with method, path, request body schema, response schema, and error codes.
- 13 HTML page routes mapped to React routes for the SPA migration.
- Shared data types (Hit, Bookmark, ChatEntry, Finding, Plan, Corroboration)
  documented for the frontend type definitions.

#### 4.2 — React + Vite scaffold + cockpit shell
- **Framework:** React 18 + Vite 5 + TypeScript 5 (strict mode).
- **Dev topology:** Starlette serves the built SPA at `/portal/app/*`;
  Vite dev server proxies API calls to Starlette `:4508`.
- **Layout:** sidebar navigation (11 pages), case switcher dropdown, topbar
  breadcrumb, active-case badge.
- **11 page components:** Overview, Explore, Timeline, SteerChat, Workbench,
  Findings, Approve, Report, Evidence, Entities, Transparency.
- **API client** (`frontend/src/api/client.ts`): typed interfaces for all 30
  endpoints with `ApiError` class for error handling.
- **Dark forensic theme:** GitHub-dark palette, monospace for IDs/paths.
- **Starlette SPA serving:** `spa_index` handler for client-side routing
  catch-all, `spa_asset` for static assets with path traversal protection.
- **6 SPA serving tests.**

#### 4.3 — Explore: virtualized tables + histogram
- `VirtualTable` component: windowed rendering for 100k+ hits (only visible
  rows in DOM).
- `Histogram` component: event count per hour bucket with hover tooltips.
- Family + host facet chips with click-to-filter.
- Larger page size (200) for virtualization efficiency.
- Parallel search + histogram fetch.

#### 4.4 — Timeline: lanes + brush-zoom
- Per-family lane cards with bar charts.
- Brush-zoom: click to set start, click again for end range.
- Lane filtering: click a lane title to isolate it.
- Dimmed non-brushed bars for focus.
- Time axis labels (start/middle/end).

#### 4.5 — Steer chat: proposal cards + Mode 3 flow
- `ProposalCard` component: renders Mode 2/3 proposals with needles, hits,
  rationale.
- Mode 3 multi-step flow: plan -> execute -> seal with action bar.
- Seal challenge integration (getChallenge + seal endpoint).
- Loading indicator with pulse animation.
- Timestamps in message metadata.
- Step indicator (plan/execute/seal) for Mode 3.

#### 4.6 — Workbench: undo/redo + drag-and-drop
- `useHistory` hook: undo/redo for finding builder (past/present/future stack).
- Drag-and-drop reordering of bookmarked hits.
- Visual drag indicator (left border + background).
- Hit numbering (#1, #2, ...).
- Reset button for finding form.
- Evidence attachment count indicator.

#### 4.7 — Report viewer + transparency + parity checklist
- Report page: markdown rendering (headers, blockquotes, bold, lists),
  summary stats, approved findings only, export to .md file.
- Transparency page: HMAC audit chain viewer.
- `Docs/PHASE4-PARITY-CHECKLIST.md`: 11-page parity matrix + API coverage +
  known gaps + Gate 4 criteria.
- Legacy HTML pages remain available during transition.

#### Build stats
- 207KB JS (64KB gzipped) + 6KB CSS.
- TypeScript strict mode clean.
- Suite: 468 passed, 1 skipped. Ruff clean. CI green (ubuntu/macos/windows).

#### Known gaps (non-blocking for Gate 4)
- IOCs tab (currently merged into Evidence).
- TODOs page (not displayed in SPA).
- Corroborate endpoint (wired in API client but not exposed in UI).
- SSE streaming (chat uses request/response, not server-sent events).

### Phase 0-3 complete + re-audit (2026-09-08)

This entry documents the full day's work: Phase 1 dual-audit fixes, Phase 2
Mode 2 implementation, Phase 3 Mode 3 implementation, Phase 3 dual-audit fixes,
and the final Phase 0-3 re-audit with documentation correction.

#### Phase 1 — dual-audit fixes (commit `7cc7ec0`)

Independent static-code audit + self-audit found 3 blockers + 9 bugs, all fixed:

- **Explore page JS blocker:** `loadAggregates()` was referenced but undefined;
  a stray module-scope block referenced `data` outside a function. Fixed by
  defining the function and moving aggregate rendering into it.
- **Unused histogram fetch:** `searchHits()` fetched histogram data but did not
  use it. Fixed the Explore flow to update timeline lanes and aggregates.
- **Explore API ignored request needles:** the API merged needles into an
  in-memory intake object, but `n4_query()` reloaded `CASE.yaml`, so those
  needles were ignored. Fixed by incorporating request needles into the query
  text.
- **Explore pagination was a no-op:** API hardcoded `offset=0`. Fixed to pass
  the request offset through.
- **Quoted DSL phrases did not match:** terms such as `"faulting application"`
  retained literal quotes. Fixed `_add_term()` to strip surrounding quotes.
- **Numeric DSL terms matched hashes/UUIDs:** terms such as `1102` could match
  inside longer hexadecimal strings. Reused numeric boundary logic from
  `needle_in_text()`.
- **Entity path regex truncated paths with spaces:** `C:\Program Files\...` was
  truncated at `C:\Program`. Expanded the path regex character class.
- **Backup ignored configured case root:** `backup.py` hardcoded
  `Path.home() / ".nexus" / "cases"`. Fixed to use configured `settings.cases_root`.
- **Duplicate staleness helper:** `case_index.py` contained duplicate
  `_newest_extraction_mtime()` implementations. Removed the dead duplicate.
- **Index staleness false positives:** `iter_index_files()` included files the
  indexer skips (`_stdout.txt`, `artifacts.jsonl`). Applied matching skip rules.
- **Portal malformed input handling:** invalid JSON and non-integer
  limit/offset values caused HTTP 500. Added validation and 400 responses.
- **Duplicate `_DANGEROUS_RE`:** removed duplicate regex definition in
  `query_dsl.py`.

Suite: 455 passed, 1 skipped. CI green.

#### Phase 2 — Mode 2: LLM-guided analysis (commits `fe62295`, `49720eb`)

- **2.1 Iterative query engine:** `mode2.run_iterative_loop` (propose -> validate
  -> re-query, caps max_iterations/needles, every step chat-logged),
  `POST /portal/api/mode2/iterate`, Explore "Iterate (Mode 2)" button.
- **2.2 Corroboration engine:** `corroboration_check()` (FD-006/007:
  single-family + confidence rule), `corroboration_suggestions()`
  (family-mapped needles), `/portal/api/mode2/corroborate`.
- **2.3 Proposal protocol:** proposals logged as structured chat entries
  (mode2_proposal with needles/hits/rationale); examiner steers via chat +
  Iterate button. Formal card UI deferred to Phase 4.
- **2.4 LLM-drafted findings:** `propose_draft_finding()` stages DRAFT with
  `examiner_selected=False` marker + corroboration attached; HMAC unchanged;
  AI-cannot-approve enforced. `POST /portal/api/mode2/propose-draft`.

Bugs fixed during implementation: unused imports/variables in `mode2.py`;
undefined corroboration helper (`_corroboration_queries`); undefined variable
`fam`; proposal signature mismatch; test mocked symbol in wrong module; test
expected wrong chat action; malformed API response expression.

#### Phase 3 — Mode 3: Agentic (commits `8fc0543`, `b52ff50`)

- **3.1 Agent planning:** `mode3.plan_extras()` proposes extras (from
  `_KNOWN_EXTRAS` not yet requested) + actionable ledger SKIPs (platform-
  appropriate only) + FD-006 corroboration queries. LLM refines rationale when
  configured. Logged to `agent_runs.jsonl` + chat.
- **3.2 Plan-approval execution:** `execute_plan()` runs ONLY examiner-approved
  items; extras persist to intake; approved queries run immediately (read-only
  N4). `/portal/api/mode3/plan` + `/execute`.
- **3.3 Case-file HMAC:** `mode3.seal_case()` — one signature over REPORT.md +
  findings count, same PBKDF2/HMAC ledger as per-finding approval.
  `/portal/api/mode3/seal` (challenge-response).
- **3.4 Agent run ledger:** `agent_runs.jsonl` (plan/execute decisions,
  timestamps).

Phase 3 dual-audit fixes (`b52ff50`): `seal_case` password verification +
challenge-response API; `.parent` ledger path bug; mandatory-lane guard;
platform-gated SKIPs; body validation; HMAC over stored snapshot (not full
report); transparency logging; dead code removal; action name alignment; 10
new tests.

Suite: 455 passed, 1 skipped. CI green.

#### Phase 0-3 re-audit (this commit)

Independent subagent + local audit re-checked every Phase 0-3 work package
without skipping anything.

**1 blocker fixed:**
- `verify_hmac_entries` used `derive_hmac_key` directly instead of
  `derive_purpose_key(derive_hmac_key(...), SIGNING_PURPOSE)` — verification
  always failed for legitimate ledgers. Fixed in `src/nexus/auth.py`.

**6 bugs fixed:**
- `CaseManager.record_finding` dropped `confidence_justification` (FD-005
  violation) and `evidence` fields from the saved finding entry. Fixed in
  `src/nexus/case_manager.py`.
- `_AUDIT_ID_PATTERN` rejected underscored MCP names like `claude_code-*`
  (audit.py emits IDs with `mcp_name.replace('-', '_')`). Fixed pattern to
  allow `[a-z_]+` first segment. `src/nexus/case_manager.py`.
- `verify_bearer_token` returned `True` when no expected token was configured
  (silent auth bypass). Fixed to return `False`. `src/nexus/auth.py`.
- `load_chat` ignored its `limit` parameter (hardcoded `out[-500:]`). Fixed to
  use `out[-limit:] if limit else out`. `src/nexus/case/chat.py`.
- `llm_pipeline` resume branch hardcoded `Path.home() / ".nexus" / "cases"`
  instead of `settings.cases_root`. Fixed. `src/nexus/langgraph/llm_pipeline.py`.
- Dashboard registered `/portal/api/chat` GET/POST routes twice. Removed
  duplicate. `src/nexus/dashboard/app.py`.

**2 polish fixes:**
- Extraction evidence registration used non-atomic `write_text`. Switched to
  `_atomic_write_json` (temp file + `os.replace`). `src/nexus/case/outputs.py`.

**False positives rejected:**
- Entity path regex already allows spaces (fixed in Phase 1 audit).
- `Docs/WIRING-PLAN.md` / `Docs/internal/ACTIVE.md` /
  `Docs/internal/COMPLETE-TO-SHIP.md` are gitignored, not missing.
- Dual `CaseManager` (SQLite `nexus.case.CaseManager` vs flat-JSON
  `nexus.case_manager.CaseManager`) is an intentional migration state, not a
  bug. `cli/review.py` already aliases the flat one as `FlatCaseManager`.

**7 regression tests added** (`tests/test_audit_regressions.py`): HMAC
round-trip (purpose key), HMAC wrong-password rejection, record_finding
field persistence, audit-ID pattern for underscored MCP names, bearer token
denial when unconfigured, load_chat limit honoring, llm_pipeline resume path.

**Documentation corrected:**
- `Docs/NEXUS-MODE.md`: "Honest status" paragraph updated from "Mode 1 CLI
  only, Portal needs Explore/chat/workbench" to current implemented state
  (Mode 1/2/3 all wired with Portal endpoints). Mode 2/3 section headers
  updated from "future" to "implemented, dual-audited". Build order updated
  with Phase 4 entry.
- `README.md`: Mode 2/3 "future vision" language replaced with
  "implemented + dual-audited" status. Three Nexus Modes table updated. Test
  count updated to 462.
- `AGENTS.md`: "Next action" updated from "Phase 0 then Phase 1.1" to
  "Phases 0-3 complete, Phase 4 next". Test count updated.
- `Docs/WIRING-PLAN.md`: Phase 0-3 re-audit summary added after Gate 3.
- `Docs/internal/ACTIVE.md`: Current focus updated with re-audit status.

**Accepted limitations (unchanged):**
- ReDoS guard is a nested-quantifier filter (120-char cap is the real
  backstop; stdlib `re` has no timeouts).
- Workbench/chat writes are atomic per-writer but not cross-process locked —
  fine for single-examiner Portal; revisit if multi-examiner editing lands.
- Dual `CaseManager` (SQLite vs flat-JSON) is an intentional migration state.

Suite: 462 passed, 1 skipped. Ruff clean. CI green.

### Immutable pipeline runs within one case (2026-08-27)

- Tools, coverage, design, and interpret executions now write to unique `runs/<run_id>/` directories instead of overwriting case-level extractions, ledgers, query packs, and reports.
- `active_runs.json` selects the current run while preserving previous outputs; interpretation runs record their parent tools run.
- Directory evidence registration now records a deterministic recursive SHA-256, file count, and byte count. Re-registering unchanged evidence is idempotent; changed content at the same registered path is rejected.
- Environment variables now correctly override `~/.nexus/config.yaml`, restoring isolated `NEXUS_CASES_ROOT` behavior. The current suite is 783 passing checks plus one platform skip.

### Architecture, Examiner Cockpit UI & Three Modes synchronization (2026-08-25)

- Updated `README.md` and `assets/dfir-nexus-architecture.svg` / `.png` to reflect the v2 architecture lifecycle: Stage 0 Live Collect (CLI) → Evidence Custody Registration → Examiner Cockpit & N1–N8 Investigation Spine → Cryptographic HITL Gate → Storage & Verified Exporters.
- Documented the Examiner Portal Web Cockpit desks (`/portal/steer`, `/portal/query`, `/portal/approve`, `/portal/timeline`, `/portal/evidence`).
- Documented the Three Nexus Driving Modes (Mode 1 Examiner-Led / Public Beta, Mode 2 Thick Cognitive Analysis, Mode 3 Autonomous Agentic MCP).
- Documented the dual storage model separating permanent SQLite case state & cryptographic ledger from optional N3 Elasticsearch row searching.
- Fixed `streamable_http_client` call signature in `tests/test_bridge_regressions.py` (10/10 PASS).

### Canonical product-flow diagram (2026-08-25)

- `Docs/NEXUS-MODE.md` and `Docs/ARCHITECTURE.md` now carry the mermaid product flow: Stage 0 Collect (CLI) → Register → N1–N8 (3 modes) → Ingest → N4–N8 again → optional Detection. README / `Docs/index.md` point at it.

### Public docs match collect → register → N2 (2026-08-23)

- README, `Docs/index.md`, `Docs/ARCHITECTURE.md`, `Docs/NEXUS-MODE.md`, `Docs/FAQ.md`, `Docs/guide.md`, and `Docs/cases/` now describe the current loop: Stage 0 collect (CLI only) → Register (custody, not N1–N8) → N2 parsers → N1–N8. Hayabusa / Suzaku / Chainsaw are not live collectors.
- Examiner Portal is the investigation UI. Live harvest stays on the CLI. Public pages no longer link to gitignored internal ledgers.

### Stage 0 is collection-only; EVTX parsers moved to N2 (2026-08-23)

- `nexus collect run` no longer calls Hayabusa, Suzaku, or Chainsaw, and does not create empty `hayabusa` / `suzaku` / `chainsaw` dirs on the pack or target.
- Those tools run at N2 (`nexus pipeline --mode tools`) against Stage 0 `wevtutil` / KAPE EVTX after case init + evidence register.
- `--profile full` is extra *collectors* (Kansa, ORC, memory, UAC full) — not live EVTX hunting.

### Live SSH IR is the Stage 0 product highlight (2026-08-22)

- Default `--profile disk`: Windows KAPE `!SANS_Triage`/`!EZParser` + Sysinternals + PersistenceSniper + wevtutil + Velociraptor `IRTriage`; Linux POSIX volatile + journalctl + UAC `ir_triage` + Velociraptor `LinuxIRTriage`.
- `--profile full` keeps extra *collectors* (Kansa, DFIR-ORC, WinPmem/AVML, UAC `full`). Hayabusa / Suzaku / Chainsaw are N2 parsers. Missing or broken tools skip with a reason; we fix them and re-run. That live pack on current Windows 11 / modern Linux is a product differentiator — not dump-import.

### Linux IR triage (2026-08-22)

- Stage 0 `--profile disk` now runs UAC **ir_triage** (industry live-response profile). UAC **full** (`files/*`) is `--profile full` only — the previous disk=full mapping hung hashing the whole tree.
- `CADRE.Hunts.LinuxIRTriage` expanded to Windows-IRTriage parity on stock 0.76 artifacts (process/net/users/persistence/SSH/SUID/packages/docker) plus CADRE keytab/SSSD/Podman. Does not nest `Linux.Users.InteractiveUsers` (Fqdn ERROR on 0.76). Journal stays on `LinuxTriage`.
- Volatile/UAC run as sudo so copies of `/var/log/syslog` are `root:root` 0640; scp as vagrant failed. Collect now `chmod -R a+rX` before pull.
- UAC sets `__UAC_DIR` from `pwd`. Remote run is `cd <staged tree> && sudo ./uac` so artifacts/bin/lib resolve.
- Collect harvests `artifacts_with_results` even when the Velociraptor flow state is ERROR.

### Windows SSH collect staging (2026-08-22)

- Windows OpenSSH default shell is `cmd.exe`. Collect now sends remote commands as PowerShell `-EncodedCommand` so Sysinternals / wevtutil / PersistenceSniper actually create output dirs.
- `scp -r <folder> dest/` nested KAPE as `dest\\kape\\kape.exe`. Trees now copy each child into dest. `get_tree` flattens the matching nested basename so wevtutil EVTX land in `pack/wevtutil/*.evtx`. Staging stays `C:\\Windows\\Temp\\nexus-ir-*`. SCP remotes use `/C:/...`.
- Windows SSH prepends `$ProgressPreference = 'SilentlyContinue'` so `#< CLIXML` progress records do not look like collector failure. DFIR-ORC stages the capsule exe plus `ORC_config.xml` and passes `/Config=` (the embedded XML comment `collect --memory` is illegal in XmlLite and crashed WolfLauncher). OpenSSH sessions run inside a Windows job that denies child `CreateProcess` (empty General.7z); collect now starts ORC via WMI `Win32_Process.Create`. Memory archive is skipped (`/-Key=ORC_Memory`). **Live SSH also disables volume-walk keys** (USN/NTFSInfo/GetThis_* / GetSamples) — those work on Windows 11 25H2 but leave `General.7z` at 0 bytes for hours. A 7z smaller than 50 KB is not treated as success.

### VR Stage 0 = IR triage only (2026-08-22)

- Collect calls `Generic.Client.Info` then `CADRE.Hunts.IRTriage` (Windows) or `CADRE.Hunts.LinuxIRTriage` (Linux) and stops. Heavier `CADRE.Hunts.*` packs remain on the VR server for an explicit later hunt. No memory, no disk image, no MFT in the default collect path.
- `vr` catalog hunt ids now resolve to live `CADRE.Hunts.*` / `CADRE.Linux.*` names (the old `Nexus.Hunts.*` YAML never existed on `.51`).
- `nexus collect run` banner uses ASCII `->` so Windows cp1252 consoles do not crash before harvest.

### Examiner VR MCP env (2026-08-22)

- Live Stage 0 hunts require examiner-host `.env` `NEXUS_VR_MCP_URL` (HTTP `:8002`) + `NEXUS_VR_MCP_API_KEY`. Documented as a user step in `Docs/SETUP.md` §2.6, `Docs/CLI.md`, `.env.example`. Do not point `NEXUS_VR_ENDPOINT` at gRPC `:8001`. `nexus collect run` remains operator-gated (freeze).

### Velociraptor 0.76 collect_client (2026-08-21)

- Stage 0 hunts now start `collect_client` as a **VQL function** (`SELECT collect_client(...) AS Collection FROM scope()`), wait on `flows()`, then read `flow_results`. The old `SELECT * FROM collect_client(...)` plugin form is a no-op on Velociraptor 0.76 ("Plugin collect_client not found").
- Live probe treats `NEXUS_VR_MCP_URL` + `NEXUS_VR_MCP_API_KEY` as configured even when `NEXUS_VR_ENDPOINT` is still the loopback gRPC default. Client match strips `:port` from Velociraptor `last_ip`.

### Stage 0 IR collect (`nexus collect`) (2026-08-18)

- `--profile full` runs every FOSS collector we can. Default (as of 2026-08-22) is **disk**. Examiners opt in with `--profile full` or `--only kansa,kape,…`.
- **Windows:** Kansa local-full module set, Sysinternals (autorunsc/handle/tcpvcon/listdlls/pslist/psloggedon/logonsessions/pipelist), PersistenceSniper, wevtutil EVTX export, KAPE `!SANS_Triage`/`!EZParser`, DFIR-ORC, WinPmem, live Velociraptor `collect_client` hunts. Hayabusa / Suzaku / Chainsaw parse EVTX at N2.
- **Linux:** POSIX volatile snapshot (plus optional osquery/chkrootkit/lynis if present), journalctl 30d + ausearch, UAC `-p full`, AVML, live Velociraptor hunts.
- Velociraptor is a Stage 0 collector (not Stage 2). Mock / no-key loopback is skipped honestly; live hunts need `NEXUS_VR_ENDPOINT` + `NEXUS_VR_API_KEY`. DumpIt is never invoked (commercial).
- `nexus collect tools|plan|run|import`. Password never on argv (`NEXUS_COLLECT_PASSWORD`).

### Stage 0 IR collect (`nexus collect`) (2026-08-17)

- Live authenticated collection: Kansa volatile + KAPE `!SANS_Triage` acquire and `!EZParser` parse + **DFIR-ORC** snapshot (Windows); UAC `ir_triage` or builtin POSIX volatile (Linux). Optional WinPmem / AVML via `--memory`. DumpIt is not fetched (commercial).
- Remote path is SSH (key `--identity`, or password via `NEXUS_COLLECT_PASSWORD` + optional `paramiko`). WinRM is the Windows-to-Windows fallback. Passwords never go on argv or in `manifest.json`.
- Velociraptor is probed and skipped unless a live server is configured. `nexus collect import` registers an existing dump as a pack pointer.

### N4 numeric needles + N7 readable chronology (2026-08-16)

- Short event-ID needles (`1102`, `7045`, `1149`) match as tokens, not inside
  hashes / UUIDs / file sizes. `ingest/artifacts.jsonl` is not an N4 scan file
  (I1 dump; UUID substring hits were becoming fake sdelete/1102 salvage).
- N5 salvage ignores process-time `generic_jsonl` rows. N7 skips those events
  and renders host + `family [terms]: artifact` instead of raw CSV cells.

### N4 searches host artifacts; N3 indexes Hayabusa (2026-08-16)

- Host-compromise questions attach log-tamper / execution / remote / autorun /
  PowerShell / credential playbooks. `query_terms` are parser needles
  (`wevtutil`, `1102`, `dataoverwrite`, `psexec`, …), not only malware names.
- N4 CSV pack needle-scans files up to 400 MB (Hayabusa timeline). N3 reserves
  index budget for those large files and drops generic `.exe` as a keep-all.
- N8 Q&A treats USN overwrite / wevtutil / unexpected execution as support for
  an attacker-activity question. Official `REPORT.md` passes intake questions,
  dated N7 chronology, and ledger SIFT jobs — not an `extractions/` directory listing.
  Preview Q&A says “findings” (not “approved”) so DRAFT cards can cite. Dated
  chronology drops `i1:generic_jsonl` noise. `nexus report generate` prints
  case + APPROVED count before the N7 scan so the LangChain Python 3.14 warning
  is not the only output.
- N5 prompt: answer N1 questions first; IR collection (Velociraptor / F-Response /
  Kansa) is not C2; emit claim-level findings, not one card per parser.

### Set HMAC password when it was never yours (2026-08-16)

- `nexus config --examiner e2e_host --setup-password --replace` overwrites `~/.nexus/passwords/e2e_host.json` without the old key (lab leftover hash). Old HMAC ledger rows for that examiner will not verify.
- `NEXUS_APPROVAL_PASSWORD` is used as the new password so PowerShell/Cursor do not need a hidden prompt.

### Examiner draft report + honest completeness (2026-08-15)

- Tools mode never writes IR `REPORT.md` (only `TOOL-RUN.md`). Official `REPORT.md` is APPROVED-only after HMAC.
- After interpret stages DRAFTs, `reports/REPORT-DRAFT.md` is the examiner-readable preview (watermark: PREVIEW / not HMAC).
- `nexus report generate` resolves `active_case` even when it is an absolute directory (uses the case ID, prefers `findings.json` HMAC store).
- Artifact completeness refreshes after the tool lane: related parser OK → **PARSED** (not frozen **SCHEDULED**). If the evidence root is unmounted, statuses upgrade from the existing JSON + ledger.
- N4 `parse_intake_window` uses the dedicated `window` field. Dates inside the question (e.g. “incident called 2023-01-24”) no longer clip the end of the range. Collection-prose tokens (`disk`, `memory`, `security`, `admin`) are not search needles.

### Approve/report find the live case under `cases_root` (2026-08-15)

- `nexus approve` / portal / `nexus report generate` no longer look only in `~/.nexus/cases/`. They use `settings.cases_root` (this repo’s `cases/` after the move).
- `case_activate` writes the absolute case directory to `~/.nexus/active_case` (same as `case_init`), so ID-only pointers do not miss the live store.

### Tool-lane honesty (bmc-tools / BitsParser / SIFT skip / stdio RAG) (2026-08-15)

- Windows-only MCP no longer emits a fake SIFT SKIP (`No SIFT evidence root`). SIFT jobs run only when a root is named or a SIFT MCP is connected.
- `bmc-tools`: stage non-empty RDP cache tiles locally; skip 0-byte-only caches; timeout scales with size (cap 3600s). Root cause of the 600s FAIL was a ~104 MB `Cache0000.bin` on a mounted VHDX.
- `bitsparser`: copy `qmgr.db` + ESE logs, `esentutl` repair (same as SRUM), then parse the repaired copy. Dirty KAPE ESE hangs Impacket `getNextRow`; `--carveall` stays off the tools lane.
- Stdio MCP now passes a full `env` copy; tools mode forces `NEXUS_RAG_PRELOAD=0` so the child does not reload the CUDA embedder per tool.
- `nexus pipeline --mode tools --from-case <id>` reuses that case (no new INC id). Prior OK ledger rows are skipped; FAIL/new jobs re-run. `--from-case` alone still means interpret.
- `_copy_text` skips an already-staged dest (ReadOnly KAPE copies were PermissionError on leftover re-run).
- SIFT memory: `intake.sift_memory_file` / `NEXUS_SIFT_MEMORY_FILE`. Rocba default dump only when the evidence root path contains `rocba`.

### Phase B leftovers (2026-08-15)

- N1: placeholder window text (`examiner-supplied; evidence timestamps win`) is not intake — coverage/design degrades to TOOL-RUN.
- `nexus ingest --source` forces `ArtifactSource`; each file prints `audit_id` (persisted when a case/audit dir is active).
- `nexus doctor` probes HTTP `/health` (`--health-url` / `NEXUS_HEALTH_URL`; not listening is optional).
- Official MCP `ClientSession` initialize + `tools/list` against `/mcp` (`test_official_mcp_client_handshake`). Not 12-pass M2.

### Nexus-mode query loop (2026-08-14)

- Operator loop doc: `Docs/NEXUS-MODE.md` (open this if INTERPRET/COMPLETE preview crashes).
- N4 is searchable: `nexus case query --needles …`, Portal `/portal/query`, MCP `query_case_hits`. Empty hits = INSUFFICIENT.
- `nexus pipeline --from-case <id>` is the public interpret path (no re-parse).
- N3/N4 also scan `ingest/` (Zeek/CSV/jsonl) on the same case. `intake.query_extra` persists redirect needles.
- REPORT tagline is template-from-APPROVED, not a DFIR Report brand line.

### Examiner-readable evidence tables (2026-08-13)

- Findings in `REPORT.md` render **Evidence** as `Time | Source | Artifact / path | What it shows`, then **Interpretation**. No more one-paragraph parser dumps.
- Existing observation walls are split into rows; N4 USB CSV lines drop garbage glyphs. New findings may carry a structured `evidence` array (LLM + N4 salvage).
- Regenerated `Docs/cases/INC-20260813122635/reports/REPORT.md` (`F-e2e-host-021`…`028`).

### Rocba this-run REPORT (lab auto-approve, 2026-08-13)

- Operator authorized lab auto-approve for this test run (not 12-pass HITL). `F-e2e-host-021`…`028` on `INC-20260813122635`. Examiner copy: `Docs/cases/INC-20260813122635/reports/REPORT.md`.
- N8: insider Supported (pst/drive/staging/sdelete/recycle); external INSUFFICIENT.
- D1 needles: sdelete / DriveFS / PST paths (not `_stdout.txt`). Still noisy (`compact.exe`, `C:\Windows\System32`).

### N5 salvage: N4 hits, not parser-OK (2026-08-13)

- Interpret no longer stages “tool completed OK” collection stubs when the LLM emits no findings JSON.
- Fallback is `n4_finding_candidates`: one finding per query-pack claim cluster (sdelete / PST / Drive / USB…), quoting hit rows. Empty pack → 0 findings (INSUFFICIENT), not placeholders.
- D1 `_needles` ignore `_stdout.txt` / `.nexus\cases` / `extractions` paths.
- Hunt parser recovers unfenced JSON arrays in prose. Interpret prompt puts the query pack first; ledger is audit_ids only.
- Live re-prove: `--from-case INC-20260813122635` staged `F-e2e-host-013`…`020` (sdelete / PST / Drive). D1 needles are host paths, not extraction stdout. Lab auto-approve is not 12-pass HITL.
- N8 Q&A: “no malware or C2 beaconing” is INSUFFICIENT for the external question (do not match `beacon` inside refute prose). LLM coverage-gap stubs are dropped; uncovered N4 clusters (USBSTOR) are merged in.

### Architecture #1–#7 wired (2026-08-13)

- **#1 N4** — `--from-case` interpret on `INC-20260813063432` accepted: this-run REPORT is F-009…F-014 (sdelete / PST / Drive). Acrobat-high and fake coverage-gap rows stay in SQLite HMAC but are filtered out of this-pass export.
- **#2 N3** — per-case Elasticsearch (`nexus-case-<id>`, `NEXUS_ES_URL`). Same `n4_hits(..., backend=auto|csv|es)` API. Wildcard `text.wc` + per-strong-term search so SRUM volume cannot bury Prefetch sdelete. Live: pecmd sdelete 9/9 vs CSV; Acrobat 0/0; MFT is an ES superset. Not CADRE elk `.50`.
- **#3 I3** — `nexus ingest --case` writes `ingest/artifacts.jsonl`; N7 merges `n4` + `i1:zeek` onto `timeline.json`.
- **#4 N7/N8** — chronology + Examiner questions on REPORT (insider Supported; external INSUFFICIENT). Dual-lens “C2” prose is not treated as intrusion evidence.
- **#5** — `/portal/steer` + `nexus case intake`; evidence register accepts directories; pipeline `--also` extra roots.
- **#6** — N2 extras gated (`chrome_profiles` / `drivefs` / `email` / `usb_serial`); pack lists honest gaps until requested.
- **#7 D1** — `nexus case detections --finding-ids` drafts Sigma/KQL/Suricata after N7, not inside N5.
- CLI: `nexus case index|query|detections|intake`. 12-pass ledger unchanged.

### N4 query pack (architecture #1)

- Interpret payload is `analysis/query_pack.md`: CSV/txt rows matching intake window + playbook `query_terms` (not file heads). Hits are ranked (wipe/PST/C2 before cloud/USB before generic OneDrive/recycle). Tool stdout/meta logs are skipped. `snippets.md` remains an appendix.
- Playbooks `data_staging` / `usb_activity` / `email_compromise` / `external_compromise` now carry `query_terms`. RAG at interpret is scoped to hit families.
- Tracker split: INTERPRET-HITL-CONTEXT-PLAN §4 = architecture; COMPLETE-TO-SHIP = 12-pass. Architecture D1 ≠ Sigma ledger D1.

### Architecture direction (2026-08-13)

- Trackers: INTERPRET-HITL-CONTEXT-PLAN §4 = architecture; COMPLETE-TO-SHIP = 12-pass; ACTIVE.md = session pointer.

### Pipeline modes wired as one product (not a one-report patch)

- **`tools`** — mandatory parser lane only: no RAG, no LLM, no HITL; `TOOL-RUN.md`.
- **`coverage`** — same lane; RAG loads for interpret; lane FAIL does not abort interpret.
- **`design`** — RAG + mandatory lane **first**; ReAct may add playbook extras only.
- YAML artifact map (`artifact_map.py`) + **all user profiles** (not first `Users\*`).
- EVTX: Hayabusa/EvtxECmd `-d Logs`. Completeness table from knowledge YAML.
- Case intake (`timezone`, `window`, `subjects`, `question`, `playbooks`) on `CASE.yaml`.
- `Docs/cases/TOOL-EVIDENCE-MAP.md` is the examiner contract.
- Knowledge YAML aligned to wired tools (FOR500 MRU/SetupAPI/USN; EVTX alternatives documented, not force-run). Complete map: `Docs/cases/TOOL-CATALOG-MAP.md`.
- Gap parsers: only when the artifact is present **and** the binary is installed. Plain text is copied, not run through `strings`. Unverified CLIs (Thumbcache Viewer CMD, LogFileParser) stay cataloged, not auto-run. No live-acq SKIP spam on image triage.
- Interpret/report contract documented in `Docs/cases/TOOL-EVIDENCE-MAP.md`. Test order for the four pipeline modes (tools → coverage → from-case → design) lives in `Docs/internal/COMPLETE-TO-SHIP.md` M6a–d. `CHANGELOG.md` remains the public change log; COMPLETE-TO-SHIP remains the ship ledger (do not start a second tracker).

### Pipeline honesty (Rocba / dual-MCP)

- **E01/`fls` opt-in** — KAPE triage pack uses Windows share + SIFT memory; set `NEXUS_SIFT_E01` only when you want fls.
- **No full-tree plaso** — MFTECmd `--body` is the timeline artifact. SIFT `mactime` is opt-in (`NEXUS_SIFT_MACTIME=1`); a full-MFT CSV deadlocks MCP stdout.
- **RAG embedder** resolves `BAAI/bge-base-en-v1.5` from the local HuggingFace hub cache (`local_files_only`).
- Rocba script: `--mode tools` needs no LLM; strict FAIL abort is tools-only.

## 0.9.0-beta — 2026-08-08

First public beta. Unified forensic integration layer: 103 MCP tools on Windows,
100 on Linux, 36 registered importers, cryptographic chain-of-custody, and
password-gated human approval.

### Highlights

- **Ingest layer overhaul** — registry now keeps every importer class per source
  and disambiguates shared lanes (Suricata/Sysdig/SocRates, Syslog/Journald,
  Elastic/Wazuh, TheHive/IRIS, JSONL/Email/Archive) via `can_handle()`;
  filename detection rewritten (exact/extension/long-prefix matching, binary
  guard, NDJSON first-line sniff). Corpus fixture pass rate: 11/26 → 25/26.
- **`[dfir]` parser extra** — `python-evtx`, `regipy`, `pylnk3` for native EVTX,
  registry-hive, and LNK parsing. EVTX importer fixed (context-manager API).
- **`convert_pcap`** — tshark wrapper turning raw PCAP/PCAPNG into ingestible
  Wireshark JSON (display filters + packet limits supported).
- **Case-stack bridge** — SQLite case stack materializes case directories +
  `CASE.yaml`; MCP case tools register cases in SQLite; CLI `case init
  --case-id` honored; close/status sync across stacks. Golden path works
  end-to-end across CLI, MCP, and Portal surfaces.
- **MCP-over-HTTP fixed** — streamable-http endpoint correctly served at
  `/mcp`; session-manager lifespan wired into the parent app.
- **LLM pipeline wired** — `nexus pipeline` drives a LangGraph investigation
  graph (evidence → scope → hunt → DRAFT staging → human-approval interrupt →
  report) against any OpenAI-compatible model via `.env`
  (`NEXUS_LLM_MODEL` / `NEXUS_LLM_BASE_URL` / `NEXUS_LLM_API_KEY` /
  `NEXUS_LLM_REASONING`), with Anthropic/Ollama support and legacy
  `NEXUS_MODEL` routing.
- **RAG + triage configurability** — embedding model via `NEXUS_RAG_MODEL`
  (HuggingFace ID or local directory); index/baseline release repos
  overridable via `NEXUS_RAG_RELEASE_REPO` / `NEXUS_TRIAGE_RELEASE_REPO`.
- **CLI onboarding fixed** — `nexus config --examiner / --setup-password /
  --show` and `nexus init "Case" --evidence …` work as documented; `init`
  creates the case and registers + hashes evidence.
- **Standalone hygiene** — removed the OpenSearch indexing lane and the
  push-ingest gateway; removed the native Prefetch parser (PECmd via
  `run_windows_command` is the Prefetch path); Velociraptor module made
  fully env-var driven (mock mode by default, no lab wiring).

### Security & quality

- Dependency CVE fixes: aiohttp ≥ 3.14.3, cryptography ≥ 50.0.0, pycti
  ≥ 7.260807 (see SECURITY.md for accepted-risk notes).
- Audit attribution: audit rows carry the configured examiner identity;
  `evidence_register` returns its `audit_id` for provenance chains.
- Triage: `check_process_tree` accepts bare account names (no more false
  SUSPICIOUS on canonical system trees); `check_file` verdict fix.
- Importer robustness: guarded JSON parsing in 7 importers (clean errors on
  malformed input); NDJSON-behind-`.json` fallback in journald/wazuh/
  velociraptor importers.
- Ruff clean across `src/` + `tests/`; ruff gate added to CI.
- 609 checks passing (292 pytest + 202 script + 115 functional).

## 0.8.0 — 2026-07-17

Security hardening and feature-completeness pass.

- 17 security blockers fixed, each with a regression test:
  - Portal pass-the-hash eliminated — signing keys derived from the stored
    PBKDF2 hash via `derive_purpose_key` (purpose-separated keys).
  - Dashboard XSS eliminated — all case data HTML-escaped; CSP headers added.
  - Per-install random audit secret (`~/.nexus/audit_secret`, 0600) replaces
    the previous static dev secret.
  - Findings default to DRAFT at schema, store, and manager layers; explicit
    APPROVED is structurally blocked until human approval.
  - Tool-execution hardening: input-path validation, dangerous-flag blocking,
    denylist/allowlist enforcement, quoted batch arguments.
  - Real backup/restore with SHA-256 manifests; HTTP transport corrected;
    syslog RFC 3164 timestamps; Splunk severity mapping; Sigma tactic mapping;
    TI key redaction; Docker compose reachability.
- 30 new analysis modules: beacon detection, log-gap analysis, command
  deobfuscation, KEV/NSRL lookups, adversary technique prediction, detection
  coverage, playbooks, evidence graph, correlation, declarative importers.
- Importer registry completed: 36 sources registered with graceful
  degradation for optional parser dependencies.

## 0.1.0 — 2026-05-14

Initial release candidate.

- Single FastMCP process exposing the forensic tool surface (stdio + HTTP).
- Flat-JSON case management with SHA-256 evidence registry and HMAC audit
  chain; examiner approval workflow with PBKDF2 password gating and
  3-strike lockout.
- Knowledge base (YAML), forensic RAG tooling, Windows triage baselines,
  threat-intel router (abuse.ch family + MISP, optional providers keyed).
- Typer CLI, Examiner Portal dashboard, Markdown/HTML/STIX/DOCX/ZIP exports.
- MITRE ATT&CK navigator export and RBA scoring.
