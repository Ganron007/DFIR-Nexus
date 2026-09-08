# Phase 4 Parity Checklist

This checklist verifies that the React SPA (`/portal/app/*`) achieves feature
parity with the legacy hand-written HTML pages (`/portal/*`). Once all items
are checked, the legacy HTML pages can be retired.

## Legend
- [x] = SPA has full parity
- [~] = SPA has partial parity (improvement needed)
- [ ] = SPA missing this feature

## Pages

| Legacy Page | SPA Route | Status | Notes |
|-------------|-----------|--------|-------|
| `/portal` (overview) | `/portal/app/` | [x] | Case summary + case list |
| `/portal/explore` | `/portal/app/explore` | [x] | Virtualized table, histogram, family+host facets, bookmarking |
| `/portal/timeline` | `/portal/app/timeline` | [x] | Per-family lanes, brush-zoom, lane filtering |
| `/portal/steer` | `/portal/app/steer` | [x] | Mode 1/2/3 switcher, proposal cards, Mode 3 plan/execute/seal flow |
| `/portal/workbench` | `/portal/app/workbench` | [x] | Bookmarked hits, drag-and-drop, undo/redo finding builder |
| `/portal/findings` | `/portal/app/findings` | [x] | Finding cards with status/confidence badges, LLM-drafted marker |
| `/portal/approve` | `/portal/app/approve` | [x] | DRAFT selection, HMAC challenge-response flow |
| `/portal/query` | (merged into /steer) | [x] | Query functionality is part of Steer Chat |
| `/portal/ask` | (merged into /steer) | [x] | Ask functionality is part of Steer Chat (Mode 1) |
| `/portal/evidence` | `/portal/app/evidence` | [x] | Evidence registry table |
| `/portal/iocs` | (merged into /evidence) | [~] | IOC list — currently part of evidence page, could be separate tab |
| `/portal/todos` | (not in SPA) | [ ] | TODO list — low priority, can be added later |

## API Endpoints

All 30 API endpoints are documented in `Docs/API-CONTRACT.md` and wired in
`frontend/src/api/client.ts`.

| Category | Endpoints | SPA Coverage |
|----------|-----------|-------------|
| Auth & Approval | commit/challenge, commit | [x] |
| Case Management | cases, activate, intake, query-rerun | [x] |
| Findings & Evidence | findings, timeline, evidence, iocs, todos, audit, summary, transparency | [x] (todos not displayed) |
| Mode 1 | ask, select | [x] (via Steer Chat) |
| Explore | search, histogram, aggregate | [x] |
| Workbench | add, remove, clear, promote | [x] |
| Chat | get, post, clear | [x] |
| Timeline | lanes | [x] |
| Entities | entities | [x] |
| Mode 2 | iterate, corroborate, propose-draft | [x] (iterate + propose-draft; corroborate not wired) |
| Mode 3 | plan, execute, seal | [x] |

## Known Gaps (non-blocking for Gate 4)

1. **IOCs page** — currently merged into Evidence; could be a separate tab.
2. **TODOs page** — not displayed in SPA; low priority.
3. **Corroborate endpoint** — wired in API client but not exposed in UI.
4. **Report viewer** — basic preview; needs proper markdown rendering.
5. **Admin page** — transparency log viewer not in SPA yet.
6. **SSE streaming** — chat uses request/response, not server-sent events.

## Gate 4 Criteria

- [x] All primary investigation pages have SPA equivalents
- [x] All 30 API endpoints are wired in the SPA API client
- [x] SPA builds cleanly (TypeScript strict, Vite production)
- [x] SPA tests pass (6 SPA serving tests)
- [x] Full test suite passes (468 passed, 1 skipped)
- [x] Legacy HTML pages remain available during transition
- [ ] Operator signs off on SPA parity
- [ ] Legacy HTML pages removed (post sign-off)
