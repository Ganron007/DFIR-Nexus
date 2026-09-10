# DFIR-Nexus Examiner Portal API Contract

> **Phase 4.1 — API contract freeze.** This document is the single source of
> truth for the React SPA frontend. Every `/portal/api/*` endpoint is
> described below with its HTTP method, path, request schema, response
> schema, error conditions, and a brief description.
>
> **Base URL:** `http://127.0.0.1:8080` (loopback-only by default).
>
> **Content-Type:** `application/json` for all POST request bodies.
>
> **Authentication:** No bearer token. Examiner identity is resolved
> server-side from environment / OS user. Approval endpoints use an
> HMAC challenge-response flow (never sends the password in plaintext).
>
> **Case scoping (Phase 4e):** Every endpoint that operates on a case accepts
> an explicit `X-Nexus-Case: <case_id>` request header (the React SPA sends it
> automatically) or a `?case_id=` query param. Explicit identity always wins
> over the server-side active-case pointer (`~/.nexus/active_case`); the
> pointer remains the fallback for CLI, MCP, and legacy HTML consumers.
> Evidence is stored in SQLite (system of record) and mirrored to
> `evidence.json` for legacy consumers.
>
> **Source file:** `src/nexus/dashboard/app.py` — route table in
> `create_dashboard()` (line 2300+), handlers defined above.

---

## Table of Contents

1. [Auth & Approval](#1-auth--approval)
2. [Case Management](#2-case-management)
3. [Findings & Evidence](#3-findings--evidence)
4. [Mode 1](#4-mode-1)
5. [Explore](#5-explore)
6. [Workbench](#6-workbench)
7. [Chat](#7-chat)
8. [Timeline](#8-timeline)
9. [Entities](#9-entities)
10. [Mode 2](#10-mode-2)
11. [Mode 3](#11-mode-3)
12. [HTML Page Routes (React Routes)](#12-html-page-routes-react-routes)
13. [Health](#13-health)

---

## 1. Auth & Approval

### GET /portal/api/commit/challenge
**Description:** Issues a challenge nonce + salt for password-based approval authentication. The examiner computes `HMAC-SHA256(pbkdf2(password, salt, 600000), nonce)` and submits it to `POST /portal/api/commit` or `POST /portal/api/mode3/seal`.

**Request:** No body. No query params.

**Response 200:**
```json
{
  "challenge_id": "string (32-char hex)",
  "nonce": "string (64-char hex)",
  "salt": "string",
  "iterations": 600000,
  "hash_algorithm": "SHA-256"
}
```

**Errors:**
- `401` — No examiner identity resolvable from environment.
- `403` — No password configured for the examiner (run `nexus config --setup-password`).
- `429` — Too many failed approval attempts (3-strike lockout, 15-minute window) OR too many active challenges (>1000).

---

### POST /portal/api/commit
**Description:** Approves one or more DRAFT findings using HMAC challenge-response authentication. Promotes each finding from `DRAFT` to `APPROVED`, writes an HMAC-signed entry to the verification ledger, and appends to the transparency log.

**Request:**
```json
{
  "challenge_id": "string (required — from GET /portal/api/commit/challenge)",
  "response": "string (required — HMAC-SHA256 hex of the nonce)",
  "finding_ids": ["string"] (required — list of finding IDs to approve; must be non-empty)
}
```

**Response 200:**
```json
{
  "status": "committed",
  "approved": ["string"] (finding IDs successfully approved),
  "errors": [{"id": "string", "error": "string"}] (per-finding errors),
  "examiner": "string"
}
```

**Errors:**
- `400` — Invalid JSON, missing `challenge_id` or `response`, or empty `finding_ids`.
- `401` — No examiner identity, invalid/expired challenge, challenge/examiner mismatch, or incorrect password (includes remaining attempt count; after 3 failures → lockout message).
- `403` — No password configured for examiner.
- `404` — No active case.
- `429` — Locked out due to too many failed attempts.
- `500` — Corrupted password entry (hash not valid hex).

---

## 2. Case Management

### GET /portal/api/cases
**Description:** Lists all case IDs (directories containing `CASE.yaml`), the currently active case, and a per-case summary map for the dashboard (name, status, mode, counts, pipeline/report flags).

**Request:** No body. No query params.

**Response 200:**
```json
{
  "cases": ["string"] (sorted case directory names),
  "active": "string" (active case ID, or "" if none),
  "details": {
    "CASE-XXXX-XXXX": {
      "case_id": "CASE-XXXX-XXXX",
      "name": "Campaign H — WS01",
      "status": "created",
      "mode": "1",
      "evidence_count": 3,
      "findings_count": 5,
      "approved_count": 2,
      "pipeline_complete": true,
      "report_exists": false
    }
  }
}
```

**Errors:** None (always 200).

---

### POST /portal/api/case/activate
**Description:** Switches the active case by writing the case ID to the active-case pointer file (`~/.nexus/active_case`).

**Request:**
```json
{
  "case_id": "string (required — case directory name)"
}
```

**Response 200:**
```json
{
  "ok": true,
  "active": "string" (the activated case ID)
}
```

**Errors:**
- `404` — Case directory not found under `cases_root`.

---

### POST /portal/api/case/deactivate
**Description:** Clears the active-case pointer ("Exit to Dashboard"). The case stays on disk untouched; the cockpit simply detaches so the dashboard can preview/enter cases without ambiguity.

**Request:** No body.

**Response 200:** `{"ok": true, "active": ""}`

**Errors:** None (always 200).

---

### POST /portal/api/case/reopen
**Description:** Reopens a sealed (completed), closed, or archived case and returns it to `ACTIVE`. Sealing is the completion gate: sealed cases reject mutating actions with `409` until reopened. The transition is audit-chained.

**Request:**
```json
{ "case_id": "CASE-XXXX-XXXX" }
```
`case_id` optional — falls back to the active case (or the `X-Nexus-Case` header).

**Response 200:**
```json
{ "ok": true, "status": "active", "reopened_from": "sealed" }
```
If the case is already open: `{"ok": true, "status": "created", "note": "already open"}`.

**Errors:** `404` case not found. `409` from any mutating endpoint (evidence register, pipeline run, mode change, workbench promote, mode 2/3 actions) while the case is `SEALED`.

---

### POST /portal/api/intake
**Description:** Persists N1 intake fields (question, window, extras, playbooks, subjects, hypothesis, query_extra) into the active case's `CASE.yaml` under the `intake` key. Only non-empty fields are written; existing fields are merged.

**Request:**
```json
{
  "question": "string (optional)",
  "window": "string (optional — e.g. '2026-08-01..2026-08-10')",
  "extras": "string (optional — comma-separated: chrome_profiles,drivefs,email,usb_serial)",
  "playbooks": "string (optional)",
  "subjects": "string (optional)",
  "hypothesis": "string (optional)",
  "query_extra": "string (optional — comma-separated extra needles)"
}
```

**Response 200:**
```json
{
  "ok": true,
  "intake": {"field": "string"} (the full written intake dict)
}
```

**Errors:**
- `400` — No active case.

---

### POST /portal/api/query-rerun
**Description:** Re-runs the N4 query pack. If `needles` are provided, runs an ad-hoc query (optionally persisting them to intake). If no needles, regenerates the query pack markdown file.

**Request:**
```json
{
  "needles": "string (optional — comma-separated search terms)",
  "persist": "boolean (optional — persist needles to intake; only if needles non-empty)",
  "limit": "integer (optional — max hits, default 80)"
}
```

**Response 200 (with needles):**
```json
{
  "ok": true,
  "backend": "string",
  "terms": ["string"],
  "count": 0,
  "hits": [{"family": "string", "file": "string", "line": "string", "terms": "string", "text": "string"}],
  "persisted": false,
  "empty": true
}
```

**Response 200 (without needles):**
```json
{
  "ok": true,
  "query_pack": "string (path to regenerated query_pack.md)"
}
```

**Errors:**
- `400` — No active case.

---

## 3. Findings & Evidence

### GET /portal/api/findings
**Description:** Returns findings from the active case, optionally filtered by status and limited in count.

**Request:** Query params:
- `status` (string, optional — e.g. `DRAFT`, `APPROVED`, `REJECTED`; case-insensitive)
- `limit` (integer, optional — max number of findings; 0 = all)

**Response 200:**
```json
{
  "findings": [
    {
      "id": "string",
      "case_id": "string",
      "status": "string (DRAFT | APPROVED | REJECTED)",
      "title": "string",
      "observation": "string",
      "interpretation": "string",
      "confidence": "string (LOW | MEDIUM | HIGH | SPECULATIVE)",
      "confidence_justification": "string",
      "evidence": [{"source": "string", "...": "..."}],
      "type": "string",
      "host": "string",
      "affected_account": "string",
      "event_timestamp": "string",
      "attack_ids": ["string"],
      "audit_ids": ["string"],
      "iocs": [{"value": "string", "type": "string", "category": "string"}],
      "artifacts": [{"type": "string", "value": "string", "audit_id": "string", "source": "string"}],
      "examiner": "string",
      "created_at": "string (ISO 8601)",
      "modified_at": "string (ISO 8601)",
      "approved_by": "string (present if APPROVED)",
      "approved_at": "string (ISO 8601, present if APPROVED)"
    }
  ],
  "total": 0
}
```

**Errors:** None (returns empty list if no case or no findings).

---

### GET /portal/api/timeline
**Description:** Returns timeline events from the active case, optionally filtered by event type and limited.

**Request:** Query params:
- `event_type` (string, optional)
- `limit` (integer, optional — 0 = all)

**Response 200:**
```json
{
  "events": [
    {
      "timestamp": "string",
      "description": "string",
      "event_type": "string",
      "host": "string",
      "source": "string"
    }
  ],
  "total": 0
}
```

**Errors:** None (returns empty list if no case).

---

### GET /portal/api/evidence
**Description:** Returns the evidence registry for the resolved case (explicit `X-Nexus-Case`/`case_id`, else the active case). Reads the SQLite system of record; legacy flat registries are imported once. This is the same source used by `/summary`, `/case/{id}/details`, and `/evidence/verify`.

**Request:** No body.

**Response 200:**
```json
{
  "evidence": [
    {
      "id": "string",
      "path": "string",
      "sha256": "string",
      "description": "string",
      "registered_at": "string",
      "status": "registered",
      "name": "string",
      "kind": "file",
      "files": 1,
      "total_bytes": 1234
    }
  ],
  "total": 0
}
```

**Errors:** None (returns an empty list if no case is resolved).

---

### POST /portal/api/evidence
**Description:** Registers a new evidence file or directory with the resolved case. Writes to the SQLite evidence registry (system of record) and refreshes the `evidence.json` mirror. Files hash their contents; directories hash a deterministic recursive manifest (relative path + size + file hash), so re-registering unchanged content is idempotent.

**Request:**
```json
{
  "path": "string (required — filesystem path to file or directory; must exist)",
  "case_id": "string (optional — explicit case; header also accepted)",
  "description": "string (optional)"
}
```

**Response 200:**
```json
{
  "ok": true,
  "case_id": "CASE-XXXX-XXXX",
  "status": "registered",
  "path": "string (resolved path)",
  "sha256": "string (hex digest)",
  "files": 1,
  "total_bytes": 1234,
  "registered_at": "string"
}
```

**Errors:**
- `400` — No case resolved, or `path` missing / does not exist.
- `409` — Same path already registered with different content.

---

### GET /portal/api/iocs
**Description:** Returns all IOCs extracted from findings in the active case. Each IOC is annotated with its parent finding's title and status.

**Request:** No body. No query params.

**Response 200:**
```json
{
  "iocs": [
    {
      "value": "string (or 'indicator')",
      "type": "string",
      "context": "string",
      "finding_title": "string",
      "finding_status": "string"
    }
  ],
  "total": 0
}
```

**Errors:** None (returns empty list if no case).

---

### GET /portal/api/todos
**Description:** Returns TODO items from the active case, optionally filtered by status.

**Request:** Query params:
- `status` (string, optional — e.g. `open`, `completed`)

**Response 200:**
```json
{
  "todos": [
    {
      "todo_id": "string (or 'id')",
      "description": "string",
      "status": "string (default 'open')",
      "priority": "string (default 'medium')",
      "assignee": "string"
    }
  ],
  "total": 0
}
```

**Errors:** None (returns empty list if no case).

---

### GET /portal/api/audit/{finding_id}
**Description:** Returns audit log entries that reference the given finding ID. Scans all `*.jsonl` files in the case's `audit/` directory and returns entries where the finding_id appears in the JSON.

**Request:** Path param:
- `{finding_id}` — the finding ID to search for

**Response 200:**
```json
{
  "entries": [{}],
  "finding_id": "string",
  "total": 0
}
```

**Errors:**
- `400` — Missing `finding_id` path param.
- `404` — No active case.

---

### GET /portal/api/summary
**Description:** Returns aggregate counts for the active case dashboard: findings by status, timeline event count, evidence count, and TODO counts.

**Request:** No body. No query params.

**Response 200:**
```json
{
  "findings": {
    "total": 0,
    "draft": 0,
    "approved": 0,
    "rejected": 0
  },
  "timeline": 0,
  "evidence": 0,
  "todos": {
    "total": 0,
    "open": 0
  }
}
```

**Errors:** None (returns zeros if no case).

---

### GET /portal/api/transparency
**Description:** Verifies the hash-chain integrity of the transparency log for the active case. Walks the entire chain, recomputing each link's hash and checking it against the stored `previous_hash`.

**Request:** No body. No query params.

**Response 200 (valid chain):**
```json
{
  "valid": true,
  "entries": 0
}
```

**Response 200 (invalid chain):**
```json
{
  "valid": false,
  "entries": 0,
  "tampered": 0,
  "expected": "string (recomputed hash)",
  "actual": "string (stored hash)"
}
```

**Response 200 (no log):**
```json
{
  "valid": false,
  "entries": 0,
  "error": "No transparency log found"
}
```

**Errors:**
- `404` — No active case.

---

## 4. Mode 1

### POST /portal/api/mode1/ask
**Description:** Mode 1 natural-language query. The scribe is **grounded with case context** (Phase 4g): evidence families present, playbook terms/caveats for those families, RAG methodology, already-searched needles, and the case intake. Deterministic entity extraction (IPs, domains, URLs, hashes, paths, `DOMAIN\user`) always contributes needles, LLM or not. Runs an N4 ad-hoc query (persisting needles to intake) and returns the hits.

**Request:**
```json
{
  "question": "string (required — natural language question)",
  "limit": "integer (optional — max hits, default 80)"
}
```

**Response 200 (with needles):**
```json
{
  "needles": ["string"],
  "window": "string",
  "hits": [
    {"family": "string", "file": "string", "line": "string", "terms": "string", "text": "string"}
  ],
  "count": 0,
  "backend": "string",
  "rationale": "string (one sentence, LLM only)",
  "entities": {"ipv4": ["10.0.0.5"], "domain": ["evil.example.com"]},
  "families": ["evtxecmd", "hayabusa"],
  "context_sources": ["n4-families", "playbooks", "playbook-caveats", "rag"],
  "source": "llm|heuristic"
}
```

**Response 200 (no needles extracted):**
```json
{
  "needles": [],
  "window": "string",
  "error": "No needles extracted"
}
```

**Errors:**
- `400` — Missing `question`.
- `404` — No active case.

---

### POST /portal/api/mode1/select
**Description:** Promotes selected N4 hit indices to a DRAFT finding. Re-runs the N4 query (using explore filters or persisted intake) to stabilize hit indices, then stages the finding. Optionally runs the LLM scribe to fill in observation/interpretation/confidence.

**Request:**
```json
{
  "hits": ["string"] (required — 1-based hit indices as strings, e.g. ["1", "3"]),
  "title": "string (required — finding title)",
  "scribe": "boolean (optional — run LLM scribe, default true)",
  "needles": "string (optional — comma-separated needles to re-run query)",
  "family": "string (optional — comma-separated family filter)",
  "start": "string (optional — date filter YYYY-MM-DD)",
  "end": "string (optional — date filter YYYY-MM-DD)",
  "interpretation": "string (optional — examiner interpretation hint)"
}
```

**Response 200 (staged):**
```json
{
  "finding_id": "string",
  "title": "string",
  "status": "DRAFT",
  "audit_ids": ["string"]
}
```

**Response 200 (rejected — validation/provenance failure):**
```json
{
  "error": ["string"] (list of error details)
}
```

**Errors:**
- `400` — Missing title, no hits selected, invalid hit indices, indices out of range, no hits loaded (run ask first), or no active case.
- `404` — No active case.

---

## 5. Explore

### POST /portal/api/explore/search
**Description:** Faceted N4 search over parsed evidence. Supports a DSL query (AND/OR/NOT, field filters like `family:`, `host:`, `user:`, `event:`, `file:`, `regex:<pattern>`), plain needles, family filter, and date range. DSL query takes precedence over plain needles; both are merged.

**Request:**
```json
{
  "query": "string (optional — DSL query text, e.g. 'error AND family:evtx NOT defender')",
  "needles": "string (optional — comma-separated plain search terms)",
  "family": "string (optional — comma-separated family names to filter)",
  "start": "string (optional — start date YYYY-MM-DD)",
  "end": "string (optional — end date YYYY-MM-DD)",
  "limit": "integer (optional — max hits, clamped 1-400, default 80)",
  "offset": "integer (optional — pagination offset, default 0)"
}
```

**Response 200:**
```json
{
  "hits": [
    {"family": "string", "file": "string", "line": "string", "terms": "string", "text": "string"}
  ],
  "count": 0,
  "total_before_family_filter": 0,
  "backend": "string",
  "families": ["string"] (available extraction families),
  "needles": ["string"] (effective query terms),
  "query": "string (effective query description)",
  "offset": 0
}
```

**Errors:**
- `400` — `limit`/`offset` not integers, or query syntax error.
- `404` — No active case.

---

### POST /portal/api/explore/histogram
**Description:** Returns time-bucketed hit counts for the current search context. Buckets hits by date (and optionally hour) based on date patterns found in hit row text.

**Request:**
```json
{
  "needles": "string (optional — comma-separated search terms)",
  "family": "string (optional — comma-separated family filter)",
  "start": "string (optional — start date YYYY-MM-DD)",
  "end": "string (optional — end date YYYY-MM-DD)",
  "bucket": "integer (optional — bucket size in minutes, default 60; 1440 = daily)"
}
```

**Response 200:**
```json
{
  "buckets": {"YYYY-MM-DD": 0, "YYYY-MM-DDTHH:00": 0},
  "count": 0
}
```

**Errors:**
- `404` — No active case.

---

### POST /portal/api/explore/aggregate
**Description:** Aggregates hit counts grouped by family, hour, day, or file. Uses the DSL query to select hits.

**Request:**
```json
{
  "query": "string (optional — DSL query text)",
  "group_by": "string (optional — 'family' | 'hour' | 'day' | 'file', default 'family')"
}
```

**Response 200:**
```json
{
  "group_by": "string",
  "buckets": {"string": 0},
  "total": 0
}
```

**Errors:**
- `400` — Unknown `group_by` value, or query syntax error.
- `404` — No active case.

---

## 6. Workbench

### GET /portal/api/workbench
**Description:** Lists all bookmarked hits in the active case's workbench (`workbench.json`).

**Request:** No body. No query params.

**Response 200:**
```json
{
  "bookmarks": [
    {
      "id": "string (e.g. 'B-001')",
      "family": "string",
      "file": "string",
      "line": "string",
      "time": "string (extracted timestamp or empty)",
      "text": "string (truncated to 500 chars)",
      "note": "string (max 300 chars)",
      "bookmarked_at": "string (ISO 8601)"
    }
  ],
  "total": 0
}
```

**Errors:**
- `404` — No active case.

---

### POST /portal/api/workbench/add
**Description:** Bookmarks a single hit to the workbench. Deduplicates on `(family, file, line)`.

**Request:**
```json
{
  "hit": {
    "family": "string (required if no file/text)",
    "file": "string (required if no text)",
    "line": "string (optional)",
    "text": "string (optional)",
    "terms": "string (optional)"
  },
  "note": "string (optional — max 300 chars)"
}
```

**Response 200 (new bookmark):**
```json
{
  "status": "added",
  "bookmark_id": "string (e.g. 'B-001')",
  "total": 0
}
```

**Response 200 (duplicate):**
```json
{
  "status": "exists",
  "bookmark_id": "string",
  "total": 0
}
```

**Errors:**
- `400` — Missing hit data (hit must be a dict with at least `file` or `text`).
- `404` — No active case.

---

### POST /portal/api/workbench/remove
**Description:** Removes a single bookmark by ID.

**Request:**
```json
{
  "bookmark_id": "string (required — e.g. 'B-001')"
}
```

**Response 200 (removed):**
```json
{
  "status": "removed",
  "total": 0
}
```

**Response 200 (not found):**
```json
{
  "status": "not_found",
  "total": 0
}
```

**Errors:**
- `404` — No active case.

---

### POST /portal/api/workbench/clear
**Description:** Clears all bookmarks from the workbench (deletes `workbench.json`).

**Request:** No body required.

**Response 200:**
```json
{
  "status": "cleared"
}
```

**Errors:**
- `404` — No active case.

---

### POST /portal/api/workbench/promote
**Description:** Promotes selected workbench bookmarks to a DRAFT finding. Runs the same promote-to-draft + optional scribe flow as `/portal/api/mode1/select`, but uses bookmarked hits instead of live query indices.

**Request:**
```json
{
  "bookmark_ids": ["string"] (required — bookmark IDs, e.g. ["B-001", "B-003"]),
  "title": "string (required — finding title)",
  "scribe": "boolean (optional — run LLM scribe, default true)",
  "interpretation": "string (optional — examiner interpretation hint)"
}
```

**Response 200 (staged):**
```json
{
  "finding_id": "string",
  "status": "DRAFT",
  "title": "string",
  "bookmark_count": 0
}
```

**Response 200 (rejected):**
```json
{
  "error": ["string"] (list of error details)
}
```

**Errors:**
- `400` — Missing title, no bookmarks selected, or bookmark IDs not found.
- `404` — No active case.

---

## 7. Chat

### GET /portal/api/chat
**Description:** Returns the steer-chat transcript for the active case (`chat.jsonl`). Messages are returned in chronological order (last 200).

**Request:** No body. No query params.

**Response 200:**
```json
{
  "messages": [
    {
      "ts": "string (ISO 8601)",
      "role": "string (examiner | llm | system)",
      "action": "string (e.g. 'ask', 'query_run', 'mode2_proposal', 'mode3_plan')",
      "text": "string (max 2000 chars)",
      "meta": {"string": "string"} (optional — metadata, values max 300 chars)
    }
  ],
  "total": 0
}
```

**Errors:**
- `404` — No active case.

---

### POST /portal/api/chat
**Description:** Sends an examiner message to the steer chat. The message is logged, then processed through the Mode 1 ask flow (NL → needles → N4 query). The LLM reply and query results are logged to the transcript.

**Request:**
```json
{
  "message": "string (required — examiner's question)"
}
```

**Response 200 (with needles and hits):**
```json
{
  "reply": "string (e.g. 'Needles: sdelete, .pst | hits: 42 | ...')",
  "needles": ["string"],
  "window": "string",
  "hits": [
    {"family": "string", "file": "string", "line": "string", "terms": "string", "text": "string"}
  ],
  "count": 0,
  "backend": "string"
}
```

**Response 200 (no needles extracted):**
```json
{
  "reply": "string (guidance message)",
  "needles": [],
  "count": 0
}
```

**Errors:**
- `400` — Empty message, or query error from N4 backend.
- `404` — No active case.

---

### POST /portal/api/chat/clear
**Description:** Wipes the steer-chat transcript for the active case (deletes `chat.jsonl`).

**Request:** No body required.

**Response 200:**
```json
{
  "status": "cleared"
}
```

**Errors:**
- `404` — No active case.

---

## 8. Timeline

### POST /portal/api/timeline/lanes
**Description:** Returns per-family time-bucketed hit counts for timeline lane visualization. Uses the DSL query to select hits, then buckets each hit by day or hour based on date patterns in the row text.

**Request:**
```json
{
  "query": "string (optional — DSL query text)",
  "needles": "string (optional — comma-separated search terms)",
  "family": "string (optional — comma-separated family filter, not used in this handler)",
  "start": "string (optional — not used in this handler)",
  "end": "string (optional — not used in this handler)",
  "bucket": "string (optional — 'hour' | 'day', default 'hour')"
}
```

**Response 200:**
```json
{
  "families": [
    {
      "family": "string",
      "buckets": {"YYYY-MM-DD": 0, "YYYY-MM-DDTHH:00": 0}
    }
  ],
  "total": 0,
  "bucket": "string (hour | day)"
}
```

**Errors:**
- `400` — Query syntax error.
- `404` — No active case.

---

## 9. Entities

### POST /portal/api/entities
**Description:** Extracts entities (IPs, users, processes, paths) from current N4 hit row text using regex patterns. Returns counts per entity, most frequent first. Feeds the Explore entity-pivot panel.

**Request:**
```json
{
  "query": "string (optional — DSL query text to select hits)"
}
```

**Response 200:**
```json
{
  "entities": {
    "ips": {"string": 0},
    "users": {"string": 0},
    "processes": {"string": 0},
    "paths": {"string": 0}
  },
  "total": 0
}
```

**Errors:**
- `400` — Query syntax error.
- `404` — No active case.

---

## 10. Mode 2

### POST /portal/api/mode2/iterate
**Description:** Mode 2 iterative loop: query → analyze → propose new needles → re-query. Every iteration is logged to the case chat transcript. Hard cap on iterations (1-4, default 2). The loop NEVER writes findings — it returns the iteration log for examiner review.

**Request:**
```json
{
  "question": "string (required — investigation question)",
  "max_iterations": "integer (optional — 1-4, default 2, hard-capped at 4)",
  "limit": "integer (optional — max hits per query, default 80)"
}
```

**Response 200:**
```json
{
  "question": "string",
  "iterations": [
    {
      "iteration": 0,
      "action": "string (initial_query | proposed_and_ran | no_new_proposals)",
      "needles": ["string"],
      "hits": 0,
      "backend": "string",
      "rationale": "string (for proposed iterations)",
      "source": "string (for proposed iterations)",
      "new_families": ["string"] (for proposed iterations)
    }
  ],
  "total_hits": 0,
  "needles_run": ["string"],
  "capped": false
}
```

**Errors:**
- `400` — Missing question, `max_iterations` not an integer, no needles extracted from question, or query error.
- `404` — No active case.

---

### POST /portal/api/mode2/corroborate
**Description:** Runs an FD-006/007 corroboration check on a finding. Checks whether the finding has sufficient evidence family diversity and audit_id count for its confidence level. Returns problems and suggested corroboration queries.

**Request:**
```json
{
  "finding_id": "string (optional — if provided, loads finding from findings.json)",
  "finding": {} (optional — full finding dict; takes precedence over finding_id)
}
```

**Response 200:**
```json
{
  "families": ["string"],
  "distinct_families": 0,
  "confidence": "string (LOW | MEDIUM | HIGH | SPECULATIVE)",
  "ok": true,
  "problems": ["string"],
  "suggested_queries": ["string"]
}
```

**Errors:**
- `404` — No active case, or finding not found (neither `finding` nor `finding_id` resolved to a finding).

---

### POST /portal/api/mode2/propose-draft
**Description:** LLM drafts a finding from hits (or from a query that produces hits). The draft is staged as DRAFT with `examiner_selected=False` — the examiner reviews, edits, and approves via the normal HMAC flow. The LLM never approves.

**Request:**
```json
{
  "title": "string (required — finding title)",
  "hits": [{}] (optional — list of hit dicts; if omitted, `query` is used),
  "query": "string (optional — DSL query to fetch hits if `hits` not provided; limit 12)"
}
```

**Response 200 (staged):**
```json
{
  "finding_id": "string",
  "status": "DRAFT",
  "corroboration": {
    "families": ["string"],
    "distinct_families": 0,
    "confidence": "string",
    "ok": true,
    "problems": ["string"],
    "suggested_queries": ["string"]
  }
}
```

**Response 200 (rejected):**
```json
{
  "error": ["string"] (list of error details)
}
```

**Errors:**
- `400` — Missing title, no hits to draft from, or draft staging error.
- `404` — No active case.

---

## 11. Mode 3

### POST /portal/api/mode3/plan
**Description:** Agent proposes an investigation plan. Reads the tool-lane ledger (SKIPs), known extras not yet requested, and FD-006 corroboration needs from existing findings. LLM refines the rationale when configured. Logged to `agent_runs.jsonl` + chat. The examiner approves items before execution.

**Request:** No body required (empty JSON `{}` is acceptable).

**Response 200:**
```json
{
  "case_id": "string",
  "items": [
    {
      "type": "string (extra | tool_skip)",
      "key": "string (for type=extra)",
      "purpose": "string (for type=extra)",
      "tool": "string (for type=tool_skip)",
      "reason": "string (for type=tool_skip)"
    }
  ],
  "queries": ["string"] (corroboration queries, max 8),
  "rationale": "string",
  "created_at": "string (ISO 8601)",
  "lane_complete": true
}
```

**Errors:**
- `404` — No active case.

---

### POST /portal/api/mode3/execute
**Description:** Runs examiner-approved plan items. Extras are persisted to `CASE.yaml` intake (next lane run parses them; mandatory lane must complete first). Queries run immediately as read-only N4 searches. Everything is logged to `agent_runs.jsonl` + chat.

**Request:**
```json
{
  "extras": ["string"] (optional — list of extra keys to persist, e.g. ["usb_serial", "email"]),
  "queries": ["string"] (optional — list of DSL queries to run immediately)
}
```

**Response 200:**
```json
{
  "status": "executed",
  "extras_persisted": ["string"],
  "query_results": [
    {
      "query": "string",
      "count": 0,
      "error": "string | null"
    }
  ],
  "note": "string (guidance about next lane run)"
}
```

**Errors:**
- `400` — Invalid JSON, `extras` or `queries` not lists, mandatory lane not complete, or execution error.
- `404` — No active case.

---

### POST /portal/api/mode3/seal
**Description:** Case-file HMAC seal via challenge-response. Reuses the same challenge-response flow as per-finding approval (get a challenge from `GET /portal/api/commit/challenge` first). Computes an HMAC signature over `REPORT.md` content and writes it to the verification ledger. Requires a generated report first.

**Request:**
```json
{
  "challenge_id": "string (required — from GET /portal/api/commit/challenge)",
  "response": "string (required — HMAC-SHA256 hex of the nonce)",
  "examiner": "string (optional — overrides resolved examiner identity)"
}
```

**Response 200:**
```json
{
  "status": "SEALED",
  "case_id": "string",
  "examiner": "string"
}
```

**Errors:**
- `400` — Invalid JSON, missing `challenge_id` or `response`, no `REPORT.md` (generate report first), or seal error.
- `401` — No examiner identity, invalid/expired challenge, challenge/examiner mismatch, or challenge response mismatch.
- `403` — No password configured for examiner.
- `404` — No active case.

---

## 11b. RAG Preflight (WP 3.13)

### GET /portal/api/rag/status
**Description:** RAG readiness preflight. Verifies that the embedding model loads, the Chroma collection opens, the index has sufficient records, and a test query returns results. Mode 3 orchestrator and any RAG-dependent workflow should check this before starting.

**Request:** No body required.

**Response 200:**
```json
{
  "ready": true,
  "embedding_model": "BAAI/bge-base-en-v1.5",
  "model_source": "hf_hub_cache",
  "document_count": 23000,
  "source_count": 12,
  "test_query_returned": true,
  "errors": [],
  "error": ""
}
```

**Response 200 (not ready):**
```json
{
  "ready": false,
  "embedding_model": "",
  "model_source": "",
  "document_count": 0,
  "source_count": 0,
  "test_query_returned": false,
  "errors": ["RAG index not found: ..."],
  "error": "RAG index not found: ..."
}
```

**Response 500:**
```json
{
  "ready": false,
  "error": "string",
  "errors": ["string"]
}
```

**Notes:**
- `ready` is `true` only when all checks pass: dependencies installed, model loaded, Chroma opened, index > 1000 records, test query returned results.
- `test_query_returned` is `false` if the embedder + Chroma are loaded but the test query returned no results (possible embedder/index mismatch).
- This endpoint is also exposed via `nexus doctor --rag` CLI command.

---

## 11c. Phase 4b — Workflow-driven cockpit APIs

### POST /portal/api/case/create
**Description:** Create a new investigation case. Does **not** switch the active case unless `activate: true` is explicitly passed — the wizard registers evidence/mode against the returned `case_id` and activates on "Enter Cockpit". CLI `nexus case init` / MCP `case_init` remain create+activate.

**Request:**
```json
{
  "name": "Campaign H — WS01 Investigation",
  "description": "Optional description",
  "examiner": "analyst_t1",
  "mode": "1",
  "activate": false
}
```
- `activate` (optional, default `false`) — write the active-case pointer on creation.

**Response 200:**
```json
{
  "ok": true,
  "case_id": "CASE-XXXX-XXXX",
  "name": "Campaign H — WS01 Investigation",
  "active": "string (current pointer value, or \"\")"
}
```

**Response 400:** `{"error": "name is required"}` or `{"error": "Case already exists: ..."}`

---

### GET /portal/api/case/details
**Description:** Get case metadata, evidence count, findings count, pipeline status, and the SQLite lifecycle status. Without an explicit id it uses the active case.

**Path variant:** `GET /portal/api/case/{case_id}/details` — same handler, explicit case id, works with no active case.
**Query params:** `case_id` (optional)

**Response 200:**
```json
{
  "case_id": "CASE-XXXX-XXXX",
  "name": "Campaign H — WS01 Investigation",
  "description": "...",
  "status": "created",
  "investigation_mode": "1",
  "evidence_count": 3,
  "findings_count": 5,
  "approved_count": 2,
  "pipeline_complete": true,
  "report_exists": false
}
```

**Response 404:** `{"error": "No case specified"}` or `{"error": "Case not found"}`

---

### POST /portal/api/pipeline/run
**Description:** Trigger the N2 processing lane (or interpret/coverage/design) asynchronously. Returns a `run_id` for status polling. The pipeline runs in a background thread.

**Request:**
```json
{
  "mode": "tools",
  "case_id": "CASE-XXXX-XXXX"
}
```
- `mode`: one of `tools`, `interpret`, `coverage`, `design`
- `case_id`: optional; defaults to active case

**Response 200:**
```json
{
  "run_id": "abc12345",
  "case_id": "CASE-XXXX-XXXX",
  "mode": "tools",
  "status": "running"
}
```

**Response 400:** `{"error": "Invalid mode: ..."}` or `{"error": "No active case"}` (404)

---

### GET /portal/api/pipeline/status
**Description:** Poll the status of a pipeline run. State is held in memory and written through to `<case>/analysis/pipeline_runs/<run_id>.json`, so it survives page reload and server restart; a stale `running` record is reconciled against the immutable run manifest.

**Query params:** `run_id` (required)

**Response 200:**
```json
{
  "run_id": "abc12345",
  "case_id": "CASE-XXXX-XXXX",
  "mode": "tools",
  "status": "complete",
  "started_at": "2026-09-10T...",
  "completed_at": "2026-09-10T...",
  "error": "",
  "stages": []
}
```

**Response 404:** `{"error": "run_id not found"}`

---

### GET /portal/api/playbook/needles
**Description:** Return playbook-suggested search needles for the given evidence families (or all playbooks if no families specified).

**Query params:** `families` (optional, comma-separated, e.g. `evtx,registry,prefetch`)

**Response 200:**
```json
{
  "suggestions": [
    {
      "playbook": "Suspicious Execution",
      "slug": "suspicious_execution",
      "needles": ["powershell.exe", "cmd.exe", "wscript.exe"],
      "caveats": ["Legitimate admin tools may trigger..."],
      "triggers": ["Suspicious command-line arguments..."]
    }
  ],
  "total": 22
}
```

---

### POST /portal/api/case/mode
**Description:** Set the investigation mode (1/2/3) for the resolved case (explicit `case_id`/header, else the active case). Stored in `CASE.yaml`; used by the wizard before the case is active.

**Request:**
```json
{
  "mode": "1",
  "case_id": "CASE-XXXX-XXXX"
}
```
- `case_id` (optional) — explicit target case.

**Response 200:** `{"ok": true, "mode": "1"}`
**Response 400:** `{"error": "mode must be 1, 2, or 3"}`
**Response 404:** `{"error": "No case specified"}`

---

### GET /portal/api/case/mode
**Description:** Get the investigation mode for the resolved case.

**Query params:** `case_id` (optional)

**Response 200:** `{"mode": "1"}` (empty string if not set)
**Response 404:** `{"error": "No active case"}`

---

### GET /portal/api/system/health
**Description:** Cheap component status for dashboards (landing page + cockpit Overview). Reports configured/reachable state without heavy preflight — deep verification stays in `nexus doctor` and `GET /portal/api/rag/status`.

**Response 200:**
```json
{
  "backend": "ok",
  "es": {"configured": true, "reachable": true, "url": "http://..."},
  "rag": {"configured": true},
  "llm": {"configured": true, "model": "openai/gpt-4o"},
  "parser": "ok"
}
```
- `es.configured=false` means `NEXUS_ES_URL` is empty (CSV pack backend — not an error).
- `rag.configured` reports index presence only (no model load); use `/rag/status` for the full preflight.
- `llm.configured=false` means heuristic scribe fallback is active (not an error).

---

### POST /portal/api/chat/stream
**Description:** Live steer-chat turn (WP 4d.3). Runs the Mode 1 ask flow or the Mode 2 iterative loop and streams progress as Server-Sent Events. The examiner message and final reply are persisted to the case transcript; top hits are persisted in the reply entry's `data.hits` so hit cards survive reload.

**Request:**
```json
{
  "message": "show me sdelete and prefetch activity",
  "mode": "mode1",
  "max_iterations": 2
}
```
- `mode`: `mode1` (ask → query) or `mode2` (iterative loop)
- `max_iterations`: Mode 2 only, 1–5 (default 2)

**Response:** `text/event-stream` with events:
```
event: status     data: {"stage": "translating"|"querying", ...}
event: iteration  data: {"iteration": 0, "action": "initial_query", "needles": [...], "hits": N, ...}
event: hits       data: {"hits": [...capped 12 trimmed hits...], "count": N}
event: done       data: {"reply": "...", "needles": [...], "count": N, "backend": "..."}
event: error      data: {"error": "..."}
event: ping       data: {}   (keepalive every 30s while working)
```

**Notes:**
- Mode 2 `iteration` events come from `run_iterative_loop`'s `on_event` callback (WP 4d.3).
- `hits` payloads include parsed `fields` + best-effort `host` per hit (WP 4d.1).
- Non-SSE fallback: `POST /portal/api/chat` (blocking) remains available.

---

### Explore hit enrichment (WP 4d.1)

`POST /portal/api/explore/search` responses now attach per-hit:
- `fields` — parsed CSV columns (header → value, quoted-comma safe, capped 24 fields / 160 chars)
- `host` — best-effort hostname (Computer column or `\\UNC` path)

And accept an optional `"host"` filter (exact, case-insensitive).

`POST /portal/api/explore/aggregate` accepts `group_by: family|host|hour|day|file`.

---

### GET /portal/api/fs/list
**Description:** Read-only filesystem listing for the evidence picker (WP 4d.8 + 4e.9). The server runs on the examiner's machine, so this browses the same filesystem the pipeline reads from. Never returns file contents.

**Query params:** `path` (optional) — a directory or file. Omitted → list drives (Windows) or root (POSIX).

**Response 200 (directory):**
```json
{
  "path": "C:\\Evidence\\ws01",
  "parent": "C:\\Evidence",
  "drives": false,
  "entries": [
    {"name": "evtx", "path": "C:\\Evidence\\ws01\\evtx", "is_dir": true, "size": null},
    {"name": "bits_openvpn.evtx", "path": "C:\\Evidence\\ws01\\evtx\\bits_openvpn.evtx", "is_dir": false, "size": 139264}
  ]
}
```

**Response 200 (file path — WP 4e.9):**
```json
{
  "path": "C:\\Evidence\\ws01\\evtx",
  "parent": "C:\\Evidence\\ws01",
  "drives": false,
  "is_file": true,
  "file_entry": {"name": "bits_openvpn.evtx", "path": "C:\\Evidence\\ws01\\evtx\\bits_openvpn.evtx", "is_dir": false, "size": 139264},
  "entries": []
}
```
When `is_file` is true, the picker shows an "Add This File" prompt using `file_entry`.

**Errors:** 404 `path not found`.

---

### GET /portal/api/pipeline/ledger
**Description:** Tool-lane ledger for the resolved case (parser visibility). Returns the per-parser status from the active tools run — used by the Evidence page panel and the Mode 1 wizard's "Run N2 Processing Lane" step, which gates cockpit entry on lane completion.

**Query params:** `case_id` (optional — explicit case; the SPA `X-Nexus-Case` header also resolves it). Without either, the active case is used.

**Response 200:**
```json
{
  "run_id": "20260910-120000-ab12cd34",
  "ledger": [
    {"tool": "evtxecmd", "status": "OK", "detail": "...", "audit_id": "..."},
    {"tool": "pecmd", "status": "SKIP", "detail": "no prefetch artifacts"}
  ],
  "extractions": "C:\\...\\extractions"
}
```
Empty `ledger` + empty `run_id` = no tools run has executed yet for this case.

---

## 12. HTML Page Routes (React Routes)

These are server-side rendered HTML pages in the current portal. In the React SPA rewrite, these become client-side routes. Each renders the `_TEMPLATE` wrapper with case-data content.

| Route | Handler | Description |
|------|---------|-------------|
| `GET /portal` | `overview` | Case dashboard: summary cards (approved/draft/rejected findings, timeline events, evidence files, open TODOs) + 5 most recent findings. |
| `GET /portal/` | `overview` | Same as `/portal`. |
| `GET /portal/findings` | `findings_page` | Findings table with status filter (`?status=DRAFT\|APPROVED\|REJECTED`). Columns: Status, Title, Confidence, Type, Host, MITRE, Date. |
| `GET /portal/approve` | `approve_page` | DRAFT findings approval page with checkboxes and password prompt. Calls `GET /portal/api/commit/challenge` + `POST /portal/api/commit`. |
| `GET /portal/timeline` | `timeline_page` | Timeline events table sorted by timestamp. Columns: Timestamp, Description, Type, Host, Source. |
| `GET /portal/evidence` | `evidence_page` | Evidence registry table. Columns: Path, SHA-256, Description, Registered. |
| `GET /portal/iocs` | `iocs_page` | IOCs table extracted from findings. Columns: Value, Type, Context, Status. |
| `GET /portal/todos` | `todos_page` | TODO items table. Columns: ID, Description, Priority, Status, Assignee. |
| `GET /portal/steer` | `steer_page` | N1 intake + case switch + add evidence + N4 rerun. Case selector dropdown, intake form (question, window, extras), evidence path input, rerun button. |
| `GET /portal/query` | `query_page` | N4 hit browser — searches processed output (not raw evidence). Needles input, persist checkbox, hit table. |
| `GET /portal/ask` | `ask_page` | Mode 1 query desk: NL question → needles → N4 hits → select hits → promote to DRAFT. |
| `GET /portal/explore` | `explore_page` | Mode 1 Cockpit: faceted explore (DSL + needles + family + date filters), steer chat, histogram/timeline lanes, entity pivot, workbench add, promote to DRAFT, Mode 2 iterate button. |
| `GET /portal/workbench` | `workbench_page` | Finding workbench: bookmarked hits table, promote selected bookmarks to DRAFT, clear all. |

---

## 13. Health

### GET /health
**Description:** Lightweight health endpoint for load balancers and Docker healthchecks. Not under `/portal/api/` prefix.

**Request:** No body. No query params.

**Response 200:**
```json
{
  "status": "ok",
  "service": "dfir-nexus"
}
```

**Errors:** None (always 200).

---

### POST /portal/api/case/seed-demo
**Description:** Seed a populated demo investigation case with pre-built findings, evidence, and timeline entries. By default the demo is created **without** switching the active case; the dashboard previews it and offers an explicit Enter.

**Request:**
```json
{
  "name": "Demo Investigation",
  "activate": false
}
```
- `name` (optional, default `"Demo Investigation"`)
- `activate` (optional, default `false`) — switch the active case to the demo.

**Response 200:**
```json
{
  "ok": true,
  "case_id": "CASE-XXXX-XXXX",
  "evidence_count": 4,
  "findings_count": 5,
  "timeline_count": 284,
  "active": "string (current pointer value, or \"\")"
}
```

**Response 500:** `{"error": "string"}` — seed failed.

---

### POST /portal/api/findings/reject
**Description:** Reject one or more DRAFT findings with a reason. Updates both `findings.json` and the SQLite case store. Does **not** require HMAC challenge-response (rejection is a non-cryptographic state change; approval requires HMAC). Examiner identity is resolved from the request or body.

**Request:**
```json
{
  "finding_ids": ["F-001", "F-002"],
  "reason": "False positive — legitimate admin activity",
  "examiner": "analyst_t1"
}
```
- `finding_ids` (required, non-empty array)
- `reason` (required, non-empty string)
- `examiner` (optional — resolved from OS user if omitted)

**Response 200:**
```json
{
  "ok": true,
  "rejected": ["F-001", "F-002"]
}
```

**Response 400:** `{"error": "finding_ids is required"}` or `{"error": "reason is required"}`
**Response 404:** `{"error": "No active case"}`

**Security note:** Rejection does not require HMAC because it is a non-cryptographic state transition (DRAFT → REJECTED). Approval (DRAFT → APPROVED) always requires HMAC challenge-response via `POST /portal/api/commit`. Rejection is logged with examiner identity, timestamp, and reason in both `findings.json` and the SQLite store.

---

### POST /portal/api/evidence/verify
**Description:** Re-verify SHA-256 hashes of all registered evidence files for the active case. Reads each file from disk and compares the computed hash against the registered custody hash.

**Request:** No body required.

**Response 200:**
```json
{
  "ok": true,
  "results": [
    {
      "name": "ws01_evtx.zip",
      "file_path": "C:\\Evidence\\ws01_evtx.zip",
      "valid": true,
      "expected_hash": "abc123...",
      "actual_hash": "abc123..."
    },
    {
      "name": "missing.pcap",
      "file_path": "C:\\Evidence\\missing.pcap",
      "valid": false,
      "error": "File not found on disk"
    }
  ]
}
```

**Response 404:** `{"error": "No active case"}`

---

### POST /portal/api/report/generate
**Description:** Trigger official case report generation. Assembles findings, evidence, timeline, case metadata, and tool ledger into a Markdown report written to `CASE-XXXX/reports/REPORT.md`.

**Request:** No body required (empty JSON accepted).

**Response 200:**
```json
{
  "ok": true,
  "report_path": "C:\\...\\CASE-XXXX\\reports\\REPORT.md",
  "findings_count": 5
}
```
- `findings_count` = number of APPROVED findings included.

**Response 404:** `{"error": "No active case"}`
**Response 500:** `{"error": "string"}` — report generation failed.

---

### GET /portal/api/report/view
**Description:** View the case's generated `REPORT.md` as Markdown. Returns empty markdown if no report has been generated yet.

**Request:** No body. No query params.

**Response 200:**
```json
{
  "ok": true,
  "markdown": "# DFIR Report\n## Case: CASE-XXXX...",
  "title": "Report: CASE-XXXX-XXXX"
}
```

**Response (no report yet):**
```json
{
  "ok": false,
  "markdown": "",
  "error": "Report not yet generated. Click 'Generate Official Report'."
}
```

**Response 404:** `{"error": "No active case"}`

---

### GET /portal/api/mode-mapping
**Description:** Map a product mode (1/2/3) to the corresponding pipeline mode (`tools`/`coverage`/`design`). Used by the SPA to translate the examiner's control-depth selection into the pipeline execution mode (WP 3.8).

**Query params:** `product_mode` (required — `1`, `2`, or `3`)

**Response 200:**
```json
{
  "product_mode": 1,
  "pipeline_mode": "tools",
  "pipeline_modes": ["tools"],
  "description": "Examiner-driven exploration — N4 query packs, manual hit selection."
}
```

**Response 400:** `{"error": "product_mode must be 1, 2, or 3"}`

---

### POST /portal/api/mode3/draft-finding
**Description:** Agent proposes a DRAFT finding from selected hits (WP 3.7). The finding is staged with `examiner_selected=false` — the examiner reviews and approves via the normal HMAC flow. The agent **never** approves.

**Request:**
```json
{
  "hits": [{"file": "...", "line": 42, "text": "..."}],
  "title": "Suspicious PowerShell execution",
  "interpretation_hint": "Encoded command pattern matches Empire stager"
}
```
- `hits` (required, non-empty array of hit objects)
- `title` (optional, default `"Agent-proposed finding"`)
- `interpretation_hint` (optional, passed to LLM scribe)

**Response 200:**
```json
{
  "ok": true,
  "finding_id": "F-XXX",
  "title": "Suspicious PowerShell execution",
  "interpretation": "...",
  "status": "DRAFT"
}
```

**Response 400:** `{"error": "string"}` — invalid input or LLM failure.
**Response 404:** `{"error": "No active case"}`

---

### POST /portal/api/mode3/orchestrator
**Description:** Run the multi-agent orchestrator (WP 3.10). Dispatches specialist agents per evidence family, injects RAG methodology, and collects findings into synthesis. Examiner reviews proposals — nothing is auto-staged.

**Request:**
```json
{
  "hits": []
}
```
- `hits` (optional — defaults to current N4 hits from case intake if omitted)

**Response 200:**
```json
{
  "ok": true,
  "specialists": [
    {"agent": "evtx_specialist", "findings": [...], "rag_cited": [...]},
    {"agent": "registry_specialist", "findings": [...], "rag_cited": [...]}
  ],
  "synthesis": "Cross-family correlation: ...",
  "total_findings": 3
}
```

**Response 404:** `{"error": "No active case"}`

---

## Common Error Patterns

| Status Code | Condition | Body |
|------------|-----------|------|
| `400` | Bad request input (missing required field, invalid JSON, invalid type) | `{"error": "string"}` or `{"ok": false, "error": "string"}` |
| `401` | Authentication failure (no examiner, invalid/expired challenge, wrong password) | `{"error": "string"}` |
| `403` | No password configured for examiner | `{"error": "string"}` |
| `404` | No active case, case not found, or finding not found | `{"error": "string"}` or `{"ok": false, "error": "string"}` |
| `429` | Rate-limited / locked out (3-strike lockout for 15 minutes) | `{"error": "string"}` |
| `500` | Internal error (corrupted password entry) | `{"error": "string"}` |

> **Note:** Error body format is inconsistent across handlers — some use
> `{"error": "..."}`, others use `{"ok": false, "error": "..."}`. The React
> frontend should check for the presence of an `error` field in any
> non-2xx response and display it to the user.

---

## Shared Data Types

### Hit Object
Returned by all N4 query endpoints (explore/search, mode1/ask, chat, etc.):
```json
{
  "family": "string (e.g. 'evtx', 'prefetch', 'mft')",
  "file": "string (relative path within extractions)",
  "line": "string (line number)",
  "terms": "string (comma-separated matched terms, max 6)",
  "text": "string (the matched row text)"
}
```

### Bookmark Object
Returned by workbench endpoints:
```json
{
  "id": "string (e.g. 'B-001')",
  "family": "string",
  "file": "string",
  "line": "string",
  "time": "string (extracted timestamp or empty)",
  "text": "string (truncated to 500 chars)",
  "note": "string (max 300 chars)",
  "bookmarked_at": "string (ISO 8601)"
}
```

### Chat Message Object
Returned by chat endpoints:
```json
{
  "ts": "string (ISO 8601)",
  "role": "string (examiner | llm | system)",
  "action": "string",
  "text": "string (max 2000 chars)",
  "meta": {"string": "string"} (optional)
}
```

### Finding Object
Returned by findings endpoints:
```json
{
  "id": "string (e.g. 'F-examiner-001')",
  "case_id": "string",
  "status": "string (DRAFT | APPROVED | REJECTED)",
  "title": "string",
  "observation": "string",
  "interpretation": "string",
  "confidence": "string (LOW | MEDIUM | HIGH | SPECULATIVE)",
  "confidence_justification": "string",
  "evidence": [{"source": "string"}],
  "type": "string",
  "host": "string",
  "affected_account": "string",
  "event_timestamp": "string",
  "attack_ids": ["string"],
  "audit_ids": ["string"],
  "iocs": [{"value": "string", "type": "string", "category": "string"}],
  "artifacts": [{"type": "string", "value": "string", "audit_id": "string", "source": "string"}],
  "examiner": "string",
  "created_at": "string (ISO 8601)",
  "modified_at": "string (ISO 8601)",
  "approved_by": "string (if APPROVED)",
  "approved_at": "string (ISO 8601, if APPROVED)"
}
```

### Plan Item Object
Returned by mode3/plan:
```json
{
  "type": "string (extra | tool_skip)",
  "key": "string (for type=extra)",
  "purpose": "string (for type=extra)",
  "tool": "string (for type=tool_skip)",
  "reason": "string (for type=tool_skip)"
}
```

### Corroboration Result Object
Returned by mode2/corroborate and mode2/propose-draft:
```json
{
  "families": ["string"],
  "distinct_families": 0,
  "confidence": "string (LOW | MEDIUM | HIGH | SPECULATIVE)",
  "ok": true,
  "problems": ["string"],
  "suggested_queries": ["string"]
}
```
