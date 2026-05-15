# Changelog

## 2026-05-14 — Identity locked in: Unallocated Inc / Unallocated.in

Maintainer org and security contact wired through every placeholder
that was parked pending the real values:

- **GitHub URL:** all `your-org/dfir-nexus` references replaced with
  `Unallocated/DFIR-Nexus` in `README.md` (indirect via Documentation
  table), `pyproject.toml` (`homepage` + `documentation`), `mkdocs.yml`
  (`repo_url`, `edit_uri`, social link), `Docs/guide.md` (git clone
  example), `Docs/index.md` (GitHub repository link), and
  `CONTRIBUTING.md` (dev setup `git clone` line).
- **Security contact:** `SECURITY.md` placeholder replaced with
  `security@Unallocated.in`.
- **Copyright:** `LICENSE` now reads
  `Copyright (c) 2026 Unallocated Inc and DFIR-Nexus contributors`
  (org as primary holder; contributors clause preserved for community).
- **Authorship metadata:** `pyproject.toml` `authors` lists Unallocated
  Inc first plus the contributors clause; `mkdocs.yml` `site_author`
  + `copyright` align.

Tests after the rebrand: **51 + 41 + 31 = 123 passing**. No code paths
touched.

## 2026-05-14 — Doc-currency audit + packaging fix

Walk-the-doc-chain audit after the launch-surface and clean-break passes,
to confirm a fresh visitor's journey from README → guide → CLI →
architecture → FAQ → comparison is internally consistent and reflects
what actually shipped. Twelve concrete issues fixed plus one real
packaging bug.

**Doc-staleness fixes:**

- `README.md` — quickstart steps jumped `1 → 4 → 5 → 6 → 7` (two
  step numbers got lost during the setup-script consolidation).
  Renumbered to `1 → 2 → 3 → 4 → 5`.
- `Docs/COMPARISON.md` §1 + §5.1 + §5.3 — table and three sections
  still claimed the portal was read-only and that browser approval +
  JSON REST API were unsolved. Both shipped (§4 #12 + #13). Updated
  table row, struck through §5.1 and §5.3 as **Done**, noted delta
  editing is the only remaining `/api/*` gap.
- `Docs/FAQ.md` — "guide.md §9 Troubleshooting" pointed at a section
  that's been §8 since the CLI ref + env-vars sections moved to
  `Docs/CLI.md`. Fixed. Also corrected macOS tool count from "86" to
  **83** with explicit breakdown (`23 + 15 + 6 + 5 + 11 + 15 + 8`).
- `Docs/guide.md` §1 Installation — only mentioned `pip install`;
  added the three `setup-*.sh` / `.ps1` scripts as the recommended
  path with `--skip-init` / `--skip-password` flag documentation.
  Also added a `[triage]` extra mention.
- `Docs/guide.md` §8 Troubleshooting — added 6 rows for surface that
  didn't exist when the table was first written: Claude Code hooks
  not firing, audit log empty after Bash, REMnux detection by name
  substring, transparency log tamper detection, `nexus init` baseline
  missing, `nexus export --encrypt` cryptography missing.
- `Docs/ARCHITECTURE.md` topology — added `transparency.py`,
  `telemetry.py`, and `dashboard/` to the infrastructure section
  of the topology diagram.
- `Docs/ARCHITECTURE.md` Security Model — added rows for Transparency
  (hash-chained log), Bundle export (PBKDF2 + Fernet), Telemetry
  (opt-in only via `NEXUS_OTEL_ENABLED`), and clarified the Approvals
  row to include the browser path.
- `Docs/ARCHITECTURE.md` Directory Layout — added per-case
  `transparency.jsonl`, split `audit/` into `nexus.jsonl` +
  `claude-code.jsonl`, surfaced `extractions/`, `reports/`,
  `.outputs/`, added `~/.nexus/services.json`, noted the cwd
  `nexus-config.json` output of `nexus init`.
- `Docs/ARCHITECTURE.md` LLM Client Setup — added a paragraph
  pointing at `claude-code/README.md` with the lite/full distinction.
- `Docs/COMPARISON.md` §7 — added three new "Shipped" rows for the
  beyond-parity items from the launch-surface pass (Claude Code skill
  bundle, OS setup scripts, MkDocs site) and a new "Deferred" row
  for §5.3 delta editing.

**Packaging fix (real bug caught mid-audit):**

`pyproject.toml` — `[all]` extra did **not** pull `cryptography`, so
anyone installing with `pip install dfir-nexus[all]` and trying
`nexus export --encrypt` hit `ImportError`. Added `[encrypt]` extra
(`cryptography>=42.0`) and included it in `[all]` so the setup scripts
and the documented `[all]` install both provision encryption out of
the box.

**MkDocs build fix:**

`mkdocs.yml` had `Home: ../README.md` while `docs_dir: Docs` — MkDocs
won't traverse outside the docs dir, so the GitHub Pages build would
have failed. Created `Docs/index.md` (proper landing page with the
Beta admonition, what-it-is, who-it's-for, and a "where to start"
table) and pointed the Home nav at it. The site now publishes cleanly.

Tests: **51 + 41 + 31 = 123 passing** after every change.

## 2026-05-14 — Launch surface: skill bundle, setup scripts, docs site

**Claude Code skill bundle** (`claude-code/`) — first-party port of the
upstream `sift-mcp/claude-code/` bundle, adapted for DFIR-Nexus's
single-server model. Two variants:

- `claude-code/lite/` — single-machine examiner. One MCP allowlist
  entry (`mcp__dfir-nexus__*`) instead of upstream's seven. Hooks:
  `forensic-audit.sh` (PostToolUse, writes Bash invocations to
  `<case>/audit/claude-code.jsonl` with SHA-256 of command + output)
  and `case-data-guard.sh` (PreToolUse, blocks `rm`/`mv`/`find -delete`
  against case roots and protected files including our hash-chained
  `transparency.jsonl`).
- `claude-code/full/` — multi-host fleet variant. Adds `case-dir-check.sh`
  (SessionStart), sandbox config with denyWrite list, stricter deny
  rules, and additional allowlist entries for `dfir-nexus-sift`,
  `dfir-nexus-windows`, `dfir-nexus-remnux` matching `nexus setup
  client --remnux HOST:PORT` output.

Shared content (CLAUDE.md, TOOL_REFERENCE.md, FORENSIC_DISCIPLINE.md)
is identical across variants. Slash commands: `/welcome` (post-install
verification), `/case` (lifecycle ops), `/approve` (guides examiner to
terminal; LLM cannot approve), `/report` (generation + ledger
pre-flight). Case templates: ACTIONS.md, FINDINGS.md, TIMELINE.md.
`scripts/case-manager.sh` bootstraps cases outside the MCP context.

**Why this beats upstream:** one allowlist entry not seven; single
audit hierarchy means hooks write to one place; `case-data-guard`
protects our `transparency.jsonl` + `verification/` + `passwords/`
(net-new files upstream doesn't have); FORENSIC_TOOLS.md doesn't
duplicate the 1,065-line catalog — points to the YAML knowledge base
queryable via `get_tool_help`.

**Setup scripts** — `setup-linux.sh`, `setup-macos.sh`, `setup-windows.ps1`.
Each verifies Python 3.12+, creates `.venv/`, runs `pip install -e .[all]`,
prompts for examiner identity + approval password, runs `nexus init`.
`--skip-init`/`--skip-password`/`--no-venv` flags for CI and
custom flows.

**Documentation site** — `mkdocs.yml` (Material theme, dark/light
toggle, full-text search) + `.github/workflows/pages.yml` that builds
and deploys to GitHub Pages on every push to `main` that touches
`Docs/`, `README.md`, or `mkdocs.yml`.

**REMnux capability detection restored** — earlier cleanup pass had
dropped the `remnux` capability flag from `tools/case.py:_detect_capabilities`
along with the broken upstream module-name probes. Restored by reading
the user's MCP client config (`.mcp.json`, `~/.claude.json`,
`~/.mcp.json`) for any entry whose name contains `remnux` — matching
upstream's pattern, adapted because we don't use a gateway.

**Code references retired** — `forensic_mcp_*` / `windows_triage_*`
enforcement labels in `rules.yaml` replaced with real module paths
(`nexus.discipline.validate_finding`, `nexus.case_manager.record_finding`,
`nexus.triage.server`). `vhir CLI` references in `how_to_apply` text
updated to `\`nexus approve\``. Pure docstring tidy-up: no semantic
change; the data was inert labels.

**Clean break from `vhir` / Valhuntir back-compat** — every `VHIR_*`
env var fallback and `~/.vhir/` directory fallback removed from
`audit.py`, `config.py`, `case_manager.py`, `tools/case.py`,
`tools/report.py`, `tools/sift.py`, `langgraph/pipeline.py`,
`langgraph/Makefile`, all 6 hook files in `claude-code/`, and the
stale assertion in `COMPARISON.md` table that claimed `VHIR_MODEL`
was still honoured. DFIR-Nexus is a clean-namespace project from the
first release; migration aliases would have read as an incomplete
rename. Remaining `vhir` / `Valhuntir` mentions in `COMPARISON.md`,
`FAQ.md`, `ARCHITECTURE.md` comparison table, and changelog history
are deliberate — they name upstream when describing what we
compare against. SIFT references kept everywhere (legitimate
forensic-distro reference).

Tests after every change: **51 + 41 + 31 = 123 passing**.

## 2026-05-14 — Comparison + roadmap doc

Added [COMPARISON.md](./COMPARISON.md): authoritative side-by-side of
DFIR-Nexus vs. upstream (`sift-mcp`, `wintools-mcp`, `Valhuntir`, the
reference `LangGraph_integration` pipeline). Captures tool-surface
parity (~83 upstream → 97 nexus), control- and data-flow differences,
what we already do better (one process / one audit hierarchy, ledger
reconciliation in reports, boot-time LangGraph tool validation,
ledger-aware resume, vendored knowledge base, OpenSearch tool-set,
download-baseline tools), what upstream still does better (browser-
side approval `/api/commit`, gateway with per-IP rate limit, dashboard
REST + delta editing, a few `vhir` commands, pycti resilience, both
LangGraph pipelines short-circuit `stage_findings`), and a 12-item
prioritised roadmap with effort sizing.

## 2026-05-14 — Integrity review pass

A diff against the upstream `DFIR-mcp` repos surfaced regressions that the
initial integration pass had hidden behind passing tests. The audit chain
was the highest-risk break: findings could reach `STAGED` with audit IDs
that did not exist in the active case audit log, producing approved-looking
output without a real evidence trail.

### Fixed — Evidence chain

- **Audit writes route to the active case again.** `AuditWriter` no longer
  forces a global override; `_get_audit_dir()` resolves the case via
  `NEXUS_AUDIT_DIR` / `NEXUS_CASE_DIR` / `~/.nexus/active_case`, matching
  what `_score_provenance` reads back. (`src/nexus/app.py`,
  `src/nexus/audit.py`)
- **Findings are rejected when provenance is NONE, even when artifacts are
  attached.** `record_finding` now scores provenance before append and
  returns `REJECTED` (with `missing_audit_ids`) for unverifiable audit IDs,
  matching upstream forensic-mcp behavior. (`src/nexus/case_manager.py`)
- **`confidence_justification` is a hard error (FD-005), not a warning.**
  Restores the upstream discipline rule that confidence claims must be
  justified. (`src/nexus/discipline.py`)
- **Corrupt case JSON raises instead of being silently treated as empty.**
  `_load_json_file` refuses to overwrite a file it cannot parse, preventing
  silent data loss in `findings.json` / `timeline.json` / `iocs.json` /
  `todos.json` / `evidence.json`. (`src/nexus/case_manager.py`)

### Fixed — `record_finding` compatibility

- Accepts the original structured shape: top-level `artifacts`,
  `supporting_commands`, `audit_ids`, and explicit `iocs`.
- Auto-creates a timeline event when `event_timestamp` is present (returns
  `timeline_event_id` in the response).
- Persists explicit IOCs to `iocs.json` in addition to regex-extracted ones,
  with `source_findings` cross-references.
- Logs shell-self-reported supporting commands and threads their audit IDs
  back into the finding's `audit_ids`.

### Fixed — Windows tools

- `run_windows_command` restored to the upstream envelope: accepts
  `command: str | list[str]`, hashes detected/declared `input_files`,
  honors `save_output` (writes timestamped stdout/stderr into
  `<case>/extractions/` with SHA-256), and returns `audit_id`,
  `output_files`, `input_sha256s`, `data_provenance`, `field_meanings`,
  and an `input_detection_method` audit annotation.
- `get_share_info` re-exposed for cross-machine Windows/SIFT workflows.

### Fixed — Triage

- `check_registry` performs a real baseline lookup via `RegistryDB`
  (`lookup_key` / `lookup_value`) instead of returning the
  baseline-exists-but-not-queried stub. Returns `EXPECTED` with hive /
  OS-version coverage on hit, `UNKNOWN` on miss.
- `zstandard` added to the `triage` optional-dependency extra so
  `.tar.zst` baseline archives decompress without a missing-import
  failure. (`pyproject.toml`)

### Fixed — Reporting

- `generate_report` applies `start_date` / `end_date` to the timeline
  payload (previously accepted but ignored).
- `timeline_mode="referenced"` now returns the approved timeline rather
  than an empty list.
- Approved findings are reconciled against the HMAC verification ledger;
  mismatches surface as `verification_alerts` and trigger an
  `integrity_warning` for any `APPROVED_WITHOUT_LEDGER` entry.

### Fixed — OpenCTI

- `search_threat_intel` and `search_entity` re-expose paging and filter
  arguments (`limit`, `offset`, `labels`, `confidence_min`,
  `created_after`, `created_before`) so LangGraph / MCP clients can page
  threat-intel results again.

### Tests

- `tests/test_integration.py` updated for the now-strict validation: the
  `record_finding` fixture provides `interpretation` and
  `confidence_justification`; the `list_profiles` assertion reads
  `r["count"]` instead of `len(r)`.
- Suite status under the local venv with `USERPROFILE` redirected to a
  writable test home: **51/51** knowledge tests + **41/41** integration
  tests passing on Windows (91 tools registered).

---

## 2026-05-14

### Added — Phase 4: Complete Integration

**RAG — Real ChromaDB implementation**
- `RAGIndex` class wrapping ChromaDB + SentenceTransformer for semantic search (~23K records)
- MITRE technique augmentation for better query matching (e.g., "T1003" → "T1003 OS Credential Dumping")
- Source/technique/platform filtering with hybrid keyword boosting
- `forensic_rag_download` — downloads pre-built ChromaDB from AppliedIR/sift-mcp GitHub releases
- `forensic_rag_list_sources` — lists available knowledge sources in the index
- Full response envelope: status, query echo, audit_id, examiner, caveats, interpretation_constraint

**OpenCTI — Full 8-tool implementation**
- `search_threat_intel` — broad search across all entity types (indicators, actors, malware, techniques, CVEs, reports)
- `search_entity` — type-specific search for 16 entity types
- `lookup_indicator` — IOC lookup with relationship context (related actors, malware, campaigns)
- `get_recent_indicators` — recent IOCs from last N days
- `get_entity` — full entity details by UUID
- `get_relationships` — entity relationship mapping (direction + type filtering)
- `search_reports` — threat intel report search
- `search_threat_actor`, `search_malware`, `search_mitre_technique` — convenience wrappers

**Triage — Full subpackage (15 tools + analysis engine)**
- `nexus/triage/` subpackage with 5 files: `server.py`, `analysis.py`, `db.py`, `download.py`, `__init__.py`
- 13 triage tools: `check_file`, `check_process_tree`, `check_service`, `check_scheduled_task`, `check_autorun`, `check_registry`, `check_hash`, `analyze_filename_triage`, `check_lolbin`, `check_hijackable_dll`, `check_pipe`, `get_db_stats`, `get_health`
- Plus `triage_status()` and `triage_download()` for database management
- `analysis.py` — path normalization, filename heuristics, entropy analysis, Unicode evasion detection (RLO attacks, homoglyphs, typosquatting, leet speak), hash detection (MD5/SHA1/SHA256), verdict calculation (SUSPICIOUS/EXPECTED_LOLBIN/EXPECTED/UNKNOWN)
- `db.py` — `KnownGoodDB` (file/service/task/autorun baselines from SQLite), `ContextDB` (LOLBins, vulnerable drivers, process rules, named pipes, suspicious patterns)
- `download.py` — downloads `known_good.db` + `context.db` from AppliedIR/sift-mcp releases
- Response includes: path_in_baseline, filename_in_baseline, is_system_path, audit_id, examiner, caveats, interpretation_constraint ("UNKNOWN means not-in-database, NOT suspicious")

**OpenSearch — Real query DSL (our invention)**
- 8 tools: `idx_ingest` (index creation with mapping), `idx_search` (query string), `idx_aggregate` (term aggregation), `idx_timeline` (date histogram), `idx_enrich_triage`, `idx_enrich_intel`, `idx_status`, `idx_case_summary`
- Real OpenSearch query DSL: query string search, term aggregations, date histograms, index management

**Forensic — 14 discipline tools added**
- `get_investigation_framework`, `get_rules`, `get_checkpoint_requirements`, `get_evidence_standards`, `get_confidence_definitions`, `get_anti_patterns`, `get_evidence_template`, `get_tool_guidance`, `get_false_positive_context`, `get_corroboration_suggestions`, `list_playbooks`, `get_playbook`, `get_collection_checklist`
- All backed by YAML knowledge base data (91 files, 14 playbooks, 7 rules, 6 anti-patterns)

**Windows — Full wintools-mcp port (10 tools, 31 catalogs)**
- Added: `scan_tools` (full inventory), `list_missing_windows_tools` (install guidance), `check_windows_tools`, `get_windows_tool_help`, `list_kape_targets` (KAPE target/module listing)
- 24h LRU result caching (256 entries)
- Auto-output parsing (JSON/CSV/text detection)
- Missing catalog entries added: winpmem, dumpit, moneta, hollows_hunter, densityscout, Get-InjectedThreadEx, mactime (31 total)

**CLI — 7 new commands**
- `nexus export` / `nexus merge` — case bundle export/import
- `nexus exec` — audit-logged command execution
- `nexus audit log` / `nexus audit summary` — audit trail viewer
- `nexus todo add` / `nexus todo list` / `nexus todo complete` — TODO management
- `nexus portal` — open web dashboard in browser
- `nexus update` — git pull + pip rebuild
- `nexus setup test` / `nexus setup client` — connectivity test + LLM client config generator

**Auth — Password-based approval (PBKDF2 + HMAC)**
- `setup_password()`, `verify_password()`, `check_lockout()` with 15-min lockout
- HMAC verification ledger: `derive_hmac_key()`, `compute_hmac()`, `write_verification_entry()`, `read_verification_ledger()`
- `nexus config --setup-password` — interactive password setup

**Dashboard — Full web application**
- 6 pages: Overview, Findings, Timeline, Evidence, IOCs, TODOs
- Dynamic data from case directory JSON files
- Status badges, confidence badges, sortable tables

### Fixed

- **Response structure consistency**: All 5 critical gaps fixed across sift, forensic, case, triage, and rag modules
  - `examiner` field added to all tool responses
  - `data_provenance` changed from dict to string literal (matching original)
  - `interpretation_constraint: "UNKNOWN means not-in-database, NOT suspicious"` added to triage
  - Full RAG response envelope: status, query, audit_id, examiner, caveats
  - `provenance_detail` (mcp/hook/shell/none classification) + `provenance_grade` (FULL/PARTIAL) in record_finding
  - REJECTED status for findings without audit trail
  - `field_meanings`, `field_notes`, `related_tools` added to sift response
- **AuditWriter constructor argument swap** — `app.py` had `AuditWriter(settings.audit_dir, "nexus")` which caused `TypeError` when Path.replace() was called instead of str.replace(). Fixed to `AuditWriter("nexus", settings.audit_dir)`.
- **Provenance check order** — moved provenance scoring BEFORE saving finding (was saving then rejecting)
- **`last_audit_id` property** added to AuditWriter for tools to reference their own audit_id
- **Platform-gated registration** — SIFT tools only register on Linux, Windows tools only on Windows (via `if _IS_LINUX` / `if _IS_WINDOWS` guards in `app.py` and respective modules)
- **Input file auto-detection** — command args scanned for existing files (fallback when input_files not provided)
- **Auto-output parsing** — JSON/CSV auto-detection in sift.py _build_response
- **FK enrichment wired in** — `_build_response` now actually called from `run_command` (was defined but never used)
- **Integration test platform-awareness** — SIFT-only tests skip on non-Linux

### Added — Phase 4e: All roadmap items implemented

- **P0-1: LangGraph real stage_findings** (`langgraph/pipeline.py`) — `_parse_hunt_candidates()` extracts structured findings from hunt agent messages (supports both raw JSON and ```json``` code blocks). `_normalize_candidate()` maps to `record_finding` args. Loops `record_finding` over each candidate. Falls back to placeholder if none found. `_parse_hunt_candidates` is a pure function with no side effects.
- **P1-3: Portal REST API** (`dashboard/app.py`) — 8 new JSON endpoints: `GET /portal/api/findings?status=DRAFT&limit=20`, `timeline`, `evidence`, `iocs`, `todos`, `audit/{finding_id}`, `summary`, `transparency`. All read from the same JSON files as the HTML pages.
- **P2-1: Granular service control** (`cli/service.py`) — `nexus service start/stop/restart <name>` works with any name. Extensible via `~/.nexus/services.json` for custom services. Start command supports `NEXUS_{NAME}_ARGS` env var for per-service overrides.
- **P2-3: OpenTelemetry tracing** (`nexus/telemetry.py`) — `trace_tool_call()` context manager creates spans with tool name and audit_id attributes. Enabled via `NEXUS_OTEL_ENABLED=true`. Graceful fallback if `opentelemetry` not installed.
- **P3-1: Hash-chained transparency log** (`nexus/transparency.py`) — `transparency_append()` appends entries to a hash chain where each entry stores the SHA-256 of the previous entry's hash. `transparency_verify()` walks the chain and detects tampering (returns tampered index). Every portal commit also writes to the transparency log.
- **P3-2: Encrypted export** (`cli/sync.py`) — `nexus export --encrypt` and `nexus merge --decrypt` with PBKDF2 + Fernet encryption. Requires `cryptography` package (graceful error with install hint if missing). Key derived with 600K PBKDF2 iterations.
- **P3-3: Help-text examples** — Added worked examples to `run_command` (SIFT), `forensic_rag_search` (RAG), `idx_search` (OpenSearch) docstrings. These tools are ready to use with examples.
- **All roadmap items from COMPARISON.md §7 are now closed.** The remaining frontier is documented in §6.
- Tests: 51/51 knowledge + 41/41 integration unchanged.

### Added — Phase 4d: Browser-based approval (Portal commit workflow)

- **Portal commit endpoints** (`dashboard/app.py`) — `GET /portal/api/commit/challenge` issues nonce + salt challenge; `POST /portal/api/commit` verifies HMAC response, approves findings, writes HMAC verification ledger. Protocol matches upstream: PBKDF2(password, salt) → HMAC(stored_hash, nonce). Lockout after 3 failed attempts (15 min).
- **Portal approve page** (`/portal/approve`) — HTML page with Web Crypto JS that computes PBKDF2 + HMAC in the browser. Finding checkboxes, "Approve Selected" button, status feedback. No password sent to server — only the HMAC response.
- **`_approve_finding()` helper** — reusable function that approves a single finding and writes the HMAC verification ledger entry. Used by both portal commit and CLI approve paths.
- Closes §5.1 upstream feature gap (browser-based approval). Moved from roadmap P1-1 to §4 item 12.
- Tests: 51/51 knowledge + 41/41 integration unchanged.

### Added — Phase 4c: Conflict detection, OpenCTI retry, nexus init

- **Conflict detection** (`case_manager.py:_detect_conflicts`) — `record_finding` now checks new findings against existing APPROVED findings on the same host + time window. Incompatible types (exclusion vs execution, attribution) or conflicting confidence levels surface a `conflicts_with` field. Upstream didn't have this — original advantage.
- **Corroboration suggestions** (`record_finding` response) — when provenance grade is NONE or PARTIAL and a finding type is set, wires `fk.get_corroboration_suggestions()` into the response as `corroboration_suggestions` field.
- **OpenCTI retry/backoff** (`opencti.py:_cti_retry`) — new `_cti_retry(client, method_name, *args)` function with exponential backoff (1.5^attempt, max 3 attempts) and `_cti_safe_call(method_name, *args)` wrapper that handles connection errors gracefully. Existing tools unchanged.
- **`nexus init` quickstart** (`cli/init_cmd.py`) — one-command onboarding: checks dependencies, sets examiner, reports triage/RAG status, prints LLM client config snippet. New CLI subcommand, all existing commands untouched.
- **COMPARISON.md**: P0-2, P2-2, P3-3 moved from roadmap §7 to §4 (done). 3 new items in §4 (items 10-11 + init).

### Added — Phase 4b: Password rotation + doc updates

- **Password rotation** — `reset_password()` in `auth.py` verifies old password, hashes new password with fresh salt, re-signs all HMAC verification ledger entries for the examiner. `nexus config --setup-password` now auto-detects existing passwords and offers rotation.
- **COMPARISON.md fixes** — corrected wintools-mcp parity (suggest_windows_tools IS ported), removed reopen from unported list, bumped CLI count to 19, moved password rotation to §4, removed from roadmap §7
- **CLI count**: 12 `add_typer` groups + 6 `@app.command()` = 18 entry points
