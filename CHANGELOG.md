# Changelog

All notable changes to DFIR-Nexus are documented here.

## Unreleased

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
