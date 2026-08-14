# Tool ↔ evidence map (product contract)

This is the source of truth for **what runs** in `tools`, `coverage`, and `design`.
It is not a one-case patch. Presence is evaluated against **this evidence pack**,
not the full catalog.

**Complete catalog (Windows 37 + SIFT 68 + knowledge gaps):**
[TOOL-CATALOG-MAP.md](TOOL-CATALOG-MAP.md). Catalog ≠ knowledge YAML ≠ mandatory lane.

Knowledge YAML lives at `src/nexus/data/knowledge/artifacts/windows/*.yaml`
(`locations` + `related_tools`). The planner globs those locations against the
Windows image root (`artifact_map.py`). Argv builders live in `tool_lane.py`
because YAML `quick_start` is not structured enough to execute.

## Modes

| Mode | RAG | LLM | Mandatory lane | After the lane |
|------|-----|-----|----------------|----------------|
| **tools** | no | no | yes — every present artifact | `TOOL-RUN.md` ledger. STOP. No HITL. |
| **coverage** (`debug`) | yes, before interpret | interpret only | same lane | RAG + LLM write findings from **N4 query pack hits**. LLM does **not** pick parsers. |
| **design** | yes, whole process | extras + interpret | same lane **first** | ReAct may **add** playbook/corroboration tools. Must not skip present artifacts or report with zero tool `audit_id`s. |
| **interpret** | yes | interpret | no (reuse ledger) | `--from-case` |

**Relevant** = artifact **present on this evidence**. SKIP = absent, or an
unverified CLI (Thumbcache / LogFileParser). FAIL = present, parser ran and
broke. **Do not SKIP because a portable parser was never fetched** — run
`tools/fetch-windows-tools.ps1` / `tools/fetch-linux-tools.sh` and `nexus doctor`
before the pipeline. Do not SKIP-spam live-acq tools on an image.

Hypothesis / playbooks change **interpretation** and **extra** design jobs.
They never replace the base lane. Tools mode writes a deterministic
case-context overlay on `TOOL-RUN.md` (read-order hints only, no findings).

## Case intake (all modes)

Persisted on `CASE.yaml` under `intake:`:

timezone · incident window · subjects/SIDs/hosts · known-good · question to
answer · playbook IDs · hypothesis.

Hypothesis loses to evidence.

## Windows lane (executed)

All **user profiles** (not the first `Users\*` directory). Default/Public skipped.

| Artifact family | Present if | Parser |
|-----------------|------------|--------|
| EVTX | `Windows\System32\winevt\Logs\*.evtx` | Hayabusa `-d Logs`, EvtxECmd `-d Logs` |
| Prefetch | `Windows\Prefetch` | PECmd |
| Amcache | `Amcache.hve` | AmcacheParser |
| Shimcache | SYSTEM hive | AppCompatCacheParser |
| SRUM | `SRUDB.dat` | copy + esentutl + SrumECmd |
| MFT | `$MFT` | MFTECmd CSV + `--body` (then SIFT `mactime`) |
| Recycle | `$Recycle.Bin` | RBCmd |
| LNK | per-user `Recent` | LECmd |
| Jump lists | per-user Automatic/CustomDestinations | JLECmd |
| Shellbags | per-user `UsrClass.dat` | SBECmd `-f` |
| Activities | per-user `ActivitiesCache.db` | WxTCmd |
| Browser | Chrome/Edge History, Firefox `places.sqlite` | SQLECmd |
| Registry | `config\` + per-user `NTUSER.DAT` | RECmd batch (UserAssist, BAM, Run keys, MountPoints2, Explorer MRU) |
| USN Journal | `$Extend\$J` / `$UsnJrnl:$J` if extracted | MFTECmd `-f` (skip if missing) |
| SetupAPI / PS transcripts / PSReadLine | those files | **copy** into extractions (already text — no strings) |
| Thumbcache / `$LogFile` | present | cataloged, **not auto-run** until CLI is verified |
| RDP bitmap / BITS / UAL | cache tiles / qmgr.db / SUM `*.mdb` | bmc-tools / BitsParser / KStrike — **must be fetched** (UAL only if `*.mdb` exists) |
| `$I30` file | extracted `$I30` only | MFTECmd `-f` |
| Named samples | intake `sample_files` | capa / densityscout / yara only when named (and installed) |
| Live response | `NEXUS_LIVE_RESPONSE=1` | autorunsc / handle / Get-InjectedThreadEx; memory only if `NEXUS_LIVE_ACQUIRE_MEMORY=1` |

YAML artifacts with no argv builder (WER minidumps, VSS, …) appear in
`extractions/_artifact_completeness.json` as `PRESENT_NO_PARSER` or `ABSENT`.
That is a coverage gap, not a silent skip of a parser we own.

## SIFT lane

- Volatility against `NEXUS_SIFT_MEMORY_FILE` (or `{root}/memory/Rocba-Memory.raw`)
- `fls` only if `NEXUS_SIFT_E01` is set
- **No** full-tree `log2timeline` / plaso (disk cannot hold a multi-GB store)
- `mactime` after MFTECmd bodyfile is pushed

## Interpret and report (what actually runs)

These are **not** extra pipeline modes. They are nodes on the coverage / design /
interpret graphs. `tools` never reaches them.

```
tools:     register → scope → lane → TOOL-RUN.md     STOP
coverage:  RAG → register → scope → lane → interpret → DRAFT → HITL → REPORT.md
design:    RAG → register → scope → lane → ReAct extras → interpret → DRAFT → HITL → REPORT.md
interpret: RAG → load existing ledger → interpret → DRAFT → HITL → REPORT.md
```

### Interpret (LLM)

1. Reads the tool-lane ledger (OK / FAIL / SKIP + `audit_id` + saved path).
2. Builds **N4 query pack** `analysis/query_pack.md` — rows matching intake window + playbook `query_terms` (not CSV heads). `analysis/snippets.md` remains an examiner appendix.
3. Requires RAG ready (`forensic_rag_status`), then `forensic_rag_search` **scoped to hit families**.
4. Emits a JSON array of findings: observation (facts from **query pack hits**) vs
   interpretation (what they mean). Hypothesis loses to evidence.
5. FAIL/SKIP are coverage gaps. Empty query hits + OK ledger = INSUFFICIENT rows, not a coverage gap.

The LLM does **not** pick or skip parsers. It does **not** write `REPORT.md`.

If the JSON is missing, staging falls back to one DRAFT per OK ledger row
(collection evidence, not a compromise claim). That is honesty, not a finding.

### HITL

Findings stage as **DRAFT** (`record_finding`). The graph **pauses**
(`await_approval`). Only the examiner promotes them: `nexus approve` or the
Examiner Portal. Then `nexus pipeline --resume` (or the rocba script’s
operator-gated auto-approve). The agent cannot approve.

### Report

`generate_report` builds `REPORT.md` from **APPROVED** findings only
(`dfir_report.py` template). DRAFT/REJECTED are omitted. Structure is code;
the LLM filled observation/interpretation earlier. `tools` mode writes
`TOOL-RUN.md` instead — that is a ledger, not an IR.

`interpret` reuses a finished tools-mode case (do not re-run parsers). Today
that path is `scripts/rocba_agentic_pipeline.py --from-case <id>`.
`nexus pipeline` does not yet take a case id — tracked in
`Docs/internal/COMPLETE-TO-SHIP.md` (M6d).

## What else exists (not pipeline modes)

Do not collapse these into `tools|coverage|design`. Test them **after** the
four pipeline modes are proven on one evidence pack.

| Surface | What it is |
|---------|------------|
| **Windows / SIFT / live-acq lanes** | Which parsers the mandatory lane may schedule (this file + TOOL-CATALOG-MAP) |
| **CLI / MCP / Portal** | Three UIs on the same case brain (`nexus`, `nexus serve`, `/portal`) |
| **Ingest** | 43 importer classes (`nexus ingest`) — logs in, not host-triage parsers |
| **Heuristic 6-agent graph** | Offline alert/cloud/network/endpoint/synthesis/timeline — **not** `nexus pipeline` |
| **RAG / TI / Sigma / VR / triage** | Optional analysis MCP tools |
| **Custody** | evidence hash, approve/reject, backup, export, audit verify |

Ship tracker (every advertised capability): [`Docs/internal/COMPLETE-TO-SHIP.md`](../internal/COMPLETE-TO-SHIP.md).
Change log (what landed): [`CHANGELOG.md`](../../CHANGELOG.md).
