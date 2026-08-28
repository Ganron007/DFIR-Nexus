# Nexus mode (the investigation loop)

This page is the operator mental model. Open it first: collect → register → N1–N8.

One product, three doors, one `case_id`:

1. **Nexus mode** (this page) — host pack: process, query, interpret, approve, export
2. **Import/ingest** — Zeek, Suricata, EVTX, EDR/SIEM export onto the **same** case
3. **Detection eng** — after the story: draft Sigma/KQL/Suricata for the SIEM team

Do import and detection **after** Nexus mode is honest on one pack.
They reuse the same query / HITL / report brain. They do not replace it.

## Stage 0 — live collect (before Register)

Stage 0 is a **live run** against a host you can authenticate to:

`nexus collect run --os windows --host <ip> --user <acct> --identity <key>`

**`--profile disk` is the default ship spine** (current Windows 11 / modern Linux):
Windows KAPE + Sysinternals + PersistenceSniper + wevtutil + Velociraptor IRTriage;
Linux POSIX volatile + journalctl + UAC `ir_triage` + Velociraptor LinuxIRTriage.
`--profile full` wraps extra *collectors* (Kansa, DFIR-ORC, WinPmem/AVML, UAC `full`)
and **skips with a reason** when a tool is missing or broken.

**Stage 0 is strictly IR collection. No parsers. No Hayabusa, no Suzaku, no
Chainsaw.** Those are N2 parsers. The empty `hayabusa-out/`, `chainsaw-out/`,
`suzaku-out/` folders that appeared in earlier Stage 0 packs were a mistake —
those tools must never run during collection. N2 runs them after Register.

**KAPE packing (forensically sound):** KAPE triage should be packed as a
**zipped VMDK** (or raw image), not as a plain folder of loose files. Stage 0
collects the VMDK; the examiner mounts it into a directory before Register;
N2 parses the mounted directory. A plain KAPE triage dumped into a folder is
not forensically sound and is not acceptable as the Stage 0 pack format going
forward. The pack format is:

```
pack/
├── hosts/<hostname>/
│   ├── kape/           → zipped VMDK or raw image (mounted before N2)
│   ├── velociraptor/   → VR IRTriage JSON (direct host collection)
│   ├── sysinternals/   → Sysinternals output (direct host collection)
│   ├── wevtutil/       → raw EVTX exports (direct host collection)
│   ├── kansa/          → Kansa CSV output (direct host collection)
│   ├── persistencesniper/  → PersistenceSniper CSV (direct host)
│   ├── orc/            → DFIR-ORC exports (direct host collection)
│   ├── volatile/       → POSIX volatile / UAC ir_triage (Linux direct host)
│   └── journal/        → journalctl export (Linux direct host)
├── elk/                → ELK exports (NOT direct host — goes to ingest)
├── monitor/            → Zeek/Suricata (NOT direct host — goes to ingest)
└── manifest.json
```

Writes `hosts/<hostname>/…` + `manifest.json`. **Not** an analysis dump.

Then **Register** (separate from N1–N8): `nexus case init` and
`nexus evidence register` the pack. After that, N2 parsers and N1–N8
run in examiner / thick / agents mode against the same `case_id`.

`nexus collect import <dump>` is the helper when you already have a KAPE image or
Kansa CSVs. Velociraptor is a **Stage 0 collector**: skipped honestly when the
server is mock or unreachable; live hunts run when examiner `.env` has
`NEXUS_VR_MCP_URL` + `NEXUS_VR_MCP_API_KEY` (HTTP `:8002`, not gRPC `:8001`).
See [SETUP.md §2.6](SETUP.md#26-live-velociraptor-hunts-every-examiner-host).
`nexus collect run` harvests — wait for operator freeze. Opt into overlap with
`--profile full`. Opt out with `--profile volatile`, `--only kansa,kape`,
or `--no-*`.

Without SSH or WinRM (or local) credentials, collection does not run. That is
the orchestrator boundary.

## Register stays outside N1–N8

Do **not** fold Register into N1–N8. Custody is a gate, not analysis.

| Activity | What it is |
|----------|------------|
| **Stage 0 Collect** | Live IR → pack on disk. No case required. No LLM. No parsers. |
| **Register** | `nexus case init` + `nexus evidence register <pack>`. HMAC / chain-of-custody. Also used for import-only cases (no collect). |
| **N1–N8** | Analysis spine on a registered `case_id`. Examiner / thick / agents are *how you drive* that spine, not extra stages. |
| **N2** | All direct host logs (Win/Linux/Mac): binary parsers + pre-collected host output → CSVs under the case with audit_id. Given a directory (pack or mounted VMDK) and recursively parses all host evidence. |
| **N3** | SQLite (default) or ES (optional) index of this case's N2 output. Not the lab SIEM. |

Why Register is separate:

- Import-only cases must register without collect.
- Re-running N2 must not re-register.
- The three Nexus modes all need an existing `case_id`. Mixing Register into N1 makes Mode 2/3 awkward.

One collect command. Follow-up is **separate CLI commands**, not one mega-script.

A case is stable across retries. Each tools, coverage, design, or interpret execution creates an immutable `runs/<run_id>/` directory containing that execution's extractions, ledger, analysis, and reports. `active_runs.json` selects the current tools and interpretation runs without overwriting earlier output. Register unchanged evidence once; a changed pack must be preserved at a new path and registered as new evidence.

## Surfaces (CLI vs UI)

| Surface | What |
|---------|------|
| **Collect** | Stays **CLI** (`nexus collect`). Portable, headless, freeze-gated. No Portal harvest. |
| **Register + N1–N8 + ingest + detection** | CLI **and** Examiner Portal / MCP. Portal is the investigation desk. |

Do not put live IR behind a browser. Do not skip Register because the Portal can open a case.

## Mode 1 / 2 / 3 — three doors, one spine, one case

The N1–N8 spine is identical in all three modes. The difference is **how you
drive it** and **how much autonomy the agent has**. All three modes produce
the same case artifacts: extractions, ledger, query pack, DRAFT findings,
HMAC approvals, timeline, report. The case direction and scope do not change
between modes.

### Mode 1 — Examiner-Led / Public Beta (current ship target)

The examiner drives every step. The LLM is optional and narrow.

| Stage | Who acts | LLM role |
|-------|----------|----------|
| N1 | Examiner types the question + time window in CLI or Portal | None |
| N2 | `nexus pipeline --mode tools` — deterministic lane runs all parsers | None |
| N3 | SQLite/ES index built automatically | None |
| N4 | Playbook needles auto-search + examiner can add needles via CLI/Portal | None — N4 is code search |
| N5 | `nexus pipeline --mode interpret` — LLM narrates N4 hits only | Narrates hits; stages DRAFT; cannot approve |
| N6 | Examiner reviews DRAFTs, runs `nexus approve` (password/HMAC) | None — cannot approve |
| N7 | Timeline built from approved hits | None |
| N8 | `nexus report generate` — template from APPROVED only | None — template fill, no new facts |
| Ingest | Examiner ingests network/SIEM/cloud via CLI or Portal | None |
| Detection | Optional drafts after N8 | May suggest Sigma/KQL drafts; examiner reviews |

**Key constraint:** The LLM never chooses which parsers run. It never
invents facts. It never approves. It narrates N4 hits and that is all.

### Mode 2 — Thick Cognitive Analysis (future)

The LLM proposes needles, correlates across hits, and suggests follow-up
queries. The examiner still approves.

| Stage | Who acts | LLM role |
|-------|----------|----------|
| N1 | Examiner question + LLM expands into sub-questions | Proposes sub-questions from playbooks/RAG |
| N2 | Same deterministic lane (LLM does not skip parsers) | None — N2 is still deterministic |
| N3 | Same SQLite/ES index | None |
| N4 | LLM proposes additional needles from initial hit families | Proposes needles; examiner can accept/reject |
| N5 | LLM correlates across hit families, suggests finding clusters | Heavier interpretation; cross-family correlation |
| N6 | Examiner reviews — same HMAC gate | None — cannot approve |
| N7 | Same timeline | None |
| N8 | Same template | None |
| Ingest | LLM may suggest which network logs to ingest based on host hits | Suggests; examiner decides |
| Detection | LLM drafts detections with justification | Drafts with ATT&CK mapping; examiner reviews |

**Key constraint:** Same N6 gate. The LLM is thicker at N4/N5 but still
cannot approve, cannot skip N2, and cannot invent facts beyond N4 hits.

### Mode 3 — Autonomous Agentic MCP (future, was the old plan)

A ReAct agent drives tool selection, runs the lane, adds extras, and
proposes findings. The examiner approves.

| Stage | Who acts | LLM role |
|-------|----------|----------|
| N1 | Agent reads the question, loads playbooks autonomously | Full intake reasoning |
| N2 | Agent runs the mandatory lane first, then may **add** extras (carve, extra Volatility plugins, additional parsers) | Runs lane + adds extras after, not instead of |
| N3 | Same index | None |
| N4 | Agent proposes and executes needles via `query_case_hits` tool | Proposes + executes; empty = stop |
| N5 | Agent narrates hits, stages DRAFT findings with provenance | Full interpretation with audit chain |
| N6 | Examiner reviews — same HMAC gate | None — cannot approve |
| N7 | Same timeline | None |
| N8 | Same template | None |
| Ingest | Agent may ingest network logs and re-run N4→N8 | Autonomous ingest + re-query |
| Detection | Agent drafts detections | Full draft with justification |

**Key constraint:** The agent must run the mandatory N2 lane first. It may
add extras after the lane, not instead of it. FAIL in the lane is not
papered over by omitting the parser. N6 is still human HMAC. The agent
cannot approve its own findings.

### What stays constant across all modes

- Same `case_id`, same immutable runs, same audit chain
- Same N2 deterministic lane (parsers always run; agent can add, not skip)
- Same N4 code search (no LLM grep of raw disks)
- Same N6 human HMAC approval (no auto-approve in any mode)
- Same N8 template from APPROVED only (no new facts)
- Same ingest boundary (network/SIEM/cloud/EDR, not direct host)
- Same detection timing (after N8, not before)

## Product flow (canonical)

One product, one `case_id`. Stage 0 is skippable for import-only cases. Register is not.
The three Nexus modes are **how you drive** N1–N8 — not extra stages after N8.
After ingest, “Nexus again” means re-run **N4→N8** on merged evidence — not collect / register / N2 from scratch.

```mermaid
flowchart TB
  subgraph ENTRY["Entry (pick one or both)"]
    S0["Stage 0 — Collect<br/>nexus collect run<br/>CLI only · freeze-gated · no LLM · no parsers"]
    IMP["Import-only<br/>existing dump / pack already on disk"]
  end

  REG["Register<br/>case init + evidence register<br/>SHA-256 custody · not part of N1–N8"]

  S0 --> REG
  IMP --> REG

  subgraph NEXUS["Nexus N1–N8 — one spine, three drivers"]
    direction TB
    N1["N1 Intake<br/>question · window · playbooks"]
    N2["N2 Process<br/>all direct host logs (Win/Linux/Mac)<br/>parsers + pre-collected → extractions/ + audit_id"]
    N3["N3 Index<br/>SQLite default · ES optional<br/>this-case N2 output only · no LLM"]
    N4["N4 Query<br/>code search · hits only · no LLM"]
    N5["N5 Interpret<br/>LLM narrates N4 hits only"]
    N6["N6 Approve<br/>human HMAC · DRAFT → APPROVED"]
    N7["N7 Timeline<br/>hits + ingest chronology"]
    N8["N8 Export<br/>template from APPROVED · no new facts"]

    N1 --> N2 --> N3 --> N4 --> N5 --> N6 --> N7 --> N8
  end

  REG --> N1

  MODE["How you drive the same spine<br/>Mode 1 examiner-led · Mode 2 thick · Mode 3 agents/MCP"]
  MODE -.-> NEXUS

  ING["Ingest<br/>Zeek / Suricata / PCAP / EDR / SIEM / cloud / TI<br/>non-direct-host only · PCAP parsed via tshark<br/>onto the same case_id"]

  N8 -->|"host story honest"| ING
  ING -->|"merge onto case"| N4

  DET["Detection eng optional<br/>draft Sigma / KQL / Suricata<br/>after APPROVED story · for SIEM team"]
  N8 -->|"APPROVED narrative ready"| DET

  UI["Examiner Portal / MCP<br/>Register · N1–N8 · Ingest · Detection · HMAC"]
  UI -.-> REG
  UI -.-> NEXUS
  UI -.-> ING
  UI -.-> DET
```

### How to read it

| Step | What it is | What it is not |
|------|------------|----------------|
| **Stage 0** | Live IR → pack on disk | Analysis, parsers, Portal harvest |
| **Register** | Custody gate into a case | An N1–N8 step |
| **N2** | All direct host logs (Win/Linux/Mac) → parsers + pre-collected host output → CSVs + audit_id | Network/SIEM/cloud/EDR (that is ingest, after N8) |
| **N3** | SQLite/ES index of this case's N2 output | The lab SIEM; a global ES store |
| **N1–N8** | The investigation brain | Three separate products |
| **3 modes** | *How* you drive N1–N8 | Extra stages after N8 |
| **Ingest** | Network/SIEM/cloud/EDR/PCAP onto **that** case (after N8) | A second collect / re-register / direct-host re-parse |
| **Nexus again** | Re-run **N4→N8** on merged evidence | Collect / Register / N2 from scratch |
| **Detection** | Optional drafts after APPROVED | Required next click; not N5 |

### Happy path (host first, then network)

```text
Collect (CLI) ──► Register ──► N1→N2→N3→N4→N5→N6→N7→N8
                                      │
                                      ▼ (optional)
                                   Ingest logs
                                      │
                                      ▼
                              N4→N5→N6→N7→N8 again
                                      │
                                      ▼ (optional)
                              Detection drafts (D1)
```

### Import-only shortcut

```text
Existing dump ──► Register ──► N1–N8 ──► (Ingest?) ──► (Detection?)
```

### N1–N8 spine (locked)

```
N1  Intake     examiner question + window + playbooks
N2  Process    all direct host logs (Win/Linux/Mac) → parsers + pre-collected → CSVs + audit_id
N3  Index      ES or SQLite index of THIS case's N2 output (no LLM)
N4  Query      code searches processed output    (no LLM)
N5  Interpret  LLM narrates N4 hits only
N6  Approve    human HMAC; reject / redirect
N7  Timeline   chronology from hits + ingest
N8  Export     Python template from APPROVED     (no new facts)
D1  Optional   draft detections after N8
```

Facts never come from the model. Hits come from N4. Findings cite hits.
Empty hits = INSUFFICIENT, not a coverage gap, not a fake story.

Continuous improvement (AI forensics, better parsers, playbooks, RAG) lands **inside**
N1–N8 — not as a parallel product.

### N2 — host parser lane (all direct host logs)

N2 is the **deterministic host-artifact lane**. It is given a directory
(the registered pack, or a mounted VMDK image) and recursively parses all
direct host evidence it finds. It has two jobs:

1. **Run external binary parsers** against raw host artifacts — Hayabusa,
   Suzaku, Chainsaw, EvtxECmd (EVTX), PECmd (prefetch), MFTECmd (MFT),
   RECmd (registry), AmcacheParser, AppCompatCacheParser, SBECmd
   (shellbags), LECmd/JLECmd (LNK/jumplists), autorunsc, BitsParser, SRUM,
   Volatility (memory). Each tool writes CSVs to
   `runs/<run_id>/extractions/` and gets an `audit_id` in the HMAC chain.

2. **Ingest pre-collected direct host logs** that Stage 0 gathered as
   structured output. These are **direct from the host** — collected live
   or from a mounted image. They include:
   - **Windows:** Velociraptor IRTriage JSON, KAPE CSV modules, Kansa CSV,
     PersistenceSniper CSV, Sysinternals output, DFIR-ORC exports, wevtutil
     EVTX exports
   - **Linux:** Velociraptor LinuxIRTriage JSON, UAC `ir_triage` output,
     journalctl exports, POSIX volatile output (auditd, authlog, bash_history,
     syslog — when collected directly from the host)
   - **Mac:** (future) direct host collection output

   All direct host logs — Windows, Linux, Mac — go through N2, not the
   ingest lane. N2 registers them as extractions with `audit_id`.

**The boundary is "direct from host" vs "from another source":**

| Source | Lane | Why |
|--------|------|-----|
| Collected directly from the host (Stage 0, mounted image, live SSH) | **N2** | Direct host evidence; custody chain; audit_id |
| EDR console export (e.g. Defender, CrowdStrike, SentinelOne) | **Ingest** | Not direct host collection — filtered/processed by the EDR vendor |
| SIEM export (Elastic, Splunk, Wazuh) even if it contains host events | **Ingest** | Aggregated from multiple sources; not direct host collection |
| ELK dashboard export with host details | **Ingest** | From the SIEM, not from the host directly |
| Velociraptor hunt JSON from Stage 0 | **N2** | Direct host collection via VR client |
| Velociraptor server export from ELK/SIEM | **Ingest** | From the SIEM, not direct VR collection |

**Pre-parsed skip:** If the pack already contains parsed CSV/JSON output
(e.g. a prior Hayabusa run), N2 should detect it, skip the redundant parser
run, register the existing CSVs as N2 extractions with `audit_id`, and
proceed to N3. The examiner does not pay for a second Hayabusa pass on
already-timelined EVTX. (Note: Stage 0 no longer runs parsers — but
import-only cases may bring pre-parsed output from another tool.)

**What N2 does NOT cover:**

- Network telemetry (Zeek, Suricata, Wireshark/PCAP, Sysdig)
- SIEM exports (Elastic, Splunk, SecurityOnion, Wazuh, SocRates)
- EDR console exports (Defender, CrowdStrike, SentinelOne — not direct host)
- Cloud logs (Azure, CloudTrail, M365)
- Threat-intel feeds (AbuseIPDB, MISP, OTX, ThreatFox, VirusTotal)
- Any log that was not collected directly from the host

Those are the **ingest lane** (below), which runs after the first N1–N8 pass.

### N3 — case index (not optional in practice)

N3 indexes **this case's N2 extractions** so N4 can query large CSVs without
linear-scanning every file. Two backends:

| Backend | When | Storage |
|---------|------|---------|
| **SQLite** | Default. Always available, no external service. | `runs/<run_id>/analysis/case_index.sqlite` |
| **Elasticsearch** | When `NEXUS_ES_URL` is set and reachable. | Per-case ES index `nexus-case-<case_id>` |

SQLite is the **offline-first default**. It loads N2 CSVs into a local
per-case SQLite database with the same schema as the ES index
(`case_id`, `family`, `file`, `line`, `text`, `ts`). N4 query hits the
SQLite index first; if ES is available and has the case index, N4 can use
it for larger/faster wildcard searches.

ES is **not** the CADRE lab SIEM (`192.168.77.50` / `elk`). N3 must not
point at the lab SIEM — it is a per-case working index, not a global
security monitoring store. See `case_index.py` guard.

N3 is "optional" only in the sense that N4 can fall back to **direct CSV
scan** (the `query_pack.py` needle search) if no index exists. But for any
case with Hayabusa-sized timelines (hundreds of MB of CSV), the index is
what makes N4 usable. The fallback is for small cases and offline-first
guarantees, not the intended production path.

### Ingest lane — network/SIEM/cloud/TI/EDR after N1–N8

The ingest lane is a **separate post-N8 step** that brings non-direct-host
telemetry onto the same `case_id`. It uses the Python importer registry
(`src/nexus/ingest/registry.py`) — 42 importers across 7 categories.

**The rule: if it was not collected directly from the host, it goes to ingest.**

**What belongs in ingest (v2 boundary):**

| Category | Importers | Why |
|----------|-----------|-----|
| **Network** | Zeek, Suricata, Wireshark/PCAP, Sysdig | N2 does not parse network captures. PCAP must be parsed via `tshark` (Wireshark CLI) into structured output before ingestion — not Arkime/NetFlow full packet analytics, but queryable network events for N4. |
| **SIEM** | Elastic, Splunk, SecurityOnion, Wazuh, SocRates | Aggregated from multiple sources. Even if the SIEM holds host events, they are not direct host collection. |
| **EDR** | EDR console exports (Defender, CrowdStrike, SentinelOne) | Processed/filtered by the EDR vendor — not raw direct host collection. |
| **Cloud** | Azure, CloudTrail, M365 | Cloud provider logs, not host logs. |
| **TI** | AbuseIPDB, MISP, OTX, ThreatFox, VirusTotal | Enrichment feeds, not host artifacts. |

**What does NOT belong in ingest (v2 boundary):**

All direct host logs — Windows, Linux, Mac — go through N2. This includes
auditd, authlog, bash_history, syslog, journald **when collected directly
from the host** (Stage 0 or mounted image). The same log types from a SIEM
export go to ingest.

The ~17 host-artifact importers in the registry (EVTX, Hayabusa, KAPE,
Velociraptor, Volatility, AmCache, Registry, LNK, etc.) are **legacy from
the old plan**. In v2, N2 covers them with stronger provenance (audit chain,
run isolation, FAIL/SKIP ledger). They will be either:
1. Re-scoped as N2 output readers (read N2's CSV output into Artifact objects
   for the case store), or
2. Deprecated because N2 covers them.

The re-wiring happens **after** the first N1–N8 host triage run on the
CADRE pack proves N2 is honest.

**PCAP parsing in ingest:** Raw PCAP files are not directly queryable. The
ingest lane must run 	shark (Wireshark CLI) to decompose PCAP into
structured output (conn, dns, http, tls, etc.) before importing. This is
not full packet analytics (Arkime/NetFlow territory) — it is making PCAP
queryable for N4 needle search. The Zeek importer handles Zeek TSV/JSON
logs; the Wireshark importer handles PCAP via tshark decomposition.

**SIEM/EDR differentiation (future):** ELK dashboards, Arkime, and
Velociraptor server exports may all contain host details, but they come
from different sources and are not direct host collection. They go to
ingest. How we differentiate and correlate SIEM-sourced host events from
N2 direct host evidence in the UI is a high-effort problem — the Examiner
Portal must bring both into a unified view without confusing provenance.
For now, the CADRE-run investigation will help us understand what the UI
needs to do.

## Who runs N4 query?

N4 is **search code**, not a chat. Three callers, one function (`n4_hits`):

1. **Playbooks (automatic).** YAML `query_terms` plus tokens from the
   examiner question. Host-compromise / attacker-activity questions load
   execution, persistence, log-tamper, and credential playbooks — not only
   malware family names (mimikatz/beacon). This is the default pack
   `analysis/query_pack.md` that N5 reads. N3 indexes Hayabusa-sized CSVs
   (needle rows); it must not fill the budget with RDP-cache tiles.
2. **Examiner (visual + CLI).** Portal **Query** tab, or
   `nexus case query --needles sdelete,.pst`. You are hunting in
   **already-parsed** CSVs / the case ES index — not in `Evidence-files/`.
3. **Agent / LLM (MCP).** Tool `query_case_hits`. The model may **propose**
   needles from playbooks/RAG. The tool **executes** the search. Empty
   result means stop, do not invent a row.

The LLM does not grep raw disks. It does not treat RAG snippets as evidence.

## Knowledge YAML vs RAG

**YAML** (`src/nexus/data/knowledge/`):

- Artifact cards: where the file lives, which parser
- Playbooks: what to **query** after parse (`query_terms` + Identify/Content steps)
- This is the forensic checklist. It will get better when SANS extracts land.
  Do not bake Rocba plot into prompts.

**RAG** (`forensic_rag_search`, Chroma, downloadable index):

- Methodology only (Sigma, ATT&CK, KAPE cards, LOLBAS)
- Used at N5, scoped to hit families (prefetch, LNK, SRUM, …)
- Never an `audit_id`. Never a substitute for a CSV row.

`tools` mode does not load RAG. Process first, query second, interpret third.

## Tools vs design (do not skip the lane)

`tools` is the mandatory parser pass for **present** artifacts. FAIL = the
parser ran and lost (timeout/error). SKIP = artifact absent, or SIFT was never
configured (Windows-only MCP does not fake a SIFT SKIP). The LLM does not
choose this set.

`design` (agentic) runs **the same lane first**. ReAct may then add extras
(carve, extra Volatility plugins). Agentic must not paper over a FAIL by
omitting the parser. Extras after the lane, not instead of it.

## If the analysis is wrong (N6)

Do not re-parse a good ledger. Redirect:

1. Reject the DRAFT (or leave it DRAFT).
2. Add needles: `nexus case query --needles Prefetch,sdelete --persist`
   or Portal Query, or `query_case_hits(..., persist=true)`.
3. Re-run interpret only:
   `nexus pipeline --mode interpret --from-case INC-...`
4. New DRAFTs. Approve what is supported. INSUFFICIENT is valid.

HITL is the accuracy gate. Lab auto-approve is not 12-pass HITL.

## Report (N8)

`REPORT.md` is a **template** (`dfir_report.py`) filled from APPROVED
findings + N7 timeline. The LLM already wrote observation vs interpretation
at N5. It does not write the file.

Before HMAC, open `reports/REPORT-DRAFT.md` — same template with DRAFT
findings and a PREVIEW watermark. `nexus report generate` writes that
preview when nothing is APPROVED yet. Tools mode writes `TOOL-RUN.md`
only; it must not overwrite `REPORT.md`.

Polish later may rephrase headings. It must not add hosts, times, or
malware names that are not in APPROVED hits. Prefer examiner edits
in the portal / markdown over a second model pass.

## CLI cheat sheet

```
# once: .env, SSH keys, nexus doctor
nexus collect run --os windows --host <ip> --user analyst --identity ~/.ssh/id
nexus case init "IR host"
nexus evidence register <pack>
nexus pipeline --mode tools --case <pack>          # N2: parsers + pre-collected host logs
nexus pipeline --mode interpret --from-case INC-... # N5: LLM on N4 hits
nexus case query --needles sdelete,.pst             # N4: search parsed output
nexus approve --examiner e2e_host F-021             # N6: human HMAC
nexus report generate                               # N8: template from APPROVED
# after N8: ingest network/SIEM/cloud onto same case, then N4→N8 again
```

Portal: Steer (intake) → Query (hits) → Findings → Approve → Timeline.

## Beside the loop (workstation — not a second product)

N1–N8 is the investigation brain. Same case, same HMAC, examiner/agent may also call:

- Windows/SIFT catalogs (`run_windows_command` / `run_command`) — N2
- Triage `check_*` — known-good vs UNKNOWN (neutral)
- TI `ti_*` — IOC feeds (no OpenCTI required)
- Sigma library search/translate — not architecture D1 drafts
- VR hunts — mock offline; live = VR-GATE
- FK `get_*` — YAML methodology via MCP (RAG is still Chroma at N5)

OpenCTI is **parked**. Elasticsearch (`nexus-es`) searches **this case’s parsed rows**. OpenCTI would search an org CTI graph about an IOC taken *from* those rows. Different job.

Parser contract (public): [TOOL-EVIDENCE-MAP.md](cases/TOOL-EVIDENCE-MAP.md).
What shipped: [CHANGELOG.md](../CHANGELOG.md).

Examiner hosts keep a gitignored `Docs/internal/` tree (ship ledger, old-vs-new, live backlog). Those files are not in the public clone.
