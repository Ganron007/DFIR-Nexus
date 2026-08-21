# Nexus mode (the investigation loop)

Open this file if Cursor preview crashes on INTERPRET-HITL-CONTEXT-PLAN.md
or COMPLETE-TO-SHIP.md (assertion failed). Those two stay the architecture
tracker and the 12-pass ledger. This page is the operator mental model.

One product, three doors, one `case_id`:

1. **Nexus mode** (this page) — host pack: process, query, interpret, approve, export
2. **Import/ingest** — Zeek, Suricata, EVTX, EDR/SIEM export onto the **same** case
3. **Detection eng** — after the story: draft Sigma/KQL/Suricata for the SIEM team

Do import and detection **after** Nexus mode is honest on one pack.
They reuse the same query / HITL / report brain. They do not replace it.

## Stage 0 — live collect (before N1)

Stage 0 is a **live run** against a host you can authenticate to:

`nexus collect run --os windows --host <ip> --user <acct> --identity <key>`

That wraps **every FOSS collector we can run** (Windows: Kansa-full, Sysinternals,
PersistenceSniper, wevtutil, Hayabusa, Suzaku, Chainsaw, KAPE, DFIR-ORC, WinPmem,
live Velociraptor; Linux: POSIX volatile, journalctl, UAC `-p full`, AVML, VR).
Writes `hosts/<hostname>/…` + `manifest.json`. Then `nexus case init` and
`nexus evidence register` the pack. **Not** an analysis dump.

`nexus collect import <dump>` is the helper when you already have a KAPE image or
Kansa CSVs. Velociraptor is a **Stage 0 collector**: skipped honestly when the
server is mock or unreachable; live hunts run with `collect_client` when
`NEXUS_VR_ENDPOINT` + `NEXUS_VR_API_KEY` are set. Opt out with `--profile disk`
(no RAM dump), `--profile volatile`, `--only kansa,kape`, or `--no-*`.

Without SSH or WinRM (or local) credentials, collection does not run. That is
the orchestrator boundary.

## The loop (locked)

```
Stage 0  Collect    live IR with auth → pack on disk          (no LLM)
N1  Intake     examiner question + window + playbooks
N2  Process    parsers write CSVs + audit_id     (no LLM)
N3  Index      optional ES of THIS case's output (no LLM)
N4  Query      code searches processed output    (no LLM)
N5  Interpret  LLM narrates N4 hits only
N6  Approve    human HMAC; reject / redirect
N7  Timeline   chronology from hits + ingest
N8  Export     Python template from APPROVED     (no new facts)
D1  Optional   draft detections after N8
```

Facts never come from the model. Hits come from N4. Findings cite hits.
Empty hits = INSUFFICIENT, not a coverage gap, not a fake story.

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
nexus pipeline --mode tools --case D:\pack
nexus pipeline --mode tools --from-case INC-... --case I:\C
nexus case query --needles sdelete,.pst
nexus pipeline --mode interpret --from-case INC-20260813122635
nexus config --examiner e2e_host --setup-password --replace
nexus approve --examiner e2e_host F-021
nexus report generate
nexus ingest conn.log --source zeek --case INC-...
nexus case detections --finding-ids F-021,F-022
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

Dispositions: `Docs/internal/OLD-VS-NEW.md` §4. Not a tracker.

## Trackers (one checklist)

- Actions / 12-pass: `Docs/internal/COMPLETE-TO-SHIP.md` §0.3 (do not flip `[x]` without 12-pass)
- Architecture leftover: `Docs/internal/INTERPRET-HITL-CONTEXT-PLAN.md` §4
- Keep/Park only: `Docs/internal/OLD-VS-NEW.md` §4
- Session pointer: `Docs/internal/ACTIVE.md`
- Parser contract: `Docs/cases/TOOL-EVIDENCE-MAP.md`
