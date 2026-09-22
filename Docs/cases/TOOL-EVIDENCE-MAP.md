# Tool ↔ evidence map (product contract)

This is the source of truth for **what runs** in `tools`, `coverage`, and `design`.
It is not a one-case patch. Presence is evaluated against **this evidence pack**,
not the full catalog.

**Complete catalog (Windows 53 + SIFT 68 + knowledge gaps):**
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
| Thumbcache / `$LogFile` | present | `$LogFile` → LogFileParser (`/LogFileFile:` + `/OutputPath:`, wired). Thumbcache CLI fetched + argv verified; no lane job yet. **Neither has a sample in this evidence pack** — see availability table |
| RDP bitmap / BITS / UAL | cache tiles / qmgr.db / SUM `*.mdb` | **stage a local copy first** (mounted VHDX I/O is slow). bmc-tools on non-empty `.bmc`/`.bin` only (0-byte tiles SKIP, not FAIL); timeout scales with size. BitsParser on `qmgr.db` after the same esentutl copy+repair SRUM uses (dirty KAPE ESE hangs Impacket `getNextRow`). No `--carveall` on the tools lane. KStrike if `*.mdb` exists |
| `$I30` file | extracted `$I30` only | MFTECmd `-f` |
| Named samples | intake `sample_files` | capa / densityscout / yara only when named (and installed) |
| Live response | `NEXUS_LIVE_RESPONSE=1` | autorunsc / handle / Get-InjectedThreadEx; memory only if `NEXUS_LIVE_ACQUIRE_MEMORY=1` |

YAML artifacts with no argv builder (WER minidumps, VSS, …) appear in
`extractions/_artifact_completeness.json` as `PRESENT_NO_PARSER` or `ABSENT`.
That is a coverage gap, not a silent skip of a parser we own.

## SIFT lane

Scheduled only when the examiner named a SIFT root (`NEXUS_SIFT_EVIDENCE_ROOT`
/ `case_context.sift_evidence_root`) **or** a SIFT MCP (`run_command`) is
connected. Windows-only stdio (`nexus serve` on this workstation) does **not**
emit a SKIP row for missing SIFT — that is not a host-image coverage hole.
Memory dumps are operator-named (`NEXUS_SIFT_MEMORY_FILE`); they are **not**
inferred from a KAPE `I:\C` reconstruct.

If SIFT MCP is connected but no root is set, the ledger records one honest SKIP.

- Volatility against `NEXUS_SIFT_MEMORY_FILE` (else `{root}/memory/Rocba-Memory.raw` convention for existing Rocba packs)
- `fls` only if `NEXUS_SIFT_E01` is set
- **No** full-tree `log2timeline` / plaso (disk cannot hold a multi-GB store)
- `mactime` after MFTECmd bodyfile is pushed (`NEXUS_SIFT_MACTIME=1`)

## Evidence availability — local pack (`Evidence-files/`, scanned 2026-09-20)

Read-only file listing; **no tools were run**. This is what the T3 Tool × Evidence
matrix can actually be validated against. `_fixtures` / `_staging` / `_e2e-out` /
`_tools` are test scaffolding, not case evidence. Case-500 raw parity data is
additionally mounted: `H:\` (KAPE triage volume) and `E:\Evidence_files\500`
(E01 + raw memory) — see below. Full detail: `Docs/internal/TOOLS-INVENTORY.md`
(tool side) + this table (evidence side).

### Available (sample on disk)

| Family | Sample here | Windows tools | SIFT default tools |
|---|---|---|---|
| EVTX | `01-windows/evtx/` (500 / 504-win10 / h-triage / Yamato attack samples, 1 192 files), `rocba-fredr/evtx`, `showcase/rocba-500/host/evtx` | EvtxECmd, Hayabusa, Suzaku, Chainsaw, Zircolite, DeepBlueCLI | evtx_dump family, plaso (`log2timeline.py`) |
| Registry hives | `01-windows/registry/{NTUSER.DAT,SAM,SECURITY,SOFTWARE,SYSTEM}`, `01-windows/504-win10-ws/SOFTWARE`, `rocba-fredr/registry`, showcase | RECmd (+ AppCompatCacheParser shimcache, AmcacheParser), RegRipper 3.0 (text plugins) | RECmd (dotnet), regripper (`misc.yaml`) |
| Prefetch | `01-windows/prefetch/*.pf` (331) | PECmd | plaso (prefetch parser) |
| Amcache | `01-windows/amcache/Amcache.hve`, `rocba-fredr/amcache` | AmcacheParser | AmcacheParser (dotnet) |
| Shimcache | SYSTEM hive (above) | AppCompatCacheParser | AppCompatCacheParser (dotnet) |
| SRUM | `01-windows/504-win10-ws/{srudb.dat,SRU.*}`, `rocba-fredr/srum/SRUDB.dat`, showcase | copy + esentutl + SrumECmd | (no SIFT lane job) |
| MFT | `01-windows/kape-out/{MFT,mft.csv}`, `rocba-fredr/ntfs/$MFT`, `showcase/kape/MFT` | MFTECmd `--csv` + `--body`, `-f $J` for USN | mactime (bodyfile), fls (opt-in `NEXUS_SIFT_E01`) |
| Recycle Bin | `rocba-fredr/recycle/$I*` (4), showcase | RBCmd | — |
| LNK | `01-windows/lnk/**` (439) | LECmd | — |
| Jump lists | `rocba-fredr/jumplists/**` (90), `500-precooked/*Destinations.csv` | JLECmd | — |
| Shellbags | `rocba-fredr/shellbags/UsrClass.dat`, showcase | SBECmd | — |
| Browser (Chrome + Edge) | `01-windows/browser/fredr/.../{Chrome,Edge}/User Data/*/History`, `showcase/.../browser` | SQLECmd (mandatory), Hindsight (extra, JSONL) | — |
| WMI repository | `rocba-fredr/wmi/OBJECTS.DATA`, showcase | RECmd WMI batch, strings | — |
| Scheduled tasks | `01-windows/tasks/system32-tasks/` (XML-content task files), Kansa Autorunsc CSVs | EVTX lane + SOFTWARE hive (XML files are copied, no dedicated parser) | — |
| Kansa / KAPE pre-collected | `01-windows/{kansa,services,tasks}/**` CSVs, `kape-out/` | N2 pre-collected lane | — |
| USN `$J` (parsed) | `02-memory/508-precooked/ntfs-anti-forensics/usnjrnl-rd01.csv` | MFTECmd `-f $J` needs the raw file | — |
| WER minidump | `02-memory/dumps/minidump.dmp`, `rocba-508/minidump.dmp` | strings, YARA (on-demand) | — |
| Defender quarantine | `02-memory/508-precooked/malware/quarantine.{csv,tar}` | maldump not-wired (CSV present) | — |
| PowerShell transcript | `04-network/572/.../tshark_objects/...PowerShell_transcript*.txt` | copy into extractions (plain text) | grep / strings |
| Linux logs | `03-linux/{auth.log,syslog,audit.log,bash_history,journal.json}`, `04-network/572/.../var/log/{secure,audit.log,wtmp,lastlog,btmp}` | — | grep, awk, plaso |
| Linux collect / plaso store | `03-linux/528/{collect,plaso,psort,mft}.tar.gz` | — | plaso `log2timeline.py`, `psort.py` |
| Linux disk image | `03-linux/608-sift/dmz-www/dmz-www-disk.7z` | — | fls/icat (opt-in), plaso |
| Containers | `03-linux/608-sift/docker/prebuilt/*.tar.gz` | — | — |
| macOS logs | `03-linux/608-sift/precooked/maclogs.7z`, `triagedata.7z` | — | plaso |
| PCAP | `04-network/pcap/*` (29, ~1.3 GB) | tshark (local session guarantee), Suricata (local) | tshark, tcpflow |
| Zeek logs | `04-network/zeek/**` (~6.9 GB: conn/dns/http/ssl/files/kerberos), 572 derived | — | (not a SIFT default; consume as log files) |
| Suricata EVE | `04-network/suricata/eve.json` | ingest importer | — |
| NetFlow | `04-network/572/lab-3.2/.../netflow/**` (402 nfcapd, ~2.9 GB) | nfdump importer | nfdump |
| SIEM Elastic/ECS | `05-siem/elastic.ndjson`, `05-siem/cadre-elk/*.ndjson` (11) | ingest importers | — |
| SIEM Splunk / Wazuh | `05-siem/splunk.csv`, `05-siem/wazuh.json` | ingest importers | — |
| Cloud AWS/Azure/M365/GCP/K8s | `03-linux/608-sift/aws/cloudtrail/**` (47 k gz), `06-cloud/{cloudtrail-sample,azure-activity-sample,m365-ual}.json`, `06-cloud/500-cloud-logs/*.csv`, `06-cloud/509-section6/{gcp,k8slogs}.zip` | ingest importers | — |
| Email | `09-email-archives/{sample.pst,fred.ost,phishing.eml}`, recycle `$I*.pst` | ingest email importers | — |
| IR platforms | `08-ir-platforms/` (Velociraptor sample + server config, CyberTriage fixture, TheHive/IRIS JSON) | N2 VR IRTriage path / ingest | — |
| TI samples | `07-ti/**` (abuseipdb, MB, MISP, OTX, URLhaus, VT) | `ti_lookup` / `ti_fanout` | — |
| Sigma rules | `10-sigma/rules` (4 252) | detection indexer | Zircolite bundled ruleset |

### Case 500 evidence mounts (`H:\` EnCase E01 + `I:\` KAPE triage + `E:\Evidence_files\500`)

Read-only listings only (no tools run), 2026-09-20. Two images are mounted at
once — do not mix them up:

| Mount | Source | Exposes |
|---|---|---|
| `H:\` | `E:\Evidence_files\500\C-Drive\rocba-cdrive.e01` EnCase E01 (+ FTK `.diff`) | Full live C: — registry `config\`, WMI `OBJECTS.DATA`, Tasks, EVTX (213), `$MFT`, **hiberfil.sys / pagefile.sys / swapfile.sys / DumpStack.log.tmp**, `ProgramData` BITS/Defender/WER, `System Volume Information`, Users (fredr, srl-h, Public). **Original NTFS ACLs are enforced by the mount** — most user/System paths deny a non-elevated shell |
| `I:\` | `E:\Evidence_files\500\Rocba-Triage.vhdx` (KAPE triage output) → `I:\C` | `$MFT`, `$LogFile` (41.7 MB), `$Boot`, `$Secure_$SDS`, `$Extend\$J` (38.5 MB), `$I30` (7), thumbcache (15), `ActivitiesCache.db` (3), Firefox `places.sqlite`, RDP cache `Cache000{0,1}.bin`, `setupapi.dev.log` (2), PSReadLine history, raw host set (EVTX 339, prefetch 346, SRUM, Amcache, `UsrClass.dat` ×2, jump lists 50, `$Recycle` 19, registry, `Windows.old`), `LongFileNames`, KAPE Copy/Skip logs |
| `E:\Evidence_files\500` | case bundle | `rocba-cdrive.e01` (22 GB) + `.diff`, `Rocba-Memory.raw` (17.7 GB), `Rocba-Triage.vhdx` (6.6 GB), Exercise outputs |

**E01-present but ACL-gated on `H:\`** (denied to the non-elevated shell — content
exists): `ProgramData\Microsoft\Network\Downloader` (BITS),
`Windows Defender\Quarantine`, `System Volume Information`
(possible VSS), `Windows\Prefetch`, per-user `NTUSER.DAT`, `Recent`, RDP `Cache`,
`ConnectedDevicesPlatform`, Firefox `Profiles`, PSReadLine, `Windows\Explorer`
(iconcache/thumbcache). Read them via an elevated shell or SIFT `fls/icat`
(`NEXUS_SIFT_E01`). `WER\ReportArchive` directory names are listable on `H:\`, but the report contents are **ACL-denied** — WER is on the manual-retrieval list.
`Windows\System32\LogFiles\SUM` does not exist (client OS).
`$LogFile` / `$J` / `$Boot` are **not** exposed by the E01 mount — use `I:\C\...`.

### Pending evidence (not accessible yet — mapped to a source/action)

| Family | Consuming tool | Source | Action |
|---|---|---|---|
| BITS `qmgr*` | BitsParser | `H:\` E01: `ProgramData\Microsoft\Network\Downloader` | elevated read, or SIFT `fls`/`icat` |
| Defender quarantine | maldump / ingest | `H:\` E01: `...\Windows Defender\Quarantine` | elevated read, or SIFT `fls`/`icat` |
| VSS snapshots | vshadowinfo / mount | `H:\` E01: `System Volume Information` | elevated read; confirm store exists |
| WER report contents | strings / YARA | `H:\` E01: `...\WER\ReportArchive\*` | ACL denied — operator copy |
| `iconcache_*.db` | thumbcache_viewer_cmd | `H:\` E01: `Windows\Explorer` (denied); `I:\` has thumbcache only | elevated read, or SIFT `fls`/`icat` |
| UAL SUM `*.mdb` | KStrike | — | Server-only; n/a for this Win10 client |
| Sysdig/Falco runtime | sysdig lane | not present anywhere | needs a runtime capture |
| Security Onion alerts | ingest | fixture only (`_fixtures`) | needs an SO export |
| Socrates alerts | ingest | fixture only (`_fixtures`) | needs a Socrates export |
| CyberTriage export | ingest | fixture only (`_fixtures`) | needs a CT export |
| macOS full collection | plaso | `maclogs.7z` only | needs a full mac collection |

**T3 consequence:** Windows host families are now covered by the two mounts —
readable on `I:\` (NTFS metadata, user artifacts, raw host set) or on `H:\`
(registry, WMI, Tasks, EVTX, `$MFT`, page/hiber files); the remaining Windows gaps are five ACL-gated paths on the E01
(BITS, Defender quarantine, VSS `System Volume Information`, iconcache, WER) that
need an elevated read or the SIFT E01 path. Non-Windows ingest families remain true collection gaps.

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

If the JSON is missing, staging falls back to **N4 hit clusters**
(`n4_finding_candidates`: sdelete / PST / Drive / USB…), never “parser OK”
placeholders.

### HITL

Findings stage as **DRAFT** (`record_finding`). The graph **pauses**
(`await_approval`). Only the examiner promotes them: `nexus approve` or the
Examiner Portal. Then `nexus pipeline --resume`. The agent cannot approve.

Unhappy with the analysis? Do **not** re-parse a good ledger. Add needles
(`nexus case query --needles …` or Portal Query), then
`nexus pipeline --mode interpret --from-case <id>`.

### Report

`generate_report` builds `REPORT.md` from **APPROVED** findings only
(`dfir_report.py` template). DRAFT/REJECTED are omitted. Structure is code;
the LLM filled observation/interpretation earlier. `tools` mode writes
`TOOL-RUN.md` instead — that is a ledger, not an IR.

`interpret` reuses a finished tools-mode case (do not re-run parsers):

```
nexus pipeline --mode interpret --from-case INC-20260813122635
```

## What else exists (not pipeline modes)

Do not collapse these into `tools|coverage|design`. Test them **after**
Nexus mode is honest on one evidence pack. See [NEXUS-MODE.md](../NEXUS-MODE.md).

| Surface | What it is |
|---------|------------|
| **Windows / SIFT / live-acq lanes** | Which parsers the mandatory lane may schedule (this file + TOOL-CATALOG-MAP) |
| **CLI / MCP / Portal** | Three UIs on the same case brain (`nexus`, `nexus serve`, `/portal`) |
| **Ingest** | 45 importer classes (`nexus ingest`) — logs in, not host-triage parsers |
| **Heuristic 6-agent graph** | Offline alert/cloud/network/endpoint/synthesis/timeline — **not** `nexus pipeline` |
| **RAG / TI / Sigma / VR / triage** | Optional analysis MCP tools |
| **Custody** | evidence hash, approve/reject, backup, export, audit verify |

Operator loop: [NEXUS-MODE.md](../NEXUS-MODE.md).
Change log (what landed): [`CHANGELOG.md`](../../CHANGELOG.md).
