# Complete tool catalog and mapping

Source of truth for **what can run**, **what knowledge YAML says**, and **what the mandatory lane auto-runs**.
This is not a redesign. DFIR-Nexus still **orchestrates existing tools** (HMAC audit, DRAFT + HITL).
The LLM does not pick parsers for artifacts that are present.

Companion: [TOOL-EVIDENCE-MAP.md](TOOL-EVIDENCE-MAP.md) (mode + lane contract).

## Three layers (do not collapse)

| Layer | What it is | Where |
|-------|------------|--------|
| **1. MCP catalog** | Binary is allowed through `run_windows_command` / `run_command` | Windows: `_WIN_CATALOG` in `src/nexus/tools/windows.py` (37). SIFT: `src/nexus/data/catalog/*.yaml` (68, excluding `security.yaml`) |
| **2. Knowledge YAML** | When/how: artifact `related_tools` + tool cards `artifacts_parsed` | `src/nexus/data/knowledge/artifacts/` and `.../tools/` |
| **3. Mandatory lane** | Auto-scheduled if the artifact is **present on this evidence** | `src/nexus/langgraph/tool_lane.py` |

Catalog ⊃ knowledge cards ⊃ lane. Dumping grep/awk/winpmem/capa into the lane would be a design change. We do not do that.

**Lane roles** used below:

| Role | Meaning |
|------|---------|
| **mandatory** | Runs when the artifact is present (all three pipeline modes) |
| **extra** | Cataloged + documented; design-mode / examiner follow-up only (do not force-run alongside the primary parser) |
| **live-acq** | Live host only — not image triage |
| **on-demand** | Needs a specific file, PCAP, E01, or examiner argv |
| **opt-in** | Env-gated (`NEXUS_SIFT_E01`, named memory file) |
| **cataloged-not-scheduled** | Wired and documented; we refuse to auto-run (disk/time) |
| **not-in-lane** | Catalog utility; examiner/`run_command` only |
| **not-wired** | Knowledge mentions it; no MCP catalog binary |

---

## Windows MCP catalog (37)

Every key in `_WIN_CATALOG` is executable via `run_windows_command` when the binary is installed.

| Key | Binary | Knowledge card | Artifact YAML (`related_tools`) | Lane |
|-----|--------|----------------|----------------------------------|------|
| `amcacheparser` | AmcacheParser | `tools/zimmerman/amcacheparser.yaml` | `amcache` | **mandatory** if `Amcache.hve` |
| `appcompatcacheparser` | AppCompatCacheParser | `tools/zimmerman/appcompatcacheparser.yaml` | `shimcache` | **mandatory** if SYSTEM hive |
| `evtxecmd` | EvtxECmd | `tools/zimmerman/evtxecmd.yaml` | all `event_logs_*` | **mandatory** if `Logs\*.evtx` (`-d Logs`) |
| `hayabusa` | Hayabusa | `tools/timeline/hayabusa.yaml` | all `event_logs_*`, `hayabusa_alerts` | **mandatory** (same EVTX dir; Sigma timeline) |
| `suzaku` | suzaku | `tools/timeline/suzaku.yaml` | all `event_logs_*` | **extra** — Hayabusa-family alternative, not a second EVTX parser |
| `chainsaw` | chainsaw | `tools/timeline/chainsaw.yaml` | all `event_logs_*` | **extra** — same |
| `pecmd` | PECmd | `tools/zimmerman/pecmd.yaml` | `prefetch` | **mandatory** if Prefetch dir |
| `lecmd` | LECmd | `tools/zimmerman/lecmd.yaml` | `lnk_files` | **mandatory** per-user `Recent` |
| `jlecmd` | JLECmd | `tools/zimmerman/jlecmd.yaml` | `jump_lists` | **mandatory** per-user Automatic/CustomDestinations |
| `sbecmd` | SBECmd | `tools/zimmerman/sbecmd.yaml` | `shellbags` | **mandatory** per-user `UsrClass.dat` |
| `wxtcmd` | WxTCmd | `tools/zimmerman/wxtcmd.yaml` | `activitiescache` | **mandatory** per-user `ActivitiesCache.db` |
| `sqlecmd` | SQLECmd | `tools/zimmerman/sqlecmd.yaml` | `browser_history`, `activitiescache` | **mandatory** per-user Chrome/Edge/Firefox DBs |
| `recmd` | RECmd | `tools/zimmerman/recmd.yaml` | `userassist`, `bam`, `registry_run_keys`, `registry_services`, `mountpoints2`, `user_activity_mru`, `scheduled_tasks`, `wmi_persistence` | **mandatory** `config\` + per-user `NTUSER.DAT` |
| `mftecmd` | MFTECmd | `tools/zimmerman/mftecmd.yaml` | `mft`, `usn_journal`, `ntfs_logfile`, `ntfs_i30`, `alternate_data_streams`, `ntfs_resident_data` | **mandatory** `$MFT` (CSV + `--body`); **mandatory** `$J` / `$UsnJrnl:$J` if present |
| `rbcmd` | RBCmd | `tools/zimmerman/rbcmd.yaml` | `recycle_bin` | **mandatory** if `$Recycle.Bin` |
| `srumecmd` | SrumECmd | `tools/zimmerman/srumecmd.yaml` | `srum` | **mandatory** if `SRUDB.dat` (copy + esentutl) |
| `bstrings` | bstrings | `tools/zimmerman/bstrings.yaml` | — (file-targeted) | **on-demand** |
| `autorunsc` | autorunsc | `tools/persistence/autorunsc.yaml` | `registry_run_keys`, `registry_services`, `wmi_persistence` | **live-acq** (image path is RECmd) |
| `sigcheck` | sigcheck | `tools/malware/sigcheck.yaml` | `digital_signatures` | **on-demand** (named file) |
| `strings` | strings64 | `tools/malware/strings_tool.yaml` | — (binaries only; not plain-text logs) | **on-demand** |
| `handle` | handle64 | `tools/malware/handle.yaml` | — | **live-acq** |
| `procdump` | procdump64 | `tools/memory/procdump.yaml` | — | **live-acq** (dump then Volatility) |
| `winpmem` | winpmem | `tools/memory/winpmem.yaml` | — | **live-acq** |
| `dumpit` | dumpit | `tools/memory/dumpit.yaml` | — | **live-acq** |
| `moneta` | moneta64 | `tools/malware/moneta.yaml` | — | **live-acq** |
| `hollows_hunter` | hollows_hunter | `tools/malware/hollows_hunter.yaml` | — | **live-acq** |
| `get_injectedthreadex` | Get-InjectedThreadEx | `tools/malware/get_injectedthreadex.yaml` | — | **live-acq** |
| `mactime` | mactime.pl | `tools/timeline/mactime.yaml` | `mft` | Windows catalog has the Perl script; **lane runs mactime on SIFT** after MFTECmd `--body` |
| `kape` | KAPE | `tools/triage/kape.yaml` | `bits_jobs`, `ual` | **on-demand** collection (not a host-triage parser) |
| `capa` | capa | `tools/malware/capa.yaml` | — | **on-demand** (named executable) |
| `yara` | yara64 | `tools/malware/yara.yaml` | `wer`, `defender_quarantine` (with maldump) | **on-demand** |
| `densityscout` | densityscout | `tools/malware/densityscout.yaml` | — | **on-demand** (intake `sample_files`) |
| `thumbcache_viewer` | thumbcache_viewer_cmd | `tools/analysis/thumbcache_viewer.yaml` | `thumbcache` | **cataloged-not-scheduled** until CLI is verified on a fetched binary |
| `bmc-tools` | bmc-tools.py | `tools/analysis/bmc_tools.yaml` | `rdp_bitmap_cache` | if Cache tiles present **and** installed; else one SKIP |
| `bitsparser` | BitsParser.py | `tools/analysis/bitsparser.yaml` | `bits_jobs` | if `qmgr.db` / `qmgr*.dat` present **and** installed; else one SKIP |
| `kstrike` | KStrike.py | `tools/analysis/kstrike.yaml` | `ual` | if SUM `*.mdb` present **and** installed (Server); else one SKIP. Silent on clients (no mdb) |
| `logfileparser` | LogFileParser64 | `tools/analysis/logfileparser.yaml` | `ntfs_logfile` | **cataloged-not-scheduled** until CLI is verified on a fetched binary |

**Windows catalog → knowledge card:** all 37 keys have a card. Fetch the new parsers with `Tools/fetch-windows-tools.ps1` (operator machine, internet).

---

## SIFT catalog (68)

Loaded by `src/nexus/tools/sift.py` from YAML. Every `name` is allowed through `run_command` (sandbox + `security.yaml` denylist still apply).

### Forensic parsers (wired; subset is lane)

| Catalog name | File | Knowledge card | Lane |
|--------------|------|----------------|------|
| AmcacheParser, PECmd, AppCompatCacheParser, RECmd, MFTECmd, EvtxECmd, JLECmd, LECmd, SBECmd, RBCmd, SrumECmd, SQLECmd, **WxTCmd**, bstrings | `catalog/zimmerman.yaml` (14) | matching `tools/zimmerman/*.yaml` | Same as Windows **mandatory** when the Windows share is the triage root. SIFT copies of EZ tools are an alternate host, not a second lane. |
| hayabusa | `catalog/timeline.yaml` | `tools/timeline/hayabusa.yaml` | **mandatory** on Windows MCP for EVTX; SIFT hayabusa is extra if Windows already ran it |
| mactime | `catalog/timeline.yaml` | `tools/timeline/mactime.yaml` | **mandatory** after MFTECmd bodyfile is pushed |
| log2timeline, psort | `catalog/timeline.yaml` | `tools/timeline/plaso.yaml`, `psort.yaml` | **opt-in** `NEXUS_SIFT_PLASO=1` only (not scheduled otherwise — no SKIP row) |
| vol3 (`binary: vol`) | `catalog/volatility.yaml` | `tools/volatility/volatility3.yaml` | **mandatory** if `NEXUS_SIFT_MEMORY_FILE` or `{root}/memory/*.raw` |
| fls | `catalog/sleuthkit.yaml` | `tools/sleuthkit/fls.yaml` | **opt-in** `NEXUS_SIFT_E01` |
| icat, mmls, blkls | `catalog/sleuthkit.yaml` | matching `tools/sleuthkit/*.yaml` | **on-demand** |
| tshark, zeek | `catalog/network.yaml` | `tools/network/*.yaml` | **on-demand** (PCAP present) |
| yara, strings, ssdeep, binwalk | `catalog/malware.yaml` | yara/strings/ssdeep cards; **binwalk has no card** (catalog-only) | **on-demand** |
| bulk_extractor, **bmc-tools** | `catalog/file_analysis.yaml` | matching cards | bulk_extractor on-demand; bmc-tools also in the Windows lane |
| exiftool, regripper, hashdeep, 7z | `catalog/misc.yaml` | matching knowledge cards | **on-demand** (RegRipper aliases to RECmd for Windows hive completeness) |
| dc3dd, ewfacquire, ewfmount, vshadowinfo, vshadowmount, **esedbexport** | `catalog/misc.yaml` | `tools/imaging/*.yaml`, `tools/file_analysis/esedbexport.yaml` | **on-demand** / VSS; esedbexport is the SIFT fallback for BITS/UAL ESE |

### Unix utilities (wired; never lane)

`catalog/analysis.yaml` (27): grep, awk, sed, cut, sort, uniq, wc, head, tail, tr, diff, jq, zcat, zgrep, tar, unzip, file, stat, find, ls, md5sum, sha1sum, sha256sum, xxd, hexdump, readelf, objdump.

These are **catalog-on-demand**. No per-tool knowledge cards (they are not artifact parsers). `related_tools: [grep]` on Linux artifacts is documentation for examiners, not a scheduler key.

`catalog/security.yaml` is policy (denied binaries / flags), not a tool list.

**SIFT gap closed this pass:** WxTCmd was on Windows + knowledge but missing from `catalog/zimmerman.yaml`. It is now cataloged on SIFT too.

---

## Knowledge cards that are not execute-catalog tools

These teach the examiner; they are **not** in `_WIN_CATALOG` or SIFT `catalog/*.yaml` `tools:`.

| Card | Why it exists | Lane |
|------|----------------|------|
| Hindsight | Browser alternative; Windows path is SQLECmd | not-wired (alias → sqlecmd for completeness) |
| maldump | Defender quarantine | on-demand if binary added later; YAML lists it honestly |
| Photorec, CyLR, LogParser, MemProcFS, AppCompat Processor, 1768_cobalt | Reference / predecessor coverage | not-wired |
| MCP cards (`search`, `check_file`, …) | Nexus MCP, not host binaries | N/A |

Do not add these to the mandatory lane.

---

## Artifact YAML map (Windows)

Presence comes from `locations` globbed against the image root (`artifact_map.py`). Completeness: `SCHEDULED` / `PRESENT_NO_PARSER` / `ABSENT`.

| Artifact slug | related_tools (accurate) | Lane coverage |
|---------------|--------------------------|---------------|
| prefetch | PECmd | mandatory PECmd |
| amcache | AmcacheParser, RECmd | mandatory AmcacheParser |
| shimcache | AppCompatCacheParser, RECmd | mandatory AppCompatCacheParser |
| srum | SrumECmd | mandatory SrumECmd |
| mft | MFTECmd, mactime, fls | mandatory MFTECmd + SIFT mactime |
| usn_journal | MFTECmd | mandatory MFTECmd `-f $J` if present |
| recycle_bin | RBCmd | mandatory RBCmd |
| lnk_files | LECmd | mandatory per-user LECmd |
| jump_lists | JLECmd | mandatory per-user JLECmd |
| shellbags | SBECmd | mandatory per-user SBECmd |
| activitiescache | WxTCmd, SQLECmd | mandatory WxTCmd |
| browser_history | SQLECmd, Hindsight | mandatory SQLECmd |
| userassist, bam, mountpoints2, user_activity_mru | RECmd (+ RegRipper on mountpoints2) | mandatory RECmd NTUSER |
| registry_run_keys, registry_services | RECmd, autorunsc | mandatory RECmd; autorunsc live-only |
| event_logs_* (11 channels) | EvtxECmd, Hayabusa, Suzaku, Chainsaw | mandatory Hayabusa + EvtxECmd; Suzaku/Chainsaw extra |
| hayabusa_alerts | Hayabusa | covered by Hayabusa job |
| scheduled_tasks | EvtxECmd, Hayabusa, RECmd | EVTX + SOFTWARE hive; XML under `Tasks\` is not a separate parser |
| wmi_persistence | RECmd, autorunsc, EvtxECmd, Hayabusa | same |
| ntfs_logfile | LogFileParser | cataloged; not auto-run until CLI verified |
| ntfs_i30 | MFTECmd | MFTECmd `-f` on an **extracted** `$I30` file only |
| setupapi, powershell_transcripts, psreadline | — (plain text) | **copy** into extractions; no parser |
| wer | strings, YARA | on-demand via `sample_files` (minidumps are file-targeted) |
| digital_signatures | sigcheck, exiftool | on-demand (named file) |
| defender_quarantine | EvtxECmd, Hayabusa, maldump | EVTX scheduled; maldump still not-wired |
| bits_jobs | BitsParser, esedbexport | BitsParser if `qmgr.db` present **and** installed |
| ual | KStrike, esedbexport | KStrike if SUM `*.mdb` present **and** installed (Server) |
| volume_shadow_copies | vshadowinfo, vshadowmount, vssadmin | on-demand SIFT; vssadmin live |
| volatility_memory | Volatility3, vol | SIFT vol if memory file present |
| rdp_bitmap_cache | bmc-tools | bmc-tools if Cache tiles present **and** installed |
| thumbcache | thumbcache_viewer_cmd | cataloged; not auto-run until CLI verified |

Linux artifacts (`auth_log`, `syslog`, `bash_history`, …) map to grep/last/journalctl — SIFT utilities, not the Windows EVTX lane. `auth_log` must not list EvtxECmd/Hayabusa.

---

## Gaps — what they were, how we address them

Cited from `Courses/sans-defense` (FOR500/FOR508). We still do **not** reimplement parsers. We orchestrate the real tool, skip when the artifact is absent, and keep dangerous/huge jobs opt-in.

### 1. Thumbcache Viewer

Explorer writes `thumbcache_*.db` under each user’s `AppData\Local\Microsoft\Windows\Explorer`. FOR500 uses these to show that a user *saw* a file in Explorer (a thumbnail), which is weaker than Prefetch (execution) but stronger than “the file existed somewhere.” The GUI Thumbcache Viewer is not automatable. **Address:** catalog + fetch `thumbcache_viewer_cmd`. We do **not** auto-run it until the CLI is verified on a fetched binary (`quick_start` in the knowledge card is still unconfirmed). Design-mode extra or examiner `run_windows_command` after fetch.

### 2. bmc-tools (RDP bitmap cache)

`*.bmc` / `*.bin` under Terminal Server Client\Cache hold 64×64 tiles of what an RDP *client* displayed. They are not full screenshots and have no per-tile timestamps. **Address:** ANSSI `bmc-tools.py` is now in the Windows and SIFT catalogs. The lane runs it per user when those cache files exist **and** `bmc-tools.py` is installed. One SKIP if the tiles are present but the script is not fetched. Pair with RDP EVTX for when/where.

### 3. KStrike / UAL (not KAPE)

User Access Logging is a **Server 2012+** ESE database (`C:\Windows\System32\LogFiles\SUM\*.mdb`). It records client IPs and roles with coarse first/last seen — not session detail. It does not exist on Windows 10/11 clients (no SKIP spam — nothing to schedule). KAPE can *collect* the files; it does not parse UAL. SrumECmd is a different ESE (SRUM). **Address:** `KStrike.py` when `*.mdb` is present **and** installed. SIFT `esedbexport` is the fallback if you only have libesedb.

### 4. bitsadmin on a dead image

`bitsadmin` talks to the live BITS service. It is **MCP-denied** (same class as cmd/powershell). On an image the queue is `qmgr.db` (Win10+) or `qmgr0.dat`/`qmgr1.dat` (legacy) — ESE, not a tool you “run against the OS.” **Address:** Mandiant `BitsParser.py` when those files exist **and** the script is installed. Do not use bitsadmin. Completed jobs may already be gone from the queue.

### 5. INDXParse.py / $I30 slack

Every NTFS directory has an `$I30` index. Slack in that index can retain deleted names. INDXParse.py is one parser; **MFTECmd already parses `$I30` files**. On a mounted volume `$I30` is an *attribute*, not a file, so a recursive search would be wrong and slow. **Address:** if KAPE/extraction dropped an `$I30` file at the volume root or `FileSystem\$I30`, the lane runs `MFTECmd -f`. Otherwise SKIP with that reason. `$FILE_NAME` timestamps in the `$MFT` parse still cover the common timestomp check.

### 6. NTFS Log Tracker / $LogFile

`$LogFile` is a ~64MB circular NTFS transaction journal (metadata only, hours–days). NTFS Log Tracker is a GUI. MFTECmd does **not** replace it. **Address:** `LogFileParser` (jschicht) is in the Windows catalog and fetch script. We do **not** auto-run it — published argv varies by release. Examiner runs it after fetch once flags are confirmed. Live NTFS has no `$LogFile` file; stay silent.

### 7. log2timeline / psort (Plaso)

A full-tree Plaso store is multi-GB. This lab disk cannot hold that as a default. **Address:** not scheduled unless `NEXUS_SIFT_PLASO=1`. No SKIP row when unset. Default super-timeline remains MFTECmd `--body` → SIFT `mactime`.

### 8. Live acquisition (winpmem, dumpit, handle, procdump, Moneta, hollows_hunter, Get-InjectedThreadEx, autorunsc)

These need a **running** OS. Running winpmem against a mounted image is meaningless; running it against the examiner workstation would be an incident. **Address:** image triage does **not** schedule them (no SKIP wall). `NEXUS_LIVE_RESPONSE=1` enables autorunsc + handle + Get-InjectedThreadEx. Physical memory still requires a second gate: `NEXUS_LIVE_ACQUIRE_MEMORY=1`. Design-mode extras may still call the others on a live host.

### 9. capa / yara / densityscout

These need a **named file** (and yara needs a rules path). Scanning `C:\Windows` would be a redesign and a multi-hour job. **Address:** intake field `sample_files` (or `NEXUS_SAMPLE_FILES`) schedules capa + densityscout on up to 10 paths. YARA only if `NEXUS_YARA_RULES` is set. WER minidumps stay in this bucket — pass the dump path as a sample.

### Still not a host parser (honest leftovers)

| Item | Why it stays out of the lane |
|------|------------------------------|
| streams.exe / osslsigncode | ADS / Authenticode — MFTECmd lists streams; sigcheck is on-demand for a named file |
| wmi_persistence.py | WMI subscriptions are already RECmd + WMI EVTX |
| maldump | Defender quarantine blobs; EVTX still runs; binary not fetched |
| Suzaku + Chainsaw + Hayabusa all three | All cataloged; lane keeps Hayabusa + EvtxECmd so we do not triple-parse EVTX |
| NTFS Log Tracker GUI / Thumbcache Viewer GUI | CLI counterparts are cataloged; not auto-run until argv is verified |

---

## What stayed the same (design)

- MCP orchestrates host tools; it does not reimplement detection.
- HMAC audit on every `run_*` call.
- Findings stay DRAFT until examiner HITL.
- Presence-driven host triage. Unix utils and live-acq stay catalog-on-demand.
- Predecessors (read-only): we execute a deterministic map instead of “LLM picks parsers.”
