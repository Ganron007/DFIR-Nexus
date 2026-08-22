# DFIR-Nexus CLI Reference

> Full command reference. See [guide.md](guide.md) for workflow context.

---

## Case Management

```bash
nexus case init "Case Name"               # Create a new case (auto-activates)
nexus case init "Ransomware" --case-id CUSTOM-001  # With custom ID

nexus case activate CASE-XXXXXXXX         # Switch active case
nexus case list                           # List all cases
nexus case close                          # Close active case (or --case-id)
nexus case reopen                         # Reopen closed case
nexus case migrate                        # Import legacy flat-JSON cases into SQLite
nexus case migrate --dry-run              # Preview migration

nexus case intake --question "..." --window 2020-11-14 --extras chrome_profiles
nexus case index INC-...                  # N3: index this case's extractions (needs NEXUS_ES_URL)
nexus case query INC-... --needles sdelete,.pst --backend auto
nexus case detections INC-... --finding-ids F-009,F-010   # D1 drafts for SIEM (not N5)
```

Portal **Steer** = intake + register. Portal **Query** = N4 hit table
(processed CSVs / case index, not Evidence-files). Empty hits = INSUFFICIENT.

Mental model: [NEXUS-MODE.md](NEXUS-MODE.md).

## Stage 0 — live IR collect

This is a **live run with authentication**, not a dump-for-Nexus script.
It is a product highlight: the same command produces a case pack against
**current Windows 11** and **modern Linux** (main kernels/distros).

`nexus collect import` is only for an IR tree you already have.

**`--profile disk` (ship spine — default):** collectors that must work on the current OS.

- **Windows:** Sysinternals, PersistenceSniper, wevtutil EVTX, KAPE `!SANS_Triage`/`!EZParser`, live Velociraptor `CADRE.Hunts.IRTriage`.
- **Linux:** POSIX volatile snapshot, journalctl (30 days) + ausearch, UAC `-p ir_triage` (SANS-style live response; not UAC `full`), live Velociraptor `CADRE.Hunts.LinuxIRTriage`.

**`--profile full`:** every FOSS collector we can wire, including overlap
(Kansa, Hayabusa, Suzaku, Chainsaw, DFIR-ORC, WinPmem/AVML, UAC `full`).
Missing or broken tools **skip with a reason**. Unmaintained binaries are not
deleted from `full`; we fix them and re-run later. `--profile volatile` is
process/net/log only (no KAPE/UAC/ORC).

```bash
nexus collect tools                       # every collector binary + VR live status
nexus collect plan --os windows --host <windows-host> --user analyst --identity ~/.ssh/id
nexus collect run  --os windows --host <windows-host> --user analyst --identity ~/.ssh/id
nexus collect run  --os linux   --host <linux-host> --user vagrant --identity ~/.ssh/id --sudo
nexus collect run  --os windows --host localhost --no-probe --profile full
nexus collect import D:\kape-out --os windows --hostname rd01 --case INC-...
```

`--only kansa,hayabusa,dfir_orc` or `--profile full` pulls optional collectors.
`--kape-module none` acquires the triage image only. `--kape-remote-path` uses KAPE already installed on the target. `--no-memory` skips WinPmem/AVML (DumpIt is not used — commercial). `--vr-client-id` if hostname match fails. Password SSH/WinRM: `NEXUS_COLLECT_PASSWORD` (never `--password`). Optional extras: `pip install dfir-nexus[collect]` (paramiko / pywinrm).

### Live Velociraptor (examiner `.env` — required for hunts)

This is **your** host, not the Velociraptor VM install. Full table: [SETUP.md §2.6](SETUP.md#26-live-velociraptor-hunts-every-examiner-host).

1. Copy `.env.example` → `.env` (gitignored).
2. Set `NEXUS_VR_MCP_URL=http://<vr-host>:8002` and `NEXUS_VR_MCP_API_KEY` from the VR server MCP env (`VR_MCP_API_KEY`, often `/etc/velociraptor/mcp.env`).
3. Do not set `NEXUS_VR_USE_MOCK=1`. Do not point `NEXUS_VR_ENDPOINT` at gRPC `:8001`.
4. Check (no harvest): `nexus collect tools` → `velociraptor_live: True`.
5. `nexus collect run` harvests. Only after the operator says freeze.
   Stage 0 VR calls `CADRE.Hunts.IRTriage` (Windows) or `CADRE.Hunts.LinuxIRTriage` (Linux) after `Generic.Client.Info`. Heavier `CADRE.Hunts.*` packs stay on the VR server for a later hunt. KAPE/UAC on SSH targets do file triage.

Missing binaries are **skipped with a reason**, not omitted silently. Then: `nexus case init "IR host"` → `nexus evidence register <pack>`.

## Evidence

```bash
nexus evidence register /path/to/file     # Register file with SHA-256
nexus evidence register file.dmp -d "Memory dump from DC01"
nexus evidence list                       # List registered evidence
nexus evidence verify                     # Re-hash all evidence and check integrity
nexus evidence lock                       # Make evidence files read-only
nexus evidence unlock                     # Restore write permissions
```

## Findings & Approval

```bash
nexus approve --interactive               # Walk through all DRAFT findings
nexus approve F-analyst-001               # Approve specific finding
nexus approve F-001 F-002 --note "Verified via memory analysis"

nexus reject F-analyst-003 --reason "False positive"
nexus reject --interactive                # Interactive rejection mode
```

## Review

```bash
nexus review findings                     # List all findings
nexus review findings --status draft      # Filter by status
nexus review findings --detail            # Show descriptions + MITRE techniques

nexus review timeline                     # Timeline events
nexus review timeline --type malware      # Filter by event type
nexus review timeline --start 2026-01-01  # Date range

nexus review iocs                         # List extracted IOCs

nexus review audit                        # View audit trail
nexus review audit --limit 50             # Limit entries

nexus review verify                       # Verify HMAC audit chain integrity

nexus review todos                        # List TODOs
nexus review todos --open                 # Open only
```

## Report Generation

```bash
nexus report generate                     # Generate full report (stdout)
nexus report generate -s report.md        # Save to file
nexus report generate --case CASE-ID      # Specific case
nexus report generate --from 2026-01-01   # Date range filter (start)
nexus report generate --to 2026-06-01     # Date range filter (end)
```

## TODO Management

```bash
nexus todo list                           # List all TODOs
nexus todo add "Analyze memory dump"      # Create TODO
nexus todo complete TODO-analyst-001      # Mark complete
```

## Configuration

```bash
nexus config --examiner "alice"           # Set examiner identity
nexus config --setup-password             # Set approval password (new identity)
# Forgot / never set HMAC password (PowerShell — no hidden prompt):
#   $env:NEXUS_APPROVAL_PASSWORD = '<new password>'
#   nexus config --examiner e2e_host --setup-password --replace
nexus config --show                       # Show current config
# Subcommand form also works: nexus config set --examiner "alice" / nexus config show
```

## Onboarding (quickstart)

```bash
nexus init                                # Environment check + client config
nexus init "Case Name" --evidence /path/to/disk.raw   # Also creates the case
nexus init "Case" --evidence a.evtx --evidence b.pcap # Repeatable evidence
```

Creates the case in the SQLite stack, registers + SHA-256 hashes each evidence
file, checks triage baselines / RAG index, and writes `nexus-config.json` for
your LLM client.

## Server & Services

```bash
nexus serve                               # Start MCP server (stdio mode)
nexus serve --http                        # Start HTTP server (port 4508)
nexus serve --http --port 8080            # Custom port
nexus serve --http --host 0.0.0.0        # Bind to all interfaces

nexus portal                              # Open Examiner Portal in browser

nexus service status                      # Check service status
nexus service start                       # Start background service
nexus service stop                        # Stop background service
nexus service restart                     # Restart background service
```

## Pipeline (`nexus pipeline`)

```bash
nexus pipeline --mode tools --case /path/to/windows/image     # parsers only → TOOL-RUN.md
nexus pipeline --mode coverage --case /path/to/windows/image  # lane + LLM interpret → DRAFT
nexus pipeline --mode design --case /path/to/windows/image    # lane + ReAct extras + interpret
nexus pipeline --mode interpret --from-case INC-...           # reuse ledger, no re-parse
nexus pipeline --resume                                       # after nexus approve (HITL)
```

Modes: `tools` | `coverage` | `design` | `interpret` (aliases: `debug`→coverage, `react`/`hunt`→design).
Also `NEXUS_PIPELINE_MODE`. Contract: [TOOL-EVIDENCE-MAP.md](cases/TOOL-EVIDENCE-MAP.md)
and [NEXUS-MODE.md](NEXUS-MODE.md).

Requires: `pip install dfir-nexus[pipeline]` and LLM env for coverage/design/interpret
(`NEXUS_LLM_MODEL` / `NEXUS_LLM_BASE_URL`). `tools` needs no LLM.

## Ingest & Doctor

```bash
nexus ingest conn.log                     # auto-detect format
nexus ingest conn.log --source zeek       # skip sniffing
nexus ingest logs/ --recursive --limit 50
nexus ingest conn.log --case INC-20260815 --source zeek   # I3 merge; prints audit_id

nexus doctor                              # extras, catalog, indexes, optional keys
nexus doctor --health-url http://127.0.0.1:4508   # probe serve /health
nexus doctor --health-url skip            # skip the probe
```

`/health` not listening is an optional skip (start `nexus serve --http`), not a golden-path fail.
Collect inventory (KAPE/Kansa/DFIR-ORC/UAC/VR skip) is printed as info — missing KAPE or ORC is not a golden-path fail.

---

## Setup & Client Wiring

```bash
nexus setup test                          # Test connectivity
nexus setup client                        # Interactive LLM config wizard
nexus setup client --sift 10.0.0.2:4508 --windows 10.0.0.5:4508
nexus setup client --client claude-code   # Specific client type
nexus setup client --uninstall            # Remove config
```

## Audit & Execution

```bash
nexus exec --purpose "YARA scan" yara rules.yar /evidence/
nexus audit log                           # View audit trail
nexus audit summary                       # Audit summary
```

## Backup & Sync

```bash
nexus export bundle.json                  # Export case bundle
nexus merge bundle.json                   # Import/merge case bundle
nexus backup /path/to/backup              # Full case backup
nexus restore /path/to/backup             # Restore from backup
```

## Maintenance

```bash
nexus update                              # Pull latest code + rebuild
nexus update --check                      # Check for updates only
nexus update --no-restart                 # Update without restarting service
```
