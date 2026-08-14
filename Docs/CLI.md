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
nexus case query INC-... --backend auto   # Rebuild N4 pack (auto|csv|es)
nexus case detections INC-... --finding-ids F-009,F-010   # D1 drafts for SIEM (not N5)
```

Portal `/portal/steer` picks a case, saves intake, registers evidence paths, and re-runs the N4 pack.

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
nexus config --setup-password             # Set approval password
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
nexus pipeline --resume                                       # after nexus approve (HITL)
```

Modes: `tools` | `coverage` | `design` | `interpret` (aliases: `debug`→coverage, `react`/`hunt`→design).
Also `NEXUS_PIPELINE_MODE`. Contract: [TOOL-EVIDENCE-MAP.md](cases/TOOL-EVIDENCE-MAP.md).

`interpret` reuses an existing tool-run case (no re-parse). Until `nexus pipeline`
gains `--from-case`, use `python scripts/rocba_agentic_pipeline.py --from-case <id>`.

Requires: `pip install dfir-nexus[pipeline]` and LLM env for coverage/design/interpret
(`NEXUS_LLM_MODEL` / `NEXUS_LLM_BASE_URL`). `tools` needs no LLM.

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
