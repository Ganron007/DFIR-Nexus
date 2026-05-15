# CLI Reference

The complete `nexus` command surface. 19 top-level commands. This
page is the single source of truth — the README and
[guide.md](guide.md) link here rather than duplicating.

For a workflow walkthrough see [guide.md](guide.md). For the
provenance and security model see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Common workflows

### First-time setup

```bash
nexus config --examiner "your-name"
nexus config --setup-password            # required for approve / reject
nexus init                                # connectivity + LLM client config
```

### Daily examiner workflow

```bash
nexus case init "Ransomware-2026-001"
nexus evidence register /evidence/ --description "Triage collection"

# ... AI-driven investigation via MCP tools from your LLM client ...

nexus review --findings                   # see DRAFT items
nexus approve --interactive               # password prompt; walk DRAFT items
nexus report --full --save report.json
```

---

## Server

| Command | Purpose |
|---------|---------|
| `nexus serve` | Stdio MCP server — LLM client spawns nexus |
| `nexus serve --http --port 4508` | HTTP server with Examiner Portal at `/portal` |
| `nexus serve --http --host 0.0.0.0 --port 4508` | Bind all interfaces (LAN / multi-host) |

## Configuration

| Command | Purpose |
|---------|---------|
| `nexus config --examiner "Name"` | Set examiner identity |
| `nexus config --setup-password` | Set or rotate approval password (PBKDF2; re-signs the HMAC ledger on rotation) |
| `nexus config --show` | Print current config |

## Case lifecycle

| Command | Purpose |
|---------|---------|
| `nexus case init "Name"` | Create new case (auto ID) |
| `nexus case init "Name" --case-id CASE-001` | Create with explicit ID |
| `nexus case activate CASE-001` | Make this the active case |
| `nexus case close CASE-001` | Mark closed |
| `nexus case reopen CASE-001` | Re-open a closed case |
| `nexus case list` | List all cases |

## Evidence

| Command | Purpose |
|---------|---------|
| `nexus evidence register /path --description "..."` | Register + SHA-256 hash |
| `nexus evidence list` | List registered evidence |
| `nexus evidence verify` | Re-hash and check integrity |
| `nexus evidence lock` | `chmod 444` — prevent tampering |
| `nexus evidence unlock` | `chmod 644` — restore writable |

## Approval (human only — password required)

| Command | Purpose |
|---------|---------|
| `nexus approve F-001 F-002` | Approve specific IDs |
| `nexus approve --interactive` | Walk every DRAFT — prompt approve / reject / skip |
| `nexus approve F-001 --note "verified vs MFT"` | Approve with examiner note |
| `nexus reject F-003 --reason "Insufficient evidence"` | Reject with rationale |
| `nexus reject --interactive` | Walk DRAFTs in reject mode |

A 15-minute lockout fires after 3 failed password attempts. Every
approval writes an HMAC-signed entry to `~/.nexus/verification/`.

## Review

| Command | Purpose |
|---------|---------|
| `nexus review --findings [--detail]` | Show findings |
| `nexus review --timeline` | Show timeline events |
| `nexus review --evidence` | Show registered evidence |
| `nexus review --iocs` | Show extracted / recorded IOCs |
| `nexus review --audit --limit 100` | Tail audit log |
| `nexus review --todos [--open]` | Show TODOs |

## Reports

| Command | Purpose |
|---------|---------|
| `nexus report --full [--save out.json]` | Full report |
| `nexus report --executive-summary` | Short, leadership-facing |
| `nexus report --timeline --from 2026-01-01 --to 2026-01-31` | Date-filtered timeline |
| `nexus report --ioc` | IOC-only |
| `nexus report --findings F-001,F-002` | Subset by ID |
| `nexus report --status-brief` | One-paragraph status |

Reports reconcile approved findings against the HMAC ledger and
surface `verification_alerts` for any `APPROVED_WITHOUT_LEDGER` or
`LEDGER_WITHOUT_APPROVAL` mismatch.

## Bundles (export / merge)

Both commands take the bundle path as a **positional argument**, not
`--file`.

| Command | Purpose |
|---------|---------|
| `nexus export bundle.json` | Export case bundle |
| `nexus export bundle.json --since 2026-01-01` | Delta export |
| `nexus export bundle.tar --encrypt` | PBKDF2 + Fernet (requires `cryptography`) |
| `nexus export bundle.tar --encrypt --passphrase "..."` | Pass passphrase on CLI |
| `nexus merge bundle.json` | Import bundle |
| `nexus merge bundle.tar --decrypt` | Decrypt on import |

## Backup

| Command | Purpose |
|---------|---------|
| `nexus backup /mnt/backup/` | Snapshot the active case |
| `nexus restore /path/to/backup` | Restore from a snapshot |

## Service management (per-name)

Each service is tracked by its own PID file so you can bounce one
backend without taking the others down. Custom services live in
`~/.nexus/services.json`.

| Command | Purpose |
|---------|---------|
| `nexus service status [<name>]` | Status of all or one service |
| `nexus service start <name>` | Start named service in background |
| `nexus service start nexus --http --port 4508` | Start `nexus` in HTTP mode |
| `nexus service stop <name>` | Stop |
| `nexus service restart <name> [--http --port N]` | Restart |

## Audit

| Command | Purpose |
|---------|---------|
| `nexus audit log --limit 50` | Tail audit JSONL |
| `nexus audit log --tool run_command` | Filter by tool name |
| `nexus audit summary` | Counts by tool / examiner / time |

## TODOs

| Command | Purpose |
|---------|---------|
| `nexus todo add "desc" --priority high` | Add |
| `nexus todo list [--open]` | List |
| `nexus todo complete TODO-001` | Complete |

## Quickstart / setup

| Command | Purpose |
|---------|---------|
| `nexus init` | One-shot quickstart — env check, baseline status, demo LLM config snippet |
| `nexus setup test` | Connectivity test (RAG, OpenSearch, OpenCTI, triage DB) |
| `nexus setup client` | Interactive LLM client config wizard |
| `nexus setup client --sift 10.0.0.2:4508 --windows 10.0.0.5:4508` | Multi-server config |
| `nexus setup client --uninstall` | Remove generated config |

## Utilities

| Command | Purpose |
|---------|---------|
| `nexus portal` | Open Examiner Portal in browser |
| `nexus update [--check] [--no-restart]` | Git pull + pip install -e . |
| `nexus exec --purpose "..." <cmd>` | Audit-logged command execution |

---

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `NEXUS_EXAMINER` | OS username | Examiner identity |
| `NEXUS_CASE_DIR` | `~/.nexus/active_case` | Active case path |
| `NEXUS_AUDIT_DIR` | `<case_dir>/audit` | Override audit log root |
| `NEXUS_COMMAND_TIMEOUT` | `600` | Tool execution timeout (s) |
| `NEXUS_GATEWAY_HOST` | `127.0.0.1` | HTTP bind address |
| `NEXUS_GATEWAY_PORT` | `4508` | HTTP port |
| `NEXUS_BEARER_TOKEN` | `""` | HTTP auth token (required for any non-loopback HTTP deploy) |
| `NEXUS_OTEL_ENABLED` | `false` | Emit OpenTelemetry traces |
| `OPENCTI_URL` / `OPENCTI_TOKEN` | — | OpenCTI server |
| `OPENSEARCH_HOST` / `OPENSEARCH_PORT` | `127.0.0.1` / `9200` | OpenSearch backend |
