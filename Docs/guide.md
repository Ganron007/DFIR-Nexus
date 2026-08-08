# DFIR-Nexus — Complete User Guide

> **What:** DFIR-Nexus is a unified DFIR investigation platform. It ingests forensic data from any source, correlates findings across tools, enforces a human-in-the-loop approval workflow with cryptographic audit, and exports reports in multiple formats. Every action is recorded in an HMAC audit chain so you can prove exactly what happened.

> **Who:** Built for DFIR examiners — incident responders, forensic analysts, SOC leads, and threat hunters. You run commands (via MCP tools, CLI, or the Examiner Portal), the platform records every action, and findings are staged as DRAFT until a human approves them.

> **How:** You interact with DFIR-Nexus through an LLM client (Claude Code, Cursor, etc.), the `nexus` CLI, or the browser-based Examiner Portal. Behind the scenes it runs MCP servers that wrap your forensic tools (SIFT, Windows, Velociraptor), a RAG knowledge base, triage validation databases, and a SQLite case stack with cryptographic audit.

---

## 1. What DFIR-Nexus Accomplishes

DFIR-Nexus replaces the ad-hoc "tool A → tool B → spreadsheet → report" workflow with a single audit-backed pipeline:

```
Run forensic tools → Evidence ingested → Findings recorded (DRAFT)
→ Human reviews & approves → Report generated → Audit chain verifiable
```

**What you get:**
- **Findings** — structured observations with MITRE ATT&CK technique mapping, severity, confidence, and provenance links back to the raw evidence
- **Reports** — Markdown, HTML, JSON, STIX 2.0/2.1, CSV, ZIP, DOCX
- **Audit Trail** — every action (tool run, finding record, approval) is HMAC-chained. Tamper-evident and independently verifiable
- **Evidence Registry** — every file registered has its SHA-256 recorded and can be verified at any time
- **Timeline** — all events in chronological order, filterable by type and date range
- **IOC Database** — auto-extracted IOCs (IPs, hashes, URLs, domains, registry keys) from findings and evidence
- **MITRE ATT&CK Coverage** — see which techniques you have detection rules for, where the gaps are, and which threat actors match observed techniques
- **RAG Knowledge Search** — semantic search over ~22K curated forensic knowledge records (downloaded on first use; ~600 MB). Sources: SANS posters, MITRE ATT&CK, Sigma rules, LOLBAS, KAPE targets, Velociraptor artifacts.
- **Triage Validation** — validate processes/files/services against Windows baselines (legitimate vs suspicious vs LOLBin)

---

## 2. Installation

See **[SETUP.md](SETUP.md)** for the full installation guide. Quickstart:

**Windows (PowerShell 7+ as Admin):**
```powershell
.\setup-windows.ps1
```

**Linux / macOS:**
```bash
./setup-linux.sh        # or ./setup-macos.sh
```

**Manual:**
```bash
pip install dfir-nexus[all]
```

After install, configure your identity and credentials:
```bash
nexus config --examiner "your-name"
nexus config --setup-password
```

---

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                  LLM Client                         │
│          (Claude Code / Cursor / Cline)             │
└────────────┬────────────────────┬───────────────────┘
             │ MCP (stdio/HTTP)   │
             ▼                    ▼
┌──────────────────────┐  ┌──────────────────────┐
│  DFIR-Nexus (core)   │  │  Gateway              │
│  - Case stack        │  │  - Multi-backend MCP  │
│  - Audit chain       │  │  - Tool aggregation   │
│  - Approval workflow │  │  - Rate limiting       │
│  - SQLite persistence│  └──────────────────────┘
└──────────────────────┘
             │
    ┌────────┼────────┐
    ▼        ▼        ▼
┌───────┐ ┌──────┐ ┌──────────┐
│ SIFT  │ │ Win  │ │Velocirap │
│ linux │ │ Win  │ │  tor VR  │
└───────┘ └──────┘ └──────────┘
```

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the trust model, security boundaries, and MCP tool inventory.

---

## 4. Step-by-Step Investigation Workflow

### Step 1: Create a Case

Every investigation starts with a case:

```bash
nexus case init "Ransomware Incident XYZ"
```

Or via MCP tool:
```
case_init("Ransomware Incident XYZ")
```

This creates a case with a unique ID (`CASE-XXXXXXXX`) and sets it as active. The case stores all findings, evidence, timeline events, TODOs, and audit entries.

### Step 2: Register Evidence

Register the files you'll analyze — disk images, memory dumps, PCAPs, logs, malware samples:

```bash
nexus evidence register /path/to/memory.dmp
nexus evidence register /path/to/capture.pcap --description "Network capture from DC01"
```

DFIR-Nexus computes SHA-256 for every file and stores it in the evidence registry. You can verify integrity at any time:

```bash
nexus evidence list       # show all registered files
nexus evidence verify     # re-hash and check for tampering
```

### Step 3: Run Forensic Tools

DFIR-Nexus wraps your existing forensic tools as MCP tools. Every tool run is audited and returns an `audit_id`. **This is the key concept — every action gets a unique audit_id that findings must reference:**

**Tools available (110 total across categories):**

| Category | Tools | When to use |
|----------|-------|-------------|
| **Triage** | `triage_check_file`, `triage_check_process`, `triage_check_service`, `triage_check_hash`, `triage_check_autorun`, `triage_check_task`, `triage_check_lolbin`, `triage_analyze_path`, `triage_get_health`, `triage_status`, `triage_download` | Quick triage — validate a file/process/hash against Windows baselines. Use early in investigation to separate legitimate from suspicious. |
| **SIFT (Linux)** | `run_command`, `list_available_tools`, `get_tool_help`, `check_tools`, `suggest_tools`, `get_environment`, `reset_counters` | Deep-dive analysis on a Linux/SIFT VM. 60+ cataloged forensic tools (Volatility, Plaso, Zeek, Sleuth Kit, YARA, etc.) |
| **Windows** | `run_windows_command`, `scan_tools`, `list_windows_tools`, `list_missing_windows_tools`, `check_windows_tools`, `get_windows_tool_help`, `suggest_windows_tools`, `get_share_info`, `list_kape_targets`, `batch_scan` | Run Zimmerman tools, KAPE, Sysinternals directly. 31 cataloged tools across 7 categories. |
| **Case** | `case_init`, `case_activate`, `case_list`, `case_status`, `evidence_register`, `evidence_list`, `evidence_verify`, `export_bundle`, `import_bundle`, `audit_summary`, `record_action`, `log_reasoning`, `log_external_action` | Case lifecycle management. |
| **Forensic** | `record_finding`, `record_timeline_event`, `get_findings`, `get_timeline`, `add_todo`, `list_todos`, `update_todo`, `complete_todo` + 14 discipline tools | Investigation records and forensic discipline enforcement. |
| **Report** | `generate_report`, `set_case_metadata`, `get_case_metadata`, `list_profiles`, `save_report`, `list_reports` | Report generation in 6 profiles (full, executive, timeline, ioc, findings, status). |
| **Analysis & correlation** | `ingest_auto`, `analyze_gaps`, `deobfuscate_command`, `check_kev`, `predict_techniques`, `create_playbook`, `build_asset_graph`, `anonymize_text`, `deanonymize_text`, `export_stix_bundle`, `export_navigator_layer`, `export_blocklist`, `translate_query`, `suggest_fleet_hunts`, `check_nsrl`, `get_knowledge_graph_stats`, `get_dynamic_tables`, `list_query_templates`, `generate_sigma_rule` | Advanced analysis — auto-format detection, beacon/C2, gap analysis, deobfuscation, KEV, adversary emulation, playbooks, correlation, evidence graph, STIX/Navigator export, NL query. |
| **OpenSearch** | `idx_search`, `idx_aggregate`, `idx_timeline`, `idx_status`, `idx_case_summary`, `idx_enrich_triage`, `idx_enrich_intel`, `idx_ingest` | Evidence indexing and search via OpenSearch (optional). |
| **OpenCTI** | `search_threat_intel`, `search_entity`, `lookup_ioc`, `get_entity`, `get_relationships`, `get_recent_indicators`, `search_reports`, `search_threat_actor`, `search_malware`, `search_mitre_technique` | Threat intelligence via OpenCTI (optional). |
| **RAG** | `forensic_rag_search`, `forensic_rag_list_sources`, `forensic_rag_status`, `forensic_rag_download`, `forensic_rag_rebuild` | Semantic search over ~22K forensic records (downloaded on first use). |
| **TI** | `ti_lookup`, `ti_fanout`, `ti_list_providers` | Threat intelligence enrichment: abuse.ch, MISP, OTX, Shodan, VT, AbuseIPDB, CrowdStrike. |
| **Velociraptor** | `vr_list_clients`, `vr_list_hunts`, `vr_run_hunt`, `vr_collect_artifact`, `vr_suggest_hunts`, `vql_query` | Remote live-response collection. 10 pre-built hunts. |

**Example workflow:**
```
Tool: triage_check_file → confirms the binary is not in Windows baseline
Tool: sift_yara_scan     → finds Cobalt Strike signature
Tool: vr_run_hunt        → collects process tree from compromised host
Tool: ingest_from_source  → parses Suricata/Zeek pcaps into artifacts
Tool: ti_lookup          → enriches IOCs via ThreatFox
```

### Step 4: Record Findings

Every observation becomes a **finding** — a structured record with title, description, severity, MITRE technique IDs, and **audit_id provenance links** back to the tool runs that produced the evidence:

```
finding = record_finding(
    title="Cobalt Strike Beacon on DC01",
    severity="CRITICAL",
    technique_ids=["T1003.001", "T1059.001"],
    observation="Cobalt Strike beaconed to 45.33.32.156 every 60s",
    interpretation="Attacker established persistence via scheduled task executing beacon DLL",
    mitre_ids=["T1053.005"],
    audit_ids=["audit-abc123", "audit-def456"],  # MUST reference real audit_ids
    host="dc01.cadre.local",
    artifacts=[
        {"type": "memory_dump", "value": "lsass.dmp", "audit_id": "audit-abc123"},
        {"type": "network_capture", "value": "dc01_traffic.pcap", "audit_id": "audit-def456"},
    ]
)
```

**Critical rule:** You CANNOT invent audit_ids. `record_finding` verifies every audit_id exists in the case's audit log. If you fabricate one, the finding is REJECTED with a provenance error. This is by design — it enforces evidence-backed findings.

### Step 5: Review & Approve

All findings start as **DRAFT**. A human must review and approve them (this is the HITL — Human-In-The-Loop boundary). The LLM cannot approve findings:

**Via CLI (interactive):**
```bash
nexus approve --interactive
```
Walks you through every DRAFT finding. You see title, severity, observation, interpretation, linked artifacts. Choose [a]pprove, [r]eject, or [s]kip.

**Via CLI (batch):**
```bash
nexus approve F-analyst-001 F-analyst-002 --note "Confirmed via memory analysis"
nexus reject F-analyst-003 --reason "False positive — legitimate admin tool"
```

**Via Examiner Portal:**
Open `http://127.0.0.1:4508/portal` in your browser. Review and approve/reject findings with a GUI.

**What happens on approve:**
- The finding is PBKDF2-HMAC signed using your case approval password.
- An audit entry is recorded (`finding_approved`).
- The finding moves from DRAFT → APPROVED.
- The HMAC signature is independently verifiable later.

**What happens on reject:**
- The finding moves from DRAFT → REJECTED.
- A rejection reason is recorded.
- The finding is excluded from reports.

**Password lockout:** 3 failed attempts lock the finding for 15 minutes. This prevents brute-forcing the approval password.

### Step 6: Generate Reports

Once findings are approved, generate a report:

**Via CLI:**
```bash
nexus report generate --profile full --save report.md
```

**Via MCP:**
```
generate_report(profile="full")
```

**Available profiles:**
| Profile | Content |
|---------|---------|
| `full` | Case summary + all approved findings + evidence table + audit summary |
| `status` | Counts only (total, approved, rejected) |
| `ioc` | IOC list extracted from findings with MITRE mapping |
| `executive` | Management briefing — top 5 findings, non-technical |
| `timeline` | Chronological event narrative |
| `findings` | All approved findings in detail |

---

## 5. Understanding the Audit Chain

Every write operation in DFIR-Nexus goes through an **HMAC-SHA256 audit chain**:

```
Genesis (0x000...000) → case_created → evidence_registered → finding_recorded → finding_approved → case_closed
```

Each entry contains:
- **prev_hash** — the hash of the previous entry (forms the chain)
- **hash** — HMAC-SHA256 of (prev_hash + payload + entry_id + timestamp)
- **signature** — same as hash (provides authentication via the secret key)

**Why this matters:**
- If an attacker modifies a finding's title → the hash won't match → verification fails.
- If an entry is deleted → the chain breaks (prev_hash mismatch) → verification fails.
- Every approved finding is individually HMAC-signed with a per-finding salt derived from the case password.
- The audit chain is stored both in SQLite (via the case stack) and JSONL files in the case directory.

---

## 6. SQLite Case Stack

Cases, findings, evidence, and audit entries are stored in a SQLite database (`cases.db`) with full referential integrity:

- **Cascade delete** — deleting a case removes all findings, evidence, and audit entries.
- **Foreign keys** — findings and evidence reference their parent case.
- **Enum columns** — statuses and severities are stored as text (portable, queryable).
- **JSON metadata** — tags, technique_ids, and arbitrary metadata stored as JSON.

You can also **migrate legacy flat-JSON cases** into SQLite:
```bash
nexus case migrate --dry-run    # preview
nexus case migrate              # execute
```
All new cases created via CLI use SQLite. Existing MCP tools dual-write to both flat-JSON and SQLite for backward compatibility.

---

## 7. MITRE ATT&CK Integration

DFIR-Nexus has full MITRE ATT&CK v15 support:

| Feature | Command |
|---------|---------|
| Match observed techniques to threat actors | `mitre_match_actors(["T1486", "T1490", "T1070.001"])` |
| List built-in actor profiles | `mitre_list_actors()` |
| Risk-Based Alerting score | `mitre_rba_score(technique_ids=["T1003.001", "T1558.003"])` |
| Export Navigator layer | `mitre_navigator_layer(technique_ids=[...])` |
| Actor-specific layer | `mitre_navigator_actor_layer("apt29")` |
| Detection coverage per technique | `mitre_coverage(technique_id="T1003.001")` |
| Coverage gap analysis | `mitre_gap_analysis(["T1003.001", "T1059.001", "T9999.999"])` |

---

## 8. RAG Knowledge Search

DFIR-Nexus has a forensic knowledge base of ~22K records searchable via semantic search. **The index is downloaded on first use** (~600 MB) — it does not ship with the package. Requires `chromadb` and `sentence-transformers` (install via `pip install dfir-nexus[rag]`).

**How to use (MCP):**
```
forensic_rag_search("LSASS credential dumping detection")
forensic_rag_list_sources()
forensic_rag_status()
```

---

## 9. Triage Validation

The triage subsystem validates processes, files, services, tasks, autoruns, and hashes against Windows baselines:

**Databases (downloaded separately, ~2 GB):**
- `known_good.db` — Windows baseline files/services/tasks/autoruns
- `context.db` — LOLBins, vulnerable drivers, process rules, named pipes
- `registry.db` — Registry key baselines

**How to use (MCP):**
```
triage_check_lolbin(binary="rundll32.exe")
triage_check_file(file_path="C:\\Windows\\System32\\svchost.exe")
```

---

## 10. Ingest Pipeline

DFIR-Nexus can import forensic data from 36 registered importer classes:

**Import from a file:**
```
ingest_detect_and_parse("/case/evidence/zeek_conn.log")
ingest_from_source("/case/evidence/alerts.json", source="elastic")
```

---

## 11. Velociraptor Integration

DFIR-Nexus can orchestrate Velociraptor hunts and artifact collections across your lab:

**How to use:**
```
vr_list_clients()                                    → show enrolled hosts
vr_list_hunts()                                      → show available hunts
vr_run_hunt("cadre-process-tree", "C.mbr01")         → collect from C.mbr01
```
*Note: Velociraptor comes with a built-in Mock Mode (force-mocked by default) that returns synthetic, structured forensic data. You can test and practice hunts without setting up a Velociraptor server.*

---

## 12. Case Lifecycle

```
                    ┌──────────┐
                    │  init    │  Create case with name + description
                    └────┬─────┘
                         ▼
                    ┌──────────┐
                    │  OPEN    │  Default state — add evidence + findings
                    └────┬─────┘
                         ▼
                    ┌──────────┐
                    │ IN_PROGRESS│  (optional — via update_status)
                    └────┬─────┘
                         ▼
                    ┌──────────┐
                    │  CLOSED  │  case closed, closed_at + closed_by recorded
                    └────┬─────┘
                         ▼
                    ┌──────────┐
                    │ ARCHIVED │  (optional — for long-term storage)
                    └──────────┘
```

---

## 13. CLI Command Reference

See **[CLI.md](CLI.md)** for the full command reference.

---

## 14. Security Model

DFIR-Nexus enforces strict boundaries to preserve chain-of-custody. See **[ARCHITECTURE.md](ARCHITECTURE.md)** for details.

---

## 15. FAQ

See **[FAQ.md](FAQ.md)** for common questions.

---

## 16. Hands-On Practice Lab & Tutorial

This section provides a complete, step-by-step practical guide to learning, testing, and verifying DFIR-Nexus features from scratch on a clean machine.

### 16.1 Setting up a Practice Workspace

To practice without affecting production folders, create a test workspace directory and register mock/sample evidence:

```powershell
# Windows
mkdir C:\ForensicsTest
cd C:\ForensicsTest
# Create a dummy evidence file
"Fake log artifact content" | Out-File -FilePath .\security_log.txt -Encoding utf8
```

```bash
# Linux
mkdir -p ~/forensics_test
cd ~/forensics_test
echo "Fake log artifact content" > security_log.txt
```

#### Where to get Real Forensics Sample Datasets
To test real tool parsers, download these open-source forensic datasets:
1. **Windows Event Logs (EVTX)**: Download malicious event log files from [sbousseaden/EVTX-Attack-Samples GitHub](https://github.com/sbousseaden/EVTX-Attack-Samples).
2. **Network PCAPs**: Download packet captures from [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/).
3. **Memory Dumps**: Download memory practice challenges from [MemLabs](https://github.com/stuxnet999/MemLabs).

---

### 16.2 Bypassing Forensic Tool Requirements (Mocking Executions)

If you are a developer testing the system, or you do not have external forensic tools (like Zimmerman tools or Plaso) installed yet, **you can mock tool executions using the `log_external_action` command**. This creates a valid record in the cryptographic audit trail and outputs an `audit_id` that is accepted by `record_finding`.

#### Method A: Via CLI
```bash
nexus exec --purpose "Mock MFT Analysis" "MFTECmd.exe -f C:\evidence\MFT"
```
*Output:*
```text
[PASS] Logged external command execution.
Audit ID: audit-alicesmith-20260718-120000-abcd
```

#### Method B: Via MCP Tool Call
```json
// Tool: log_external_action
{
  "command": "vol.py -f memory.dmp windows.info",
  "output_summary": "Volatility 3 run: Found OS version Windows 10 x64",
  "purpose": "Analyze memory image profile"
}
```
*Returns:*
```json
{
  "status": "logged",
  "audit_id": "audit-alicesmith-20260718-120530-efgh"
}
```

---

### 16.3 Step-by-Step Hands-on Triage & Approval Walkthrough

This walkthrough guides you through creating a case, using a triage baseline, recording a finding, signing it with a password, and generating a report.

#### Step 1: Initialize Identity & Config
Configure your environment to run tests:
```bash
nexus config --examiner "practice_user"
nexus config --setup-password # Set password to: "PracticePassword123"
nexus case init "Practice-Case-001"
```

#### Step 2: Register a Practice Evidence File
Let's register our practice log file:
```bash
# Windows
nexus evidence register C:\ForensicsTest\security_log.txt --description "Initial triage log"
# Linux
nexus evidence register ~/forensics_test/security_log.txt --description "Initial triage log"
```
This hashes the file (`SHA-256`) and commits the hash to `evidence_registry.json`.

#### Step 3: Run Triage Baseline Verification (No External Tools Needed!)
If you have downloaded the triage databases, run a triage query. This will hit the SQLite database and return a verdict, logging the action in the audit trail:

*Via MCP:*
```json
// Tool: triage_check_lolbin
{
  "binary": "rundll32.exe"
}
```
*Returns:*
```json
{
  "binary": "rundll32.exe",
  "verdict": "EXPECTED_LOLBIN",
  "audit_id": "audit-practice_user-20260718-121000-xyz"
}
```
*Note the returned `audit_id`. We must use this ID to associate our finding with this action.*

#### Step 4: Record a Triage Finding
Use the `audit_id` from the previous step to stage a finding. If you invent a random ID that is not in the audit log, the case manager will reject the finding:

*Via MCP:*
```json
// Tool: record_finding
{
  "title": "Abuse of rundll32.exe LOLBin",
  "observation": "rundll32.exe execution identified in logs",
  "interpretation": "Attacker utilized rundll32.exe to bypass application control",
  "severity": "HIGH",
  "confidence": "HIGH",
  "confidence_justification": "Verified binary path matches expected LOLBin signature",
  "technique_ids": ["T1218.011"],
  "artifacts": [
    {
      "type": "file",
      "value": "rundll32.exe",
      "audit_id": "audit-practice_user-20260718-121000-xyz"
    }
  ]
}
```
*Returns:*
```json
{
  "status": "STAGED",
  "finding_id": "F-practice_user-1",
  "provenance_grade": "FULL"
}
```

#### Step 5: Review and Approve the Finding (Human-in-the-Loop)
The finding has been successfully staged as a `DRAFT`. It will not show up in reports until it is approved. Approve it from the terminal:
```bash
nexus approve --interactive
```
The terminal displays:
```text
==================================================
Staged Finding [1/1]: F-practice_user-1
Title: Abuse of rundll32.exe LOLBin
Severity: HIGH
Observation: rundll32.exe execution identified in logs
--------------------------------------------------
[a]pprove, [r]eject, [s]kip: a
Enter approval password: PracticePassword123

[PASS] Finding F-practice_user-1 approved. Cryptographic signature written.
```

#### Step 6: Generate and Verify the Report
Export the final report in Markdown format:
```bash
nexus report generate --profile full --save practice_report.md
```
Open `practice_report.md` in any editor. You will see the approved finding, evidence tables, and the audit trail summary.

Verify that the case database has not been tampered with:
```bash
nexus review verify
```
*Output:*
```text
[PASS] Audit chain verification successful.
Total entries verified: 5
Gaps or hash mismatches: 0
```

---

### 16.4 Automated Test Suite Execution

You can run the entire automated testing suite to verify Python code paths are fully operational:

```bash
# 1. Install with all optional extras
pip install -e ".[all]"

# 2. Run unit tests (252 checks)
pytest -q

# 3. Run functional audits (115 checks)
python tests/functional_audit.py

# 4. Run module-specific script tests (219 checks)
python tests/test_knowledge.py
python tests/test_detection.py
python tests/test_ti.py
python tests/test_ingest.py
python tests/test_integration.py
python tests/test_portal.py
python tests/test_hunt_parser.py
```
**Total:** 607 checks. All tests must report `PASS` / Exit Code `0`.

---

### 16.5 Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| `Tool not found` errors | Executable missing or not in path | Install the binary (see §3) or update the `NEXUS_TOOL_PATHS` environment variable to include its directory. |
| `REJECTED` findings | Invalid `audit_id` | You must run a triage check or external tool first to get a valid `audit_id`, or use `nexus exec` to mock the run. |
| `Connection refused` on Portal | HTTP server is not running | Run `nexus serve --http --port 4508` in the background before executing `nexus portal` or connecting your browser. |
| `sqlite3.OperationalError` | Stale database | Run `nexus case migrate` to reconcile existing cases, or delete corrupted debug databases. |
| Password authentication fails | Incorrect password or lockout | 3 consecutive failures lock the case manager for 15 minutes. Wait for the lockout period to expire, or delete the `.approval_lockout` file. |
