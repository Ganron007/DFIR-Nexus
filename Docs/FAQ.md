# DFIR-Nexus — FAQ

## General

**Q: What is DFIR-Nexus?**
A: A unified DFIR investigation platform that wraps your existing forensic tools behind MCP servers, enforces a cryptographic audit chain, and requires human approval before findings become final.

**Q: Do I need an LLM?**
A: No. The CLI (`nexus`) and Examiner Portal work without any LLM. An LLM client (Claude Code, Cursor, etc.) is optional — it lets you run investigations agentically where the LLM calls MCP tools on your behalf.

**Q: What OS does it run on?**
A: Windows, Linux, macOS. The `nexus serve` server runs on any. MCP tools (SIFT, Windows, Velociraptor) are available based on what you have installed on each host.

**Q: Is it open source?**
A: Yes. MIT license.

---

## Installation

**Q: What do I need before installing?**
A: Python 3.12+, Git, and optionally PowerShell 7+ (Windows). See [SETUP.md](SETUP.md) for per-OS prerequisites.

**Q: How do I install?**
A: `.\setup-windows.ps1` (Windows) or `./setup-linux.sh` (Linux) or `pip install dfir-nexus[all]`.

**Q: What's the difference between `[all]`, `[rag]`, `[triage]`, etc.?**
A: `[all]` installs everything. Subsets let you skip what you don't need:
- `[http]` — web server for Portal
- `[rag]` — ChromaDB + sentence-transformers (~600 MB)
- `[triage]` — orjson + zstandard (~2 GB baseline DBs)
- `[opensearch]` — OpenSearch client
- `[opencti]` — OpenCTI client
- `[encrypt]` — encryption for export bundles

**Q: Where is my data stored?**
A: `~/.nexus/` — cases, config, passwords, audit log, data (RAG/triage indices). Nothing phones home.

---

## Cases & Findings

**Q: What's a case?**
A: A container for one investigation. Holds findings, evidence, timeline events, TODOs, IOCs, and audit entries.

**Q: Can I work on multiple cases simultaneously?**
A: Yes. `nexus case activate` switches the active case. All tools route to the active case.

**Q: What's a finding?**
A: A structured observation — title, description, severity (INFORMATIONAL/LOW/MEDIUM/HIGH/CRITICAL), MITRE technique IDs, linked audit trail entries. Always starts as DRAFT.

**Q: Why are findings created as DRAFT?**
A: To enforce HITL. An LLM or automated tool can propose findings but cannot approve them. A human examiner must review and approve.

**Q: What happens if I approve a finding?**
A: The finding is PBKDF2-HMAC signed using your case password. It moves to APPROVED and appears in reports. The signature is independently verifiable.

**Q: Can the LLM approve findings?**
A: No. Approval requires the case password (PBKDF2-SHA256 hashed). The LLM never sees the password. CLI and Portal approval is human-only.

**Q: What if I enter the wrong approval password?**
A: 3 wrong attempts lock the finding for 15 minutes. A correct attempt resets the counter.

---

## Evidence & Audit

**Q: How does evidence registration work?**
A: `nexus evidence register /path/to/file`. Computes SHA-256, stores metadata. `nexus evidence verify` re-computes and compares. `nexus evidence lock` makes files read-only.

**Q: What's the audit chain?**
A: Every action (tool run, finding record, approval) is appended to an HMAC-SHA256 chain. Each entry links to the previous one via its hash. Tampering with any entry breaks the chain — detected on `nexus review verify`.

**Q: Can I prove my findings haven't been tampered with?**
A: Yes. The audit chain + per-finding HMAC signatures provide cryptographic proof. Run `nexus review verify` and `verify_approval_signatures()`.

---

## Tools & Data

**Q: What forensic tools does DFIR-Nexus support?**
A: It wraps your existing tools — NOT replaces them. Supported: SIFT workstation tools, Zimmerman tools, Sysinternals, KAPE, YARA, Volatility 3, Plaso, Hayabusa, Velociraptor, Suricata, Zeek, Elastic, and more. 110 MCP tools (Windows) / 107 (Linux).

**Q: Do I need to install the forensic tools separately?**
A: Yes. DFIR-Nexus discovers tools on your PATH or at configured paths. If SIFT tools are on a VM, point `nexus setup client --sift <ip>:4508`.

**Q: What's RAG knowledge search?**
A: Semantic search over ~22K curated forensic records (downloaded on first use, ~600 MB). Search for techniques, artifacts, or tools and get relevant SANS/MITRE/Sigma/KAPE knowledge back.

**Q: Do I need to download the RAG index?**
A: Yes, one-time: `forensic_rag_download()` (~600 MB). Findings, cases, and reports work without it.

**Q: What's triage validation?**
A: Checks files/processes/services against Windows baselines (KnownGoodDB + ContextDB + RegistryDB). Tells you if something is legitimate, a LOLBin, or suspicious. One-time download: `triage_download()` (~2 GB).

**Q: What data formats can I ingest?**
A: 36 registered importer classes — Suricata, Zeek, Elastic, Splunk, EVTX, Prefetch, Amcache, Shimcache, Shellbags, LNK, Registry, WMI, Volatility 3, Plaso, Hayabusa, MISP, OTX, VirusTotal, CloudTrail, Azure, GCP, Auditd, Authlog, Syslog, Bash History, and generic JSONL/CSV.

**Q: Can I search my detection rules?**
A: Yes. Index your Sigma/Hayabusa rules with `detection_sigma_install()`, then search by technique, severity, or keyword. Get MITRE coverage heatmaps and gap analysis.

**Q: Can I use Velociraptor?**
A: Yes. 10 pre-built hunts + 5 custom artifacts. Mock mode works out of the box (no VR server needed for testing).

---

## Reports & Export

**Q: What report formats are available?**
A: Markdown, HTML, JSON, STIX 2.0/2.1, CSV, DOCX, ZIP (bundle), SVG (swimlane + asset graph).

**Q: Can I share cases with other analysts?**
A: Yes. Export to JSON/STIX and merge on another DFIR-Nexus instance with `nexus merge bundle.json`.

**Q: Can I push findings to external platforms?**
A: Yes. Built-in exporters for Timesketch (timeline), MISP (attributes), and DFIR-IRIS (case notes). Slack/Teams/Discord/Telegram/SMTP notifications also available.

---

## Troubleshooting

**Q: `record_finding` returns REJECTED with "invalid or missing evidence trail".**
A: You're using fabricated audit_ids. Every finding must reference real audit trail entries from tool runs. Run a tool first, get its audit_id, then reference it in the finding.

**Q: "No active case" error.**
A: Run `nexus case init "Name"` or `nexus case activate CASE-XXX` first.

**Q: MCP tools not showing in my LLM client.**
A: Verify `nexus serve --http` is running and your client config points to the right URL. Use `nexus setup test` to diagnose.

**Q: The audit chain verification fails.**
A: Audit files may have been manually edited or corrupted. Check `~/.nexus/cases/<case-id>/audit/*.jsonl`. Re-import from backup if available.
