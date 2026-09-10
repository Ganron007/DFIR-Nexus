"""Demo case seeder — generates rich, realistic fixture investigations for UI/CLI testing.

Allows developers and examiners to immediately launch and test every cockpit surface
(Explore, Timeline, Steer Chat, Workbench, Findings, Approve, Report, Entities, IOCs, TODOs)
without needing hours of live collection or external parsing tools.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from nexus.config import settings

log = logging.getLogger(__name__)


def seed_demo_case(
    case_name: str = "Demo Investigation",
    examiner: str = "analyst_purple",
    case_id: str = "CASE-DEMO-001",
    activate: bool = True,
) -> dict[str, Any]:
    """Seed a rich, realistic investigation case into the case store.

    Populates:
    - Case metadata (CASE.yaml) & SQLite entry
    - Evidence registry with 4 realistic artifacts
    - Extractions directory with ~350 parsed events across EVTX, Prefetch, Zeek, Browser
    - 5 realistic findings (2 DRAFT, 2 APPROVED, 1 REJECTED)
    - 4 IOCs and 3 TODO items
    - An official compiled REPORT.md preview

    ``activate=False`` seeds the case without switching the active-case
    pointer (the Examiner Portal dashboard previews cases before entering).
    """
    from nexus.case.manager import CaseManager
    from nexus.case.outputs import set_active_case_id
    from nexus.case.schemas import ApprovalState, CaseStatus, FindingSeverity

    db_path = settings.cases_root / "cases.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    mgr = CaseManager(db_path)

    # Clean up existing demo case if present to ensure a fresh, consistent seed
    existing = mgr.store.get_case(case_id)
    if existing:
        mgr.delete_case(case_id)

    case = mgr.create_case(
        name=case_name,
        description="Assumed-breach incident simulation — credential access, lateral movement & persistence",
        severity=FindingSeverity.HIGH,
        created_by=examiner,
        tags=["campaign-h", "active-directory", "assumed-breach", "demo"],
        metadata={"investigation_mode": "1", "examiner": examiner},
        case_id=case_id,
    )

    case_dir = settings.cases_root / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    extractions_dir = case_dir / "extractions"
    reports_dir = case_dir / "reports"
    extractions_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(exist_ok=True)

    import yaml
    case_yaml_data = {
        "name": case_name,
        "description": "Assumed-breach incident simulation — credential access, lateral movement & persistence",
        "status": "created",
        "investigation_mode": "1",
        "examiner": examiner,
        "created_at": datetime.now(UTC).isoformat(),
    }
    (case_dir / "CASE.yaml").write_text(yaml.safe_dump(case_yaml_data, sort_keys=False), encoding="utf-8")

    # 1. Register Evidence Records
    evidence_items = [
        {
            "name": "Security.evtx",
            "description": "Windows Security Event Log from WS01 beachhead",
            "file_path": str(case_dir / "evidence" / "Security.evtx"),
            "hash": hashlib.sha256(b"DEMO-SECURITY-EVTX-CONTENT").hexdigest(),
        },
        {
            "name": "PECmd_Summary.csv",
            "description": "Prefetch execution parser output from C:\\Windows\\Prefetch",
            "file_path": str(case_dir / "evidence" / "PECmd_Summary.csv"),
            "hash": hashlib.sha256(b"DEMO-PREFETCH-CONTENT").hexdigest(),
        },
        {
            "name": "zeek_conn.log",
            "description": "Zeek network connection log for 192.168.77.0/24 subnet",
            "file_path": str(case_dir / "evidence" / "zeek_conn.log"),
            "hash": hashlib.sha256(b"DEMO-ZEEK-CONTENT").hexdigest(),
        },
        {
            "name": "Chrome_History.sqlite",
            "description": "Browser history extracted from user analyst_t1",
            "file_path": str(case_dir / "evidence" / "Chrome_History.sqlite"),
            "hash": hashlib.sha256(b"DEMO-CHROME-CONTENT").hexdigest(),
        },
    ]

    for ev in evidence_items:
        p = Path(ev["file_path"])
        p.parent.mkdir(parents=True, exist_ok=True)
        content = f"DFIR-Nexus Mock Evidence for {ev['name']}\n".encode()
        p.write_bytes(content)
        actual_hash = hashlib.sha256(content).hexdigest()
        ev["hash"] = actual_hash
        mgr.add_evidence(
            case_id=case.id,
            name=ev["name"],
            description=ev["description"],
            file_path=ev["file_path"],
            file_hash_sha256=actual_hash,
            collected_by=examiner,
        )

    # Mirror to evidence.json for file-based dashboard readers
    (case_dir / "evidence.json").write_text(
        json.dumps([
            {"name": ev["name"], "path": ev["file_path"], "sha256": ev["hash"], "description": ev["description"], "status": "registered", "registered_at": datetime.now(UTC).isoformat()}
            for ev in evidence_items
        ], indent=2),
        encoding="utf-8"
    )

    # 2. Populate Parsed CSV Extractions for Explore & Timeline
    now = datetime.now(UTC)
    base_time = now - timedelta(days=2)

    # 2a. EVTX Timeline CSV
    evtx_dir = extractions_dir / "evtx"
    evtx_dir.mkdir(exist_ok=True)
    evtx_file = evtx_dir / "evtx-timeline.csv"
    with open(evtx_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["TimeCreated", "EventID", "Computer", "Channel", "ProcessName", "CommandLine", "SubjectUserName", "Message"])
        # Generate 150 realistic log entries
        for i in range(150):
            t = (base_time + timedelta(minutes=i * 15)).strftime("%Y-%m-%d %H:%M:%S")
            if i % 25 == 0:
                writer.writerow([t, "4688", "WS01.CADRE.LOCAL", "Security", "C:\\Windows\\System32\\powershell.exe", "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIA...==", "analyst_t1", "Process Creation with Encoded Command"])
            elif i % 18 == 0:
                writer.writerow([t, "4624", "WS01.CADRE.LOCAL", "Security", "-", "-", "analyst_t1", "Successful Logon Type 10 RemoteInteractive"])
            elif i % 12 == 0:
                writer.writerow([t, "4625", "WS01.CADRE.LOCAL", "Security", "-", "-", "Administrator", "Failed Logon - Unknown user name or bad password"])
            elif i % 30 == 0:
                writer.writerow([t, "7045", "MBR01.CADRE.LOCAL", "System", "services.exe", "C:\\Windows\\PSEXESVC.exe", "SYSTEM", "New Service Installed: PSEXESVC"])
            elif i == 145:
                writer.writerow([t, "1102", "WS01.CADRE.LOCAL", "Security", "wevtutil.exe", "wevtutil cl Security", "analyst_t1", "The audit log was cleared"])
            else:
                writer.writerow([t, "4688", "WS01.CADRE.LOCAL", "Security", "C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs -p", "SYSTEM", "Normal System Background Process"])

    # 2b. Prefetch Summary CSV
    pf_dir = extractions_dir / "prefetch"
    pf_dir.mkdir(exist_ok=True)
    pf_file = pf_dir / "prefetch-summary.csv"
    with open(pf_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ExecutableName", "RunCount", "LastRun", "VolumePath", "Host"])
        executables = [
            ("POWERSHELL.EXE", 42, (now - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S"), "\\VOLUME{01}", "WS01"),
            ("CMD.EXE", 88, (now - timedelta(hours=4)).strftime("%Y-%m-%d %H:%M:%S"), "\\VOLUME{01}", "WS01"),
            ("MIMIKATZ.EXE", 3, (now - timedelta(hours=5)).strftime("%Y-%m-%d %H:%M:%S"), "\\VOLUME{01}", "WS01"),
            ("RUBEUS.EXE", 5, (now - timedelta(hours=6)).strftime("%Y-%m-%d %H:%M:%S"), "\\VOLUME{01}", "WS01"),
            ("SHARPDPAPI.EXE", 2, (now - timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S"), "\\VOLUME{01}", "WS01"),
            ("CERTUTIL.EXE", 12, (now - timedelta(hours=12)).strftime("%Y-%m-%d %H:%M:%S"), "\\VOLUME{01}", "WS01"),
            ("WHOAMI.EXE", 15, (now - timedelta(hours=14)).strftime("%Y-%m-%d %H:%M:%S"), "\\VOLUME{01}", "WS01"),
            ("NET.EXE", 21, (now - timedelta(hours=16)).strftime("%Y-%m-%d %H:%M:%S"), "\\VOLUME{01}", "WS01"),
        ]
        for item in executables:
            writer.writerow(list(item))

    # 2c. Zeek Conn CSV
    zeek_dir = extractions_dir / "zeek"
    zeek_dir.mkdir(exist_ok=True)
    zeek_file = zeek_dir / "conn.csv"
    with open(zeek_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration", "orig_bytes", "resp_bytes"])
        for i in range(80):
            t = (base_time + timedelta(minutes=i * 20)).strftime("%Y-%m-%d %H:%M:%S")
            if i % 10 == 0:
                writer.writerow([t, "192.168.77.60", 49210 + i, "192.168.77.62", 445, "tcp", "smb", "12.4", "1048576", "65536"])
            elif i % 7 == 0:
                writer.writerow([t, "192.168.77.62", 51200 + i, "192.168.77.10", 88, "tcp", "krb", "0.2", "2048", "4096"])
            else:
                writer.writerow([t, "192.168.77.62", 50100 + i, "192.168.77.10", 53, "udp", "dns", "0.05", "120", "240"])

    # 2d. Browser History CSV
    browser_dir = extractions_dir / "browser"
    browser_dir.mkdir(exist_ok=True)
    browser_file = browser_dir / "history.csv"
    with open(browser_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Time", "URL", "Title", "VisitCount", "User"])
        urls = [
            ((now - timedelta(hours=20)).strftime("%Y-%m-%d %H:%M:%S"), "https://github.com/gentilkiwi/mimikatz/releases", "Release 2.2.0 · gentilkiwi/mimikatz", 2, "analyst_t1"),
            ((now - timedelta(hours=18)).strftime("%Y-%m-%d %H:%M:%S"), "https://raw.githubusercontent.com/redteam/payloads/main/run.ps1", "Raw script payload", 1, "analyst_t1"),
            ((now - timedelta(hours=10)).strftime("%Y-%m-%d %H:%M:%S"), "https://portal.azure.com", "Microsoft Azure Portal", 15, "analyst_t1"),
            ((now - timedelta(hours=4)).strftime("%Y-%m-%d %H:%M:%S"), "https://learn.microsoft.com/en-us/powershell/", "PowerShell Documentation", 8, "analyst_t1"),
        ]
        for u in urls:
            writer.writerow(list(u))

    # 3. Seed Findings (DRAFT, APPROVED, REJECTED)
    findings_data = [
        {
            "id": "F-DEMO-001",
            "title": "Encoded PowerShell Command Execution on WS01 Beachhead",
            "status": "DRAFT",
            "confidence": "HIGH",
            "severity": FindingSeverity.HIGH,
            "technique_ids": ["T1059.001"],
            "observation": "Event ID 4688 records powershell.exe invoked with encoded command containing web download cradle.",
            "interpretation": "Adversary utilized obfuscated PowerShell to execute initial stage dropper in memory.",
            "justification": "Corroborated by Event ID 4688 logs and PECmd execution timestamps on volume C:.",
            "audit_ids": ["audit-evtx-4688-001", "audit-pf-ps-001"],
            "examiner_selected": True,
        },
        {
            "id": "F-DEMO-002",
            "title": "Pass-the-Hash / Overpass-the-Hash Kerberos Ticket Requests",
            "status": "DRAFT",
            "confidence": "MEDIUM",
            "severity": FindingSeverity.MEDIUM,
            "technique_ids": ["T1550.002"],
            "observation": "Repetitive Kerberos TGS requests observed from analyst_t1 account with RC4-HMAC encryption.",
            "interpretation": "Adversary requested Kerberos service tickets for lateral movement using extracted NT hashes.",
            "justification": "Zeek Kerberos connection bursts match Event 4769 audits on dc01.",
            "audit_ids": ["audit-zeek-krb-002", "audit-evtx-4769-002"],
            "examiner_selected": False,  # LLM-drafted
        },
        {
            "id": "F-DEMO-003",
            "title": "Anomalous SMB Lateral Movement from Provisioning Host 192.168.77.60",
            "status": "APPROVED",
            "confidence": "HIGH",
            "severity": FindingSeverity.CRITICAL,
            "technique_ids": ["T1021.002"],
            "observation": "High-volume SMB sessions targeting admin$ and c$ shares on member server MBR01 followed by service install.",
            "interpretation": "Psexec-style lateral movement using compromised domain credentials.",
            "justification": "Confirmed by Zeek TCP 445 byte volume (1MB+) and System Event 7045 PSEXESVC on MBR01.",
            "audit_ids": ["audit-zeek-smb-003", "audit-evtx-7045-003"],
            "examiner_selected": True,
            "approved_by": examiner,
            "approved_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        },
        {
            "id": "F-DEMO-004",
            "title": "Credential Access via Mimikatz / LSA Secret Extraction",
            "status": "APPROVED",
            "confidence": "HIGH",
            "severity": FindingSeverity.CRITICAL,
            "technique_ids": ["T1003.001"],
            "observation": "Prefetch execution artifact for MIMIKATZ.EXE and SHARPDPAPI.EXE detected on WS01 beachhead.",
            "interpretation": "Adversary attempted memory credential scraping against LSASS to harvest plaintext passwords.",
            "justification": "PECmd summary confirms MIMIKATZ.EXE executed 3 times from temp staging path.",
            "audit_ids": ["audit-pf-mimi-004"],
            "examiner_selected": True,
            "approved_by": examiner,
            "approved_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        },
        {
            "id": "F-DEMO-005",
            "title": "Routine Scheduled Task Software Update",
            "status": "REJECTED",
            "confidence": "LOW",
            "severity": FindingSeverity.LOW,
            "technique_ids": ["T1053.005"],
            "observation": "Daily task execution for system management agent.",
            "interpretation": "Baseline enterprise administrative activity.",
            "justification": "Verified against CADRE lab baseline and vendor hash registry.",
            "audit_ids": ["audit-task-005"],
            "examiner_selected": True,
            "rejected_by": examiner,
            "rejection_reason": "Legitimate enterprise software management update; verified against baseline.",
        },
    ]

    # Save to SQLite and mirror to findings.json
    flat_findings: list[dict[str, Any]] = []
    for fd in findings_data:
        f_obj = mgr.add_finding(
            case_id=case.id,
            title=fd["title"],
            description=fd["observation"],
            severity=fd["severity"],
            technique_ids=fd["technique_ids"],
            created_by=examiner,
            metadata={
                "observation": fd["observation"],
                "interpretation": fd["interpretation"],
                "confidence": fd["confidence"],
                "confidence_justification": fd["justification"],
                "audit_ids": fd["audit_ids"],
                "examiner_selected": fd["examiner_selected"],
                "rejection_reason": fd.get("rejection_reason", ""),
            },
            initial_state=ApprovalState.DRAFT,
        )
        if f_obj:
            flat_findings.append({
                "id": fd["id"],
                "case_id": case.id,
                "title": fd["title"],
                "status": fd["status"],
                "confidence": fd["confidence"],
                "observation": fd["observation"],
                "interpretation": fd["interpretation"],
                "confidence_justification": fd["justification"],
                "audit_ids": fd["audit_ids"],
                "technique_ids": fd["technique_ids"],
                "examiner_selected": fd["examiner_selected"],
                "approved_by": fd.get("approved_by"),
                "approved_at": fd.get("approved_at"),
                "rejected_by": fd.get("rejected_by"),
                "rejection_reason": fd.get("rejection_reason"),
            })

    (case_dir / "findings.json").write_text(json.dumps(flat_findings, indent=2), encoding="utf-8")

    # 4. Seed IOCs
    iocs_data = [
        {"type": "ip", "value": "192.168.77.60", "finding_title": "Anomalous SMB Lateral Movement", "severity": "HIGH"},
        {"type": "sha256", "value": "4a7d1ed414474e4033ac29ccb8653d9b002c912efc464efc85e72d4cc98d1a3b", "finding_title": "Credential Access via Mimikatz", "severity": "CRITICAL"},
        {"type": "domain", "value": "raw.githubusercontent.com", "finding_title": "Encoded PowerShell Command Execution", "severity": "MEDIUM"},
        {"type": "file", "value": "PSEXESVC.exe", "finding_title": "Anomalous SMB Lateral Movement", "severity": "HIGH"},
    ]
    (case_dir / "iocs.json").write_text(json.dumps(iocs_data, indent=2), encoding="utf-8")

    # 5. Seed TODOs
    todos_data = [
        {"todo_id": "TODO-001", "id": "TODO-001", "description": "Review Active Directory replication traffic on DC01 for DCSync indicators", "status": "OPEN", "priority": "HIGH", "assignee": examiner},
        {"todo_id": "TODO-002", "id": "TODO-002", "description": "Collect memory image from WS01 beachhead for injected shellcode verification", "status": "OPEN", "priority": "MEDIUM", "assignee": examiner},
        {"todo_id": "TODO-003", "id": "TODO-003", "description": "Isolate staging host 192.168.77.60 at the firewall boundary", "status": "COMPLETED", "priority": "HIGH", "assignee": examiner},
    ]
    (case_dir / "todos.json").write_text(json.dumps(todos_data, indent=2), encoding="utf-8")

    # 6. Seed Official Report Preview
    report_md = f"""# DFIR-Nexus Forensic Investigation Report

**Case ID:** {case_id}  
**Case Name:** {case_name}  
**Lead Examiner:** {examiner}  
**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S UTC')}  
**Integrity:** Cryptographically Sealed (HMAC-SHA256)

---

## 1. Executive Summary

An assumed-breach forensic investigation was conducted across target workstations and servers within the CADRE environment. Evidence analysis identified unauthorized credential access, execution of obfuscated PowerShell scripts, and subsequent lateral movement using SMB and remote service execution.

---

## 2. Evidence Analyzed

| Artifact Name | Hash (SHA-256) | Role / Source |
|---|---|---|
| `Security.evtx` | `{evidence_items[0]['hash'][:16]}...` | WS01 Security Audit Log |
| `PECmd_Summary.csv` | `{evidence_items[1]['hash'][:16]}...` | Windows Prefetch Parser |
| `zeek_conn.log` | `{evidence_items[2]['hash'][:16]}...` | Subnet Network Flow |
| `Chrome_History.sqlite` | `{evidence_items[3]['hash'][:16]}...` | Browser Activity |

---

## 3. Approved Findings (FD-002 Verified)

### F-DEMO-003: Anomalous SMB Lateral Movement from Provisioning Host 192.168.77.60
- **Severity:** CRITICAL
- **Technique:** MITRE ATT&CK T1021.002
- **Approved by:** {examiner}
- **Observation:** High-volume SMB sessions targeting admin$ and c$ shares on member server MBR01 followed by service install.
- **Interpretation:** Psexec-style lateral movement using compromised domain credentials.
- **Audit Witnesses:** `audit-zeek-smb-003`, `audit-evtx-7045-003`

### F-DEMO-004: Credential Access via Mimikatz / LSA Secret Extraction
- **Severity:** CRITICAL
- **Technique:** MITRE ATT&CK T1003.001
- **Approved by:** {examiner}
- **Observation:** Prefetch execution artifact for MIMIKATZ.EXE and SHARPDPAPI.EXE detected on WS01 beachhead.
- **Interpretation:** Adversary attempted memory credential scraping against LSASS to harvest plaintext passwords.
- **Audit Witnesses:** `audit-pf-mimi-004`
"""
    (reports_dir / "REPORT.md").write_text(report_md, encoding="utf-8")
    (case_dir / "REPORT.md").write_text(report_md, encoding="utf-8")

    # Pipeline run marker for cockpit
    analysis_dir = case_dir / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)
    (analysis_dir / "TOOL-RUN.md").write_text(
        f"# N2 Parser Lane Run Record\n\nCase: {case_id}\nCompleted: {now.isoformat()}\nStatus: OK\n\nAll tools executed cleanly.",
        encoding="utf-8"
    )

    # Lifecycle: the demo is fully parsed → ACTIVE. SQLite is the system of
    # record; update_status mirrors the value into CASE.yaml (audit-chained).
    mgr.update_status(case.id, CaseStatus.ACTIVE, actor=examiner)

    # Activate only when requested — the portal previews cases on the
    # dashboard without switching away from the current investigation.
    if activate:
        set_active_case_id(case.id)
    mgr.close()

    log.info("Successfully seeded demo case %s with %d findings", case.id, len(flat_findings))
    return {
        "ok": True,
        "case_id": case.id,
        "evidence_count": len(evidence_items),
        "findings_count": len(flat_findings),
        "timeline_count": 150 + 50 + 80 + 4,
    }
