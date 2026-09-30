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


# A demo case still needs a real approval, so it needs a real password.
# Documented, not secret: it protects a fixture and is regenerated on every
# seed, exactly like the demo data it signs.
_DEMO_APPROVAL_PASSWORD = "nexus-demo-fixture-approval"


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
    from nexus.case.schemas import CaseStatus, FindingSeverity

    db_path = settings.cases_root / "cases.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    mgr = CaseManager(db_path)

    # Clean up existing demo case if present to ensure a fresh, consistent seed
    existing = mgr.store.get_case(case_id)
    if existing:
        mgr.delete_case(case_id)

    # The demo case is a generated fixture that this seeder owns: a re-seed
    # resets its directory so real-path staging never appends into stale
    # findings from a previous seed.
    case_dir_stale = settings.cases_root / case_id
    if case_dir_stale.is_dir():
        import shutil

        shutil.rmtree(case_dir_stale)

    case = mgr.create_case(
        name=case_name,
        description="Assumed-breach incident simulation — credential access, lateral movement & persistence",
        severity=FindingSeverity.HIGH,
        created_by=examiner,
        tags=["campaign-h", "active-directory", "assumed-breach", "demo"],
        metadata={"investigation_mode": "1", "examiner": examiner, "synthetic": True},
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
        "mode_scheme": 2,
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

    # 3. Real audit trail: one tool-run entry per parser family, written by the
    # same AuditWriter the pipeline uses (chain-hashed, per-case dir). The
    # demo findings cite these ids — FD-001 is satisfied by *real* entries,
    # not by strings the seeder invented.
    from nexus.audit import AuditWriter

    audit_writer = AuditWriter("nexus-demo", audit_dir=case_dir / "audit")

    def _tool_run(tool: str, purpose: str, extraction: str, rows: int) -> str | None:
        p = case_dir / "extractions" / extraction
        return audit_writer.log(
            tool=tool,
            params={"purpose": purpose, "target": f"extractions/{extraction}"},
            result_summary={"rows": rows, "output": f"extractions/{extraction}"},
            input_files=[str(p)],
            input_sha256s=[hashlib.sha256(p.read_bytes()).hexdigest()],
        )

    aud_evtx = _tool_run("EvtxECmd", "Security/System EVTX timeline", "evtx/evtx-timeline.csv", 150)
    aud_pf = _tool_run("PECmd", "Prefetch execution summary", "prefetch/prefetch-summary.csv", 8)
    aud_zeek = _tool_run("zeek_conn_reader", "Zeek connection log", "zeek/conn.csv", 80)
    aud_browser = _tool_run("browser_history", "Browser history CSV", "browser/history.csv", 4)

    # 4. Findings staged through the REAL staging path — CaseManager
    # .record_finding validates FD-001..007, enforces citation integrity
    # against the audit log written above, dual-writes the SQLite projection
    # and seals the DRAFT (WP 10.4). The seeder never writes findings.json.
    from nexus.case_manager import CaseManager as FlatCaseManager

    flat = FlatCaseManager()

    def _stage(
        title: str,
        observation: str,
        interpretation: str,
        technique: str,
        confidence: str,
        severity: str,
        audit_ids: list[str | None],
        evidence: list[dict[str, str]],
        examiner_selected: bool = False,
    ) -> dict[str, Any] | None:
        """Stage one DRAFT via record_finding; returns the stored entry."""
        ids = [a for a in audit_ids if a]
        result = flat.record_finding(
            {
                "title": title,
                "observation": observation,
                "interpretation": interpretation,
                "confidence": confidence,
                "confidence_justification": (
                    "Demo fixture: corroborated across the cited parser "
                    "families by the seeded tool runs."
                ),
                "type": "execution" if technique.startswith("T1") else "other",
                "severity": severity,
                "technique_ids": [technique],
                "audit_ids": ids,
                "evidence": evidence,
                "examiner_selected": examiner_selected,
                "scribe_source": "demo_seed",
                "confidence_source": "demo_seed",
            },
            examiner_override=examiner,
            artifacts=[{"type": "audit", "audit_id": a, "value": a, "source": ""} for a in ids],
            case_dir=case_dir,
        )
        if result.get("status") != "STAGED":
            log.warning("demo finding not staged (%s): %s", title, result.get("error"))
            return None
        fid = result["finding_id"]
        findings = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
        return next((f for f in findings if f["id"] == fid), None)

    staged: list[dict[str, Any]] = []

    staged.append(_stage(
        title="Encoded PowerShell Command Execution on WS01 Beachhead",
        observation=(
            "Event ID 4688 records powershell.exe invoked with an encoded "
            "command containing a web download cradle, user analyst_t1 on "
            "host WS01."
        ),
        interpretation=(
            "Obfuscated powershell.exe execution staged the initial dropper "
            "in memory on WS01 before any file landed on disk."
        ),
        technique="T1059.001",
        confidence="HIGH",
        severity="high",
        audit_ids=[aud_evtx, aud_pf],
        evidence=[
            {"type": "row", "source": "evtx/evtx-timeline.csv",
             "detail": "powershell.exe -enc SQBFAFgA ... EventID 4688 on WS01.CADRE.LOCAL"},
            {"type": "row", "source": "prefetch/prefetch-summary.csv",
             "detail": "POWERSHELL.EXE run count 42, last run within the incident window"},
        ],
        examiner_selected=True,
    ))

    staged.append(_stage(
        title="Kerberos Ticket Requests Consistent with Overpass-the-Hash",
        observation=(
            "Repetitive Kerberos TGS traffic from 192.168.77.62 toward the "
            "DC followed failed logons for Administrator."
        ),
        interpretation=(
            "The 192.168.77.62 host requested Kerberos service tickets in a "
            "pattern consistent with pass-the-hash lateral movement."
        ),
        technique="T1550.002",
        confidence="HIGH",
        severity="medium",
        audit_ids=[aud_zeek, aud_evtx],
        evidence=[
            {"type": "row", "source": "zeek/conn.csv",
             "detail": "192.168.77.62 to 192.168.77.10:88 tcp krb service bursts"},
            {"type": "row", "source": "evtx/evtx-timeline.csv",
             "detail": "EventID 4625 failed logon on WS01, traffic source 192.168.77.62"},
        ],
        examiner_selected=False,
    ))

    approved_candidates: list[str] = []

    for spec in (
        {
            "title": "SMB Lateral Movement from Provisioning Host 192.168.77.60",
            "observation": (
                "High-volume SMB sessions from 192.168.77.60 targeting admin$ "
                "and c$ shares on MBR01, followed by a new service install."
            ),
            "interpretation": (
                "Psexec-style lateral movement from 192.168.77.60: PSEXESVC.exe "
                "appeared as an installed service on the target host."
            ),
            "technique": "T1021.002",
            "severity": "critical",
            "audit_ids": [aud_zeek, aud_evtx],
            "evidence": [
                {"type": "row", "source": "zeek/conn.csv",
                 "detail": "192.168.77.60 to 192.168.77.62:445 tcp smb, large transfers"},
                {"type": "row", "source": "evtx/evtx-timeline.csv",
                 "detail": "EventID 7045 new service PSEXESVC.exe installed on MBR01.CADRE.LOCAL"},
            ],
            "examiner_selected": True,
            "approve": True,
        },
        {
            "title": "Credential Access via Mimikatz and LSA Secret Extraction",
            "observation": (
                "Prefetch shows MIMIKATZ.EXE and SHARPDPAPI.EXE executed on "
                "WS01; the analyst browsed the mimikatz release page beforehand."
            ),
            "interpretation": (
                "MIMIKATZ.EXE execution on WS01 indicates LSASS memory scraping "
                "to harvest credentials, staged from the mimikatz release page."
            ),
            "technique": "T1003.001",
            "severity": "critical",
            "audit_ids": [aud_pf, aud_browser],
            "evidence": [
                {"type": "row", "source": "prefetch/prefetch-summary.csv",
                 "detail": "MIMIKATZ.EXE run count 3 from the staging volume"},
                {"type": "row", "source": "browser/history.csv",
                 "detail": "mimikatz release page visited before MIMIKATZ.EXE execution"},
            ],
            "examiner_selected": True,
            "approve": True,
        },
    ):
        entry = _stage(
            title=spec["title"],
            observation=spec["observation"],
            interpretation=spec["interpretation"],
            technique=spec["technique"],
            confidence="HIGH",
            severity=spec["severity"],
            audit_ids=spec["audit_ids"],
            evidence=spec["evidence"],
            examiner_selected=spec["examiner_selected"],
        )
        if entry:
            staged.append(entry)
            if spec["approve"]:
                approved_candidates.append(entry["id"])

    # The deliberate UNSUPPORTED example: every citation is real (L1.1 passes)
    # but the named executable appears in no indexed row, so L1.3 fails and the
    # verdict is UNSUPPORTED. It stays DRAFT to show the examiner exactly what
    # an override decision looks like on the Approval Desk.
    override_example = _stage(
        title=(
            "Persistence via DARKKILLCHAIN.EXE Run key "
            "(override example - L1 verdict UNSUPPORTED)"
        ),
        observation=(
            "A Run key entry allegedly launches DARKKILLCHAIN.EXE from "
            "C:\\Windows\\Temp on WS01 at user logon."
        ),
        interpretation=(
            "DARKKILLCHAIN.EXE persistence would re-launch the implant at "
            "every logon on WS01."
        ),
        technique="T1547.001",
        confidence="LOW",
        severity="medium",
        audit_ids=[aud_evtx, aud_pf],
        evidence=[
            {"type": "row", "source": "evtx/evtx-timeline.csv",
             "detail": "no row names DARKKILLCHAIN.EXE - the claim has no row"},
        ],
        examiner_selected=False,
    )
    if override_example:
        staged.append(override_example)

    # REJECTED demo finding through the real reject path (atomic, audited).
    rejected = _stage(
        title="Routine Scheduled Task Software Update",
        observation="Daily task execution for the enterprise system management agent.",
        interpretation=(
            "Baseline enterprise administrative activity on WS01, consistent "
            "with the deployed management agent."
        ),
        technique="T1053.005",
        confidence="LOW",
        severity="low",
        audit_ids=[aud_evtx, aud_pf],
        evidence=[
            {"type": "row", "source": "evtx/evtx-timeline.csv",
             "detail": "routine task execution entries for the management agent"},
        ],
        examiner_selected=True,
    )
    if rejected:
        from nexus.cli.main import _reject_finding

        _reject_finding(
            case_dir, rejected["id"], examiner,
            "Legitimate enterprise software management; verified against the "
            "lab baseline.",
        )
        rejected["status"] = "REJECTED"
        staged.append(rejected)

    # Approvals go through the real CLI approval service: seal verification,
    # L1 verdict at approval, verification-ledger + transparency entries —
    # the same function `nexus approve` calls after its password gate. The
    # password is documented (it protects a regenerated fixture), not secret.
    from nexus.analysis.claim_verification import verify_case
    from nexus.cli.approve import approve_finding

    # L1 replay against the demo's own indexed rows: the extraction files are
    # the same rows the CSV fallback (and, after indexing, Elasticsearch)
    # would answer from, so the verdict is a real replay in every
    # environment — not an environment-dependent pass.
    indexed_text = "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in sorted(extractions_dir.rglob("*.csv"))
    )
    ledger_rows = verify_case(case_dir, use_index=False, indexed_text=indexed_text)
    verdicts = {
        str(row.get("id") or ""): str(row.get("verdict") or "")
        for row in ledger_rows.get("claims") or []
    }
    approved_ids: list[str] = []
    for fid in approved_candidates:
        verdict = verdicts.get(fid, "")
        if verdict != "PROVEN":
            # Mirror the examiner gate: the demo never signs a non-PROVEN
            # draft — it stays DRAFT with its verdict visible instead.
            log.warning(
                "demo approval skipped for %s (L1 verdict %s, not PROVEN)",
                fid, verdict or "unknown",
            )
            continue
        result = approve_finding(
            case_dir, fid, examiner, _DEMO_APPROVAL_PASSWORD,
            note="demo fixture approval", l1_verdict=verdict,
        )
        if result.get("status") != "APPROVED":
            log.warning("demo approval refused for %s: %s", fid, result)
        else:
            approved_ids.append(fid)

    # 4. Seed IOCs
    iocs_data = [
        {"type": "ip", "value": "192.168.77.60", "finding_title": "Anomalous SMB Lateral Movement", "severity": "HIGH"},
        {"type": "sha256", "value": "4a7d1ed414474e4033ac29ccb8653d9b002c912efc464efc85e72d4cc98d1a3b", "finding_title": "Credential Access via Mimikatz", "severity": "CRITICAL"},
        {"type": "domain", "value": "raw.githubusercontent.com", "finding_title": "Encoded PowerShell Command Execution", "severity": "MEDIUM"},
        {"type": "file", "value": "PSEXESVC.exe", "finding_title": "SMB Lateral Movement from Provisioning Host", "severity": "HIGH"},
    ]
    (case_dir / "iocs.json").write_text(json.dumps(iocs_data, indent=2), encoding="utf-8")

    # 5. Seed TODOs
    todos_data = [
        {"todo_id": "TODO-001", "id": "TODO-001", "description": "Review Active Directory replication traffic on DC01 for DCSync indicators", "status": "OPEN", "priority": "HIGH", "assignee": examiner},
        {"todo_id": "TODO-002", "id": "TODO-002", "description": "Collect memory image from WS01 beachhead for injected shellcode verification", "status": "OPEN", "priority": "MEDIUM", "assignee": examiner},
        {"todo_id": "TODO-003", "id": "TODO-003", "description": "Isolate staging host 192.168.77.60 at the firewall boundary", "status": "COMPLETED", "priority": "HIGH", "assignee": examiner},
    ]
    (case_dir / "todos.json").write_text(json.dumps(todos_data, indent=2), encoding="utf-8")

    # 6. Seed Official Report Preview — the approved sections are rendered
    # from the findings actually staged and approved above, not hardcoded ids.
    approved_rows: list[str] = []
    for f in staged:
        if f["id"] not in approved_ids:
            continue
        witnesses = ", ".join(f"`{a}`" for a in f.get("audit_ids") or [])
        approved_rows.append(
            f"### {f['id']}: {f['title']}\n"
            f"- **Severity:** {str(f.get('severity') or '').upper()}\n"
            f"- **Technique:** MITRE ATT&CK {', '.join(f.get('technique_ids') or [])}\n"
            f"- **Approved by:** {f.get('approved_by')}\n"
            f"- **Observation:** {f.get('observation')}\n"
            f"- **Interpretation:** {f.get('interpretation')}\n"
            f"- **Audit Witnesses:** {witnesses}\n"
        )

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

## 3. Approved Findings

{chr(10).join(approved_rows) if approved_rows else "_No findings approved at seed time._"}
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

    # 7. Coherent pipeline state: the lane gate, the index state and the
    # coverage audit are written through the real writers so the gate banner,
    # the stepper and the L1 checks all read the same truth. Every extraction
    # family is OK — nothing is unprocessed, so the gate is clear.
    from nexus.langgraph.case_index import write_index_state
    from nexus.langgraph.lane_gate import write_lane_gate

    run_id = f"demo-{now.strftime('%Y%m%dT%H%M%S')}"
    ledger = [
        {"tool": "EvtxECmd", "purpose": "Security/System EVTX timeline",
         "status": "OK", "output": "extractions/evtx/evtx-timeline.csv"},
        {"tool": "PECmd", "purpose": "Prefetch execution summary",
         "status": "OK", "output": "extractions/prefetch/prefetch-summary.csv"},
        {"tool": "zeek_conn_reader", "purpose": "Zeek connection log",
         "status": "OK", "output": "extractions/zeek/conn.csv"},
        {"tool": "browser_history", "purpose": "Browser history CSV",
         "status": "OK", "output": "extractions/browser/history.csv"},
    ]
    write_lane_gate(case_dir, run_id, ledger)
    write_index_state(case_dir, {
        "docs": 150 + 8 + 80 + 4,
        "index": "",
        "capped": False,
        "caps": {},
    })
    try:
        from nexus.analysis.coverage_audit import build_coverage_audit

        coverage = build_coverage_audit(case_dir)
        (analysis_dir / "coverage_audit.json").write_text(
            json.dumps(coverage, indent=2), encoding="utf-8"
        )
    except Exception as exc:  # noqa: BLE001 - a missing audit is honest, not fatal
        log.info("demo coverage audit skipped: %s", exc)

    # Lifecycle: the demo is fully parsed → ACTIVE. SQLite is the system of
    # record; update_status mirrors the value into CASE.yaml (audit-chained).
    mgr.update_status(case.id, CaseStatus.ACTIVE, actor=examiner)

    # Activate only when requested — the portal previews cases on the
    # dashboard without switching away from the current investigation.
    if activate:
        set_active_case_id(case.id)
    mgr.close()

    log.info(
        "Successfully seeded demo case %s: %d findings staged via the real "
        "path (%d approved, 1 rejected, 1 UNSUPPORTED override example)",
        case.id, len(staged), len(approved_ids),
    )
    return {
        "ok": True,
        "case_id": case.id,
        "evidence_count": len(evidence_items),
        "findings_count": len(staged),
        "approved_count": len(approved_ids),
        "timeline_count": 150 + 50 + 80 + 4,
    }
