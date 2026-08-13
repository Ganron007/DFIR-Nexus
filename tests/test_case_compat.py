"""Tests for compat bridge (P1.8): dict converters, LegacyJsonImporter."""

from __future__ import annotations

import json
from pathlib import Path

from nexus.case import (
    ApprovalState,
    CaseManager,
    CaseStatus,
    FindingSeverity,
    LegacyJsonImporter,
    get_sqlite_manager,
)
from nexus.case.compat import dict_to_case, dict_to_evidence, dict_to_finding, sync_sqlite_to_flat


class TestDictConverters:
    def test_dict_to_case_minimal(self) -> None:
        d = {"id": "CASE-X", "name": "Test", "status": "open"}
        case = dict_to_case(d)
        assert case.id == "CASE-X"
        assert case.name == "Test"
        assert case.status == CaseStatus.OPEN
        assert case.severity == FindingSeverity.MEDIUM

    def test_dict_to_case_full(self) -> None:
        d = {
            "id": "CASE-Y",
            "name": "Full Case",
            "description": "desc",
            "status": "closed",
            "severity": "critical",
            "created_at": "2026-01-01T00:00:00+00:00",
            "created_by": "analyst",
            "tags": ["tag1"],
            "metadata": {"k": "v"},
        }
        case = dict_to_case(d)
        assert case.status == CaseStatus.CLOSED
        assert case.severity == FindingSeverity.CRITICAL
        assert case.tags == ["tag1"]
        assert case.metadata == {"k": "v"}

    def test_dict_to_finding(self) -> None:
        d = {
            "id": "FIND-1",
            "case_id": "CASE-A",
            "title": "Suspicious login",
            "observation": "anomaly detected",
            "interpretation": "likely breach",
            "status": "approved",
            "severity": "high",
            "mitre_techniques": ["T1078"],
            "confidence": "HIGH",
        }
        finding = dict_to_finding(d)
        assert finding.id == "FIND-1"
        assert finding.title == "Suspicious login"
        assert finding.description == "likely breach"
        assert finding.metadata.get("observation") == "anomaly detected"
        assert finding.metadata.get("interpretation") == "likely breach"
        assert finding.metadata.get("confidence") == "HIGH"
        assert finding.technique_ids == ["T1078"]
        assert finding.approval_state == ApprovalState.APPROVED
        assert finding.severity == FindingSeverity.HIGH

    def test_dict_to_evidence(self) -> None:
        d = {
            "case_id": "CASE-A",
            "path": "/evidence/dump.raw",
            "sha256": "abc" * 8,
            "description": "memory dump",
            "registered_at": "2026-06-01T12:00:00+00:00",
        }
        ev = dict_to_evidence(d)
        assert ev.case_id == "CASE-A"
        assert ev.file_hash_sha256 == "abc" * 8
        assert ev.file_path == "/evidence/dump.raw"
        assert ev.name == "dump.raw"


class TestLegacyJsonImporter:
    def test_import_case_with_findings_and_evidence(self, tmp_path: Path) -> None:
        case_dir = tmp_path / "CASE-IMP"
        case_dir.mkdir()
        (case_dir / "findings.json").write_text(json.dumps([
            {"id": "F-1", "title": "Suspicious login", "status": "draft",
             "observation": "found anomaly", "confidence": "HIGH",
             "mitre_techniques": ["T1078"]},
        ]))
        (case_dir / "evidence_registry.json").write_text(json.dumps([
            {"path": str(tmp_path / "dump.raw"), "sha256": "abc" * 8},
        ]))

        db_path = tmp_path / "cases.db"
        mgr = CaseManager(db_path, secret_key=b"test-key")
        importer = LegacyJsonImporter(mgr)
        case = importer.import_case(case_dir)
        assert case is not None
        assert case.id == "CASE-IMP"

        findings = mgr.list_findings("CASE-IMP")
        assert len(findings) == 1
        assert findings[0].title == "Suspicious login"

        evidence = mgr.list_evidence("CASE-IMP")
        assert len(evidence) == 1
        mgr.close()

    def test_import_all_cases(self, tmp_path: Path) -> None:
        cases_root = tmp_path / "legacy_cases"
        cases_root.mkdir()
        for cid in ("CASE-A", "CASE-B"):
            cd = cases_root / cid
            cd.mkdir()
            (cd / "findings.json").write_text(json.dumps([
                {"id": f"F-{cid}", "title": "test", "status": "draft"}
            ]))

        db_path = tmp_path / "cases.db"
        mgr = CaseManager(db_path, secret_key=b"test-key")
        importer = LegacyJsonImporter(mgr)
        stats = importer.import_all_cases(cases_root)
        assert set(stats.keys()) == {"CASE-A", "CASE-B"}
        assert all(v == 1 for v in stats.values())
        mgr.close()

    def test_import_empty_case_dir(self, tmp_path: Path) -> None:
        case_dir = tmp_path / "EMPTY-CASE"
        case_dir.mkdir()
        db_path = tmp_path / "cases.db"
        mgr = CaseManager(db_path, secret_key=b"test-key")
        importer = LegacyJsonImporter(mgr)
        # Should still create a case from directory name
        case = importer.import_case(case_dir)
        assert case is not None
        assert case.id == "EMPTY-CASE"
        mgr.close()


class TestSyncSqliteToFlat:
    def test_writes_findings_evidence_timeline(self, tmp_path: Path) -> None:
        db = tmp_path / "cases.db"
        dest = tmp_path / "CASE-SYNC"
        mgr = CaseManager(db, secret_key=b"test-key")
        case = mgr.create_case(name="Sync Me", case_id="CASE-SYNC", created_by="analyst")
        mgr.add_finding(
            case.id,
            title="LSASS dump",
            description="Vol3 psscan showed suspicious process",
            severity=FindingSeverity.HIGH,
            technique_ids=["T1003.001"],
            created_by="agent:timeline",
        )
        mgr.add_evidence(
            case.id,
            name="volatility: process",
            description="windows.psscan.json",
            file_path=str(tmp_path / "psscan.json"),
            file_hash_sha256="ab" * 32,
            collected_by="analyst",
            metadata={"host": "WS01", "dest_ip": "192.168.77.50"},
        )
        out = sync_sqlite_to_flat(case.id, mgr=mgr, case_dir=dest)
        assert out == dest
        findings = json.loads((dest / "findings.json").read_text(encoding="utf-8"))
        assert len(findings) == 1
        assert findings[0]["title"] == "LSASS dump"
        assert findings[0]["status"] == "DRAFT"
        assert findings[0]["mitre_ids"] == ["T1003.001"]
        assert findings[0]["observation"] == "Vol3 psscan showed suspicious process"
        assert findings[0]["interpretation"] == "Vol3 psscan showed suspicious process"
        evidence = json.loads((dest / "evidence.json").read_text(encoding="utf-8"))
        assert evidence[0]["host"] == "WS01"
        assert evidence[0]["dest_ip"] == "192.168.77.50"
        timeline = json.loads((dest / "timeline.json").read_text(encoding="utf-8"))
        assert timeline[0]["status"] == "APPROVED"
        iocs = json.loads((dest / "iocs.json").read_text(encoding="utf-8"))
        assert any(x["value"] == "192.168.77.50" for x in iocs["ip"])
        mgr.close()

    def test_sync_preserves_observation_and_interpretation(self, tmp_path: Path) -> None:
        db = tmp_path / "cases.db"
        dest = tmp_path / "CASE-NARR"
        mgr = CaseManager(db, secret_key=b"test-key")
        case = mgr.create_case(name="Narr", case_id="CASE-NARR", created_by="analyst")
        finding = dict_to_finding({
            "id": "F-e2e-host-001",
            "case_id": case.id,
            "title": "SRUM network usage",
            "observation": "NetworkUsages.csv shows bytes to 8.8.8.8",
            "interpretation": (
                "Possible data staging. Insider Threat Matrix (Means): Web Access."
            ),
            "status": "draft",
            "severity": "medium",
            "attack_ids": ["T1071"],
            "confidence": "HIGH",
            "confidence_justification": "SRUM CSV row",
            "itm_stage": "Means",
            "itm_objects": ["Web Access"],
        })
        mgr.store.save_finding(finding)
        out = sync_sqlite_to_flat(case.id, mgr=mgr, case_dir=dest)
        rows = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        assert rows[0]["observation"] == "NetworkUsages.csv shows bytes to 8.8.8.8"
        assert "Insider Threat Matrix" in rows[0]["interpretation"]
        assert rows[0]["itm_stage"] == "Means"
        assert rows[0]["confidence"] == "HIGH"
        mgr.close()


class TestGetSqliteManager:
    def test_creates_db_at_path(self, tmp_path: Path) -> None:
        db = tmp_path / "nest" / "cases.db"
        mgr = get_sqlite_manager(db)
        case = mgr.create_case(name="test")
        assert mgr.get_case(case.id) is not None
        assert db.exists()
        mgr.close()
