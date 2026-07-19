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
from nexus.case.compat import dict_to_case, dict_to_evidence, dict_to_finding


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


class TestGetSqliteManager:
    def test_creates_db_at_path(self, tmp_path: Path) -> None:
        db = tmp_path / "nest" / "cases.db"
        mgr = get_sqlite_manager(db)
        case = mgr.create_case(name="test")
        assert mgr.get_case(case.id) is not None
        assert db.exists()
        mgr.close()
