"""Tests for the SQLite case store (P1.4)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from nexus.case import (
    AuditAction,
    AuditEntry,
    Case,
    CaseStatus,
    EvidenceRecord,
    Finding,
    FindingSeverity,
    SQLiteStore,
)


@pytest.fixture
def store(tmp_path: Path) -> SQLiteStore:
    db = tmp_path / "test.db"
    s = SQLiteStore(db)
    yield s
    s.close()


def test_schema_creation(store: SQLiteStore) -> None:
    rows = store._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    ).fetchall()
    names = {r["name"] for r in rows}
    assert "cases" in names
    assert "findings" in names
    assert "evidence" in names
    assert "audit_log" in names


def test_case_roundtrip(store: SQLiteStore) -> None:
    case = Case(
        id="CASE-T1",
        name="Test",
        description="d",
        status=CaseStatus.OPEN,
        severity=FindingSeverity.HIGH,
        created_at=datetime.now(UTC),
        created_by="analyst",
        tags=["apt29"],
        metadata={"campaign": "test"},
    )
    store.save_case(case)
    store.close()

    store2 = SQLiteStore(store.db_path)
    case2 = store2.get_case("CASE-T1")
    assert case2 is not None
    assert case2.name == "Test"
    assert case2.severity == FindingSeverity.HIGH
    assert case2.tags == ["apt29"]
    store2.close()


def test_list_cases(store: SQLiteStore) -> None:
    for i in range(3):
        case = Case(
            id=f"CASE-{i}",
            name=f"Case {i}",
            description="",
            status=CaseStatus.OPEN,
            severity=FindingSeverity.MEDIUM,
            created_at=datetime.now(UTC),
            created_by="a",
        )
        store.save_case(case)
    cases = store.list_cases()
    assert len(cases) == 3


def test_list_cases_by_status(store: SQLiteStore) -> None:
    open_case = Case(
        id="CASE-OPEN",
        name="Open",
        description="",
        status=CaseStatus.OPEN,
        severity=FindingSeverity.MEDIUM,
        created_at=datetime.now(UTC),
        created_by="a",
    )
    closed_case = Case(
        id="CASE-CLOSED",
        name="Closed",
        description="",
        status=CaseStatus.CLOSED,
        severity=FindingSeverity.LOW,
        created_at=datetime.now(UTC),
        created_by="a",
    )
    store.save_case(open_case)
    store.save_case(closed_case)
    open_cases = store.list_cases(status=CaseStatus.OPEN)
    closed_cases = store.list_cases(status=CaseStatus.CLOSED)
    assert len(open_cases) == 1
    assert open_cases[0].id == "CASE-OPEN"
    assert len(closed_cases) == 1
    assert closed_cases[0].id == "CASE-CLOSED"


def test_delete_case(store: SQLiteStore) -> None:
    case = Case(
        id="CASE-D",
        name="D",
        description="",
        status=CaseStatus.OPEN,
        severity=FindingSeverity.MEDIUM,
        created_at=datetime.now(UTC),
        created_by="a",
    )
    store.save_case(case)
    assert store.delete_case("CASE-D") is True
    assert store.get_case("CASE-D") is None


def test_finding_roundtrip(store: SQLiteStore) -> None:
    case = Case(
        id="CASE-F",
        name="F",
        description="",
        status=CaseStatus.OPEN,
        severity=FindingSeverity.MEDIUM,
        created_at=datetime.now(UTC),
        created_by="a",
    )
    store.save_case(case)
    finding = Finding(
        id="FIND-1",
        case_id="CASE-F",
        title="LSASS",
        description="test",
        severity=FindingSeverity.CRITICAL,
        artifact_id=None,
        technique_ids=["T1003.001"],
        created_at=datetime.now(UTC),
        created_by="system",
    )
    store.save_finding(finding)
    findings = store.list_findings("CASE-F")
    assert len(findings) == 1
    assert findings[0].title == "LSASS"
    assert findings[0].severity == FindingSeverity.CRITICAL


def test_get_finding(store: SQLiteStore) -> None:
    case = Case(
        id="CASE-G",
        name="G",
        description="",
        status=CaseStatus.OPEN,
        severity=FindingSeverity.MEDIUM,
        created_at=datetime.now(UTC),
        created_by="a",
    )
    store.save_case(case)
    finding = Finding(
        id="FIND-G",
        case_id="CASE-G",
        title="t",
        description="d",
        severity=FindingSeverity.HIGH,
        artifact_id=None,
        technique_ids=[],
        created_at=datetime.now(UTC),
        created_by="a",
    )
    store.save_finding(finding)
    fetched = store.get_finding("FIND-G")
    assert fetched is not None
    assert fetched.id == "FIND-G"
    assert store.get_finding("FIND-MISSING") is None


def test_evidence_roundtrip(store: SQLiteStore) -> None:
    case = Case(
        id="CASE-E",
        name="E",
        description="",
        status=CaseStatus.OPEN,
        severity=FindingSeverity.MEDIUM,
        created_at=datetime.now(UTC),
        created_by="a",
    )
    store.save_case(case)
    evidence = EvidenceRecord(
        id="EV-1",
        case_id="CASE-E",
        artifact_id="ART-1",
        name="dump",
        description="memory dump",
        file_path="/evidence/dump.raw",
        file_hash_md5=None,
        file_hash_sha1=None,
        file_hash_sha256="abc" * 8,
        collected_at=datetime.now(UTC),
        collected_by="system",
    )
    store.save_evidence(evidence)
    evidence_list = store.list_evidence("CASE-E")
    assert len(evidence_list) == 1
    assert evidence_list[0].file_hash_sha256 == "abc" * 8


def test_audit_log_persistence(store: SQLiteStore) -> None:
    case = Case(
        id="CASE-A1",
        name="Audit Test",
        description="",
        status=CaseStatus.OPEN,
        severity=FindingSeverity.MEDIUM,
        created_at=datetime.now(UTC),
        created_by="a",
    )
    store.save_case(case)
    for seq in (1, 2):
        entry = AuditEntry(
            id=f"AUD-{seq:04d}",
            case_id="CASE-A1",
            action=AuditAction.CASE_CREATED if seq == 1 else AuditAction.CASE_CLOSED,
            timestamp=datetime.now(UTC),
            actor="a",
            payload={"seq": seq},
            prev_hash="0" * 64 if seq == 1 else "a" * 64,
            hash="b" * 64,
            signature="b" * 64,
        )
        store.save_audit_entry("CASE-A1", seq, entry)
    store.close()

    store2 = SQLiteStore(store.db_path)
    entries = store2.list_audit_entries("CASE-A1")
    assert len(entries) == 2
    assert entries[0][0] == 1
    assert entries[1][0] == 2
    assert entries[0][1].action == AuditAction.CASE_CREATED
    store2.close()


def test_cascade_delete(store: SQLiteStore) -> None:
    case = Case(
        id="CASE-CASCADE",
        name="Cascade",
        description="",
        status=CaseStatus.OPEN,
        severity=FindingSeverity.MEDIUM,
        created_at=datetime.now(UTC),
        created_by="a",
    )
    store.save_case(case)
    finding = Finding(
        id="FIND-C",
        case_id="CASE-CASCADE",
        title="t",
        description="d",
        severity=FindingSeverity.HIGH,
        artifact_id=None,
        technique_ids=[],
        created_at=datetime.now(UTC),
        created_by="a",
    )
    store.save_finding(finding)
    evidence = EvidenceRecord(
        id="EV-C",
        case_id="CASE-CASCADE",
        artifact_id=None,
        name="e",
        description="d",
        file_path=None,
        file_hash_md5=None,
        file_hash_sha1=None,
        file_hash_sha256=None,
        collected_at=datetime.now(UTC),
        collected_by="a",
    )
    store.save_evidence(evidence)
    entry = AuditEntry(
        id="AUD-C",
        case_id="CASE-CASCADE",
        action=AuditAction.CASE_CREATED,
        timestamp=datetime.now(UTC),
        actor="a",
        payload={},
        prev_hash="0" * 64,
        hash="b" * 64,
        signature="b" * 64,
    )
    store.save_audit_entry("CASE-CASCADE", 1, entry)

    assert store.delete_case("CASE-CASCADE") is True
    assert store.list_findings("CASE-CASCADE") == []
    assert store.list_evidence("CASE-CASCADE") == []
    assert store.list_audit_entries("CASE-CASCADE") == []
