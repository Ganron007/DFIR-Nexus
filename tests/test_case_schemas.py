"""Tests for the case stack schemas (P1.3)."""

from __future__ import annotations

from datetime import UTC, datetime

from nexus.case import (
    ApprovalState,
    AuditAction,
    AuditEntry,
    Case,
    CaseStatus,
    EvidenceRecord,
    Finding,
    FindingSeverity,
)


class TestCaseSchema:
    def test_case_to_from_dict(self) -> None:
        c = Case(
            id="CASE-ABC123",
            name="Test",
            description="desc",
            status=CaseStatus.OPEN,
            severity=FindingSeverity.HIGH,
            created_at=datetime.now(UTC),
            created_by="analyst",
        )
        d = c.to_dict()
        c2 = Case.from_dict(d)
        assert c.id == c2.id
        assert c.name == c2.name
        assert c.status == c2.status
        assert c.severity == c2.severity

    def test_case_new_id(self) -> None:
        cid = Case.new_id()
        assert cid.startswith("CASE-")
        assert len(cid) == 13

    def test_case_closed_round_trip(self) -> None:
        now = datetime.now(UTC)
        c = Case(
            id="CASE-1",
            name="Closed",
            description="d",
            status=CaseStatus.CLOSED,
            severity=FindingSeverity.LOW,
            created_at=now,
            created_by="a",
            closed_at=now,
            closed_by="b",
        )
        d = c.to_dict()
        c2 = Case.from_dict(d)
        assert c2.closed_at == now
        assert c2.closed_by == "b"


class TestFindingSchema:
    def test_finding_to_from_dict(self) -> None:
        f = Finding(
            id="FIND-1234",
            case_id="CASE-XYZ",
            title="LSASS",
            description="test",
            severity=FindingSeverity.CRITICAL,
            artifact_id=None,
            technique_ids=["T1003.001"],
            created_at=datetime.now(UTC),
            created_by="system",
        )
        d = f.to_dict()
        f2 = Finding.from_dict(d)
        assert f.id == f2.id
        assert f.technique_ids == f2.technique_ids
        assert f.approval_state == f2.approval_state

    def test_finding_new_id(self) -> None:
        fid = Finding.new_id()
        assert fid.startswith("FIND-")
        assert len(fid) == 13

    def test_finding_default_approval(self) -> None:
        f = Finding(
            id="FIND-D",
            case_id="CASE-1",
            title="t",
            description="d",
            severity=FindingSeverity.MEDIUM,
            artifact_id=None,
            technique_ids=[],
            created_at=datetime.now(UTC),
            created_by="a",
        )
        assert f.approval_state == ApprovalState.DRAFT


class TestEvidenceSchema:
    def test_evidence_to_from_dict(self) -> None:
        e = EvidenceRecord(
            id="EV-1",
            case_id="CASE-1",
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
        d = e.to_dict()
        e2 = EvidenceRecord.from_dict(d)
        assert e.id == e2.id
        assert e.file_hash_sha256 == e2.file_hash_sha256

    def test_evidence_new_id(self) -> None:
        eid = EvidenceRecord.new_id()
        assert eid.startswith("EV-")
        assert len(eid) == 11


class TestAuditEntrySchema:
    def test_audit_entry_to_from_dict(self) -> None:
        entry = AuditEntry(
            id="AUD-1234567890AB",
            case_id="CASE-1",
            action=AuditAction.CASE_CREATED,
            timestamp=datetime.now(UTC),
            actor="a",
            payload={"x": 1},
            prev_hash="0" * 64,
            hash="b" * 64,
            signature="c" * 64,
        )
        d = entry.to_dict()
        e2 = AuditEntry.from_dict(d)
        assert e2.action == AuditAction.CASE_CREATED
        assert e2.payload == {"x": 1}

    def test_audit_entry_new_id(self) -> None:
        aid = AuditEntry.new_id()
        assert aid.startswith("AUD-")
        assert len(aid) == 16


class TestSeverityNormalize:
    def test_severity_normalize(self) -> None:
        assert FindingSeverity.normalize("critical") == FindingSeverity.CRITICAL
        assert FindingSeverity.normalize(1) == FindingSeverity.CRITICAL
        assert FindingSeverity.normalize("2") == FindingSeverity.HIGH
        assert FindingSeverity.normalize("info") == FindingSeverity.INFORMATIONAL
        assert FindingSeverity.normalize(None) == FindingSeverity.INFORMATIONAL
        assert FindingSeverity.normalize("unknown") == FindingSeverity.INFORMATIONAL


class TestEnumValues:
    def test_case_status_values(self) -> None:
        assert CaseStatus.OPEN == "open"
        assert CaseStatus.IN_PROGRESS == "in_progress"
        assert CaseStatus.CLOSED == "closed"
        assert CaseStatus.ARCHIVED == "archived"

    def test_approval_state_values(self) -> None:
        assert ApprovalState.DRAFT == "draft"
        assert ApprovalState.PENDING_REVIEW == "pending_review"
        assert ApprovalState.APPROVED == "approved"
        assert ApprovalState.REJECTED == "rejected"

    def test_audit_action_values(self) -> None:
        assert AuditAction.CASE_CREATED == "case_created"
        assert AuditAction.FINDING_APPROVED == "finding_approved"
