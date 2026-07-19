"""Tests for the CaseManager high-level CRUD (P1.7)."""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nexus.case import (
    ApprovalLockedError,
    ApprovalPasswordError,
    ApprovalState,
    CaseManager,
    CaseStatus,
    FindingSeverity,
)
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "cases.db"


@pytest.fixture
def mgr(tmp_db: Path) -> Generator[CaseManager, None, None]:
    manager = CaseManager(tmp_db, secret_key=b"test-secret")
    yield manager
    manager.close()


class TestCaseManager:
    def test_create_case(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-001", description="test", severity=FindingSeverity.HIGH)
        assert case.name == "INC-001"
        assert case.status == CaseStatus.OPEN
        assert case.severity == FindingSeverity.HIGH

    def test_get_case(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-GET")
        fetched = mgr.get_case(case.id)
        assert fetched is not None
        assert fetched.id == case.id
        assert mgr.get_case("CASE-MISSING") is None

    def test_list_cases(self, mgr: CaseManager) -> None:
        c1 = mgr.create_case(name="INC-1")
        c2 = mgr.create_case(name="INC-2")
        cases = mgr.list_cases()
        assert {c.id for c in cases} == {c1.id, c2.id}

    def test_list_cases_by_status(self, mgr: CaseManager) -> None:
        open_case = mgr.create_case(name="OPEN")
        closed_case = mgr.create_case(name="CLOSED")
        mgr.close_case(closed_case.id)
        open_cases = mgr.list_cases(status=CaseStatus.OPEN)
        closed_cases = mgr.list_cases(status=CaseStatus.CLOSED)
        assert len(open_cases) == 1
        assert open_cases[0].id == open_case.id
        assert len(closed_cases) == 1
        assert closed_cases[0].id == closed_case.id

    def test_close_case(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-CLOSE")
        closed = mgr.close_case(case.id, closed_by="lead")
        assert closed is not None
        assert closed.status == CaseStatus.CLOSED
        assert closed.closed_by == "lead"
        assert closed.closed_at is not None

    def test_delete_case(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-DEL")
        mgr.add_finding(case.id, "F1")
        assert mgr.delete_case(case.id) is True
        assert mgr.get_case(case.id) is None
        assert mgr.list_findings(case.id) == []

    def test_add_finding(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-FIND")
        finding = mgr.add_finding(
            case.id,
            "Suspicious login",
            severity=FindingSeverity.HIGH,
            technique_ids=["T1078"],
        )
        assert finding is not None
        assert finding.case_id == case.id
        assert finding.severity == FindingSeverity.HIGH
        assert finding.approval_state == ApprovalState.DRAFT

    def test_add_finding_always_starts_as_draft(
        self, mgr: CaseManager
    ) -> None:
        case = mgr.create_case(name="INC-BLOCK")
        finding = mgr.add_finding(case.id, "Needs review", initial_state=ApprovalState.APPROVED)
        assert finding is not None
        assert finding.approval_state == ApprovalState.DRAFT
        assert finding.metadata.get("auto_approve_blocked") is True

    def test_approve_finding_persists(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-APP")
        mgr.set_case_approval_password(case.id, "secret")
        finding = mgr.add_finding(case.id, "Suspicious login")
        assert finding is not None
        approved = mgr.approve_finding(finding.id, "secret", approved_by="lead")
        assert approved is not None
        assert approved.approval_state == ApprovalState.APPROVED
        assert approved.hmac_signature is not None

        # Reopen manager and verify persistence
        mgr2 = CaseManager(mgr.store.db_path, secret_key=b"test-secret")
        finding2 = mgr2.get_finding(finding.id)
        assert finding2 is not None
        assert finding2.approval_state == ApprovalState.APPROVED
        ok, errors = mgr2.verify_approval_signatures(case.id, "secret")
        assert ok, errors
        mgr2.close()

    def test_wrong_password_via_manager(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-WRG")
        mgr.set_case_approval_password(case.id, "secret")
        finding = mgr.add_finding(case.id, "Suspicious login")
        assert finding is not None
        with pytest.raises(ApprovalPasswordError):
            mgr.approve_finding(finding.id, "wrong")

    def test_approve_lockout_via_manager(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-LOCK")
        mgr.set_case_approval_password(case.id, "secret")
        finding = mgr.add_finding(case.id, "Suspicious login")
        assert finding is not None
        for _ in range(3):
            with pytest.raises(ApprovalPasswordError):
                mgr.approve_finding(finding.id, "wrong")
        with pytest.raises(ApprovalLockedError):
            mgr.approve_finding(finding.id, "wrong")

    def test_reject_finding(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-REJ")
        mgr.set_case_approval_password(case.id, "secret")
        finding = mgr.add_finding(case.id, "Maybe bad")
        assert finding is not None
        rejected = mgr.reject_finding(finding.id, "secret", reason="False positive")
        assert rejected is not None
        assert rejected.approval_state == ApprovalState.REJECTED
        assert rejected.rejection_reason == "False positive"

    def test_review_queue(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-QUEUE")
        f1 = mgr.add_finding(case.id, "Draft 1", initial_state=ApprovalState.DRAFT)
        f2 = mgr.add_finding(case.id, "Draft 2", initial_state=ApprovalState.DRAFT)
        assert f1 is not None and f2 is not None
        f3 = mgr.add_finding(case.id, "Requested approved", initial_state=ApprovalState.APPROVED)
        assert f3 is not None and f3.approval_state == ApprovalState.DRAFT
        queue = mgr.list_review_queue(case.id)
        assert len(queue) == 3
        assert {f.id for f in queue} == {f1.id, f2.id, f3.id}

    def test_audit_log_includes_approval(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-AUD")
        mgr.set_case_approval_password(case.id, "secret")
        finding = mgr.add_finding(case.id, "Suspicious login")
        assert finding is not None
        mgr.approve_finding(finding.id, "secret", approved_by="lead")
        log = mgr.get_audit_log(case.id)
        actions = [e.action.value for e in log]
        assert "case_created" in actions
        assert "finding_recorded" in actions
        assert "finding_approved" in actions

    def test_add_evidence(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-EV")
        evidence = mgr.add_evidence(
            case.id,
            "Memory dump",
            file_path="/evidence/dump.raw",
            file_hash_sha256="abc" * 8,
        )
        assert evidence is not None
        assert evidence.case_id == case.id
        assert evidence.name == "Memory dump"
        assert mgr.list_evidence(case.id)[0].id == evidence.id

    def test_add_evidence_from_artifact(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-ART")
        artifact = Artifact(
            id="art-1",
            artifact_type=ArtifactType.NETWORK,
            source=ArtifactSource.ZEEK,
            timestamp=datetime.now(UTC),
            severity=Severity.HIGH,
            description="C2 beacon",
            host="mbr01",
            user="analyst",
            technique_ids=["T1071"],
        )
        evidence = mgr.add_evidence_from_artifact(case.id, artifact, collected_by="system")
        assert evidence is not None
        assert evidence.artifact_id == artifact.id
        assert evidence.metadata.get("host") == "mbr01"

    def test_verify_audit_chain(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-CHAIN")
        mgr.add_finding(case.id, "F1")
        ok, errors = mgr.verify_audit_chain(case.id)
        assert ok, errors

    def test_verify_audit_chain_detects_tamper(self, mgr: CaseManager) -> None:
        case = mgr.create_case(name="INC-TAMPER")
        mgr.add_finding(case.id, "F1")
        # Tamper with the stored audit entry
        entries = mgr.store.list_audit_entries(case.id)
        assert entries
        seq, entry = entries[0]
        entry.payload["tampered"] = True
        mgr.store.save_audit_entry(case.id, seq, entry)
        ok, errors = mgr.verify_audit_chain(case.id)
        assert not ok
        assert len(errors) > 0

    def test_add_finding_missing_case_returns_none(self, mgr: CaseManager) -> None:
        assert mgr.add_finding("CASE-MISSING", "F1") is None

    def test_approve_missing_finding_returns_none(self, mgr: CaseManager) -> None:
        assert mgr.approve_finding("FIND-MISSING", "secret") is None
