"""Tests for the DRAFT / HITL approval workflow (P1.6)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from nexus.case import (
    ApprovalError,
    ApprovalLockedError,
    ApprovalPasswordError,
    ApprovalState,
    ApprovalWorkflow,
    Case,
    CaseStatus,
    Finding,
    FindingSeverity,
    SQLiteStore,
)


@pytest.fixture
def workflow() -> ApprovalWorkflow:
    return ApprovalWorkflow()


@pytest.fixture
def case_and_finding() -> tuple[Case, Finding]:
    case = Case(
        id="CASE-1",
        name="INC-APW",
        description="approval test",
        status=CaseStatus.OPEN,
        severity=FindingSeverity.HIGH,
        created_at=datetime.now(UTC),
        created_by="analyst",
    )
    finding = Finding(
        id="FIND-1",
        case_id=case.id,
        title="Suspicious login",
        description="anomalous logon",
        severity=FindingSeverity.HIGH,
        artifact_id=None,
        technique_ids=["T1078"],
        created_at=datetime.now(UTC),
        created_by="system",
        approval_state=ApprovalState.DRAFT,
    )
    return case, finding


class TestApprovalWorkflow:
    def test_set_case_password_stores_hash(
        self, workflow: ApprovalWorkflow, case_and_finding: tuple[Case, Finding]
    ) -> None:
        case, _ = case_and_finding
        workflow.set_case_password(case, "hunter2")
        assert case.approval_password_hash is not None
        assert case.approval_password_salt is not None
        assert case.approval_iterations == 600_000
        assert len(case.approval_password_hash) == 64

    def test_approve_finding(
        self, workflow: ApprovalWorkflow, case_and_finding: tuple[Case, Finding]
    ) -> None:
        case, finding = case_and_finding
        workflow.set_case_password(case, "secret")
        approved = workflow.approve(case, finding, "secret", approved_by="lead")
        assert approved.approval_state == ApprovalState.APPROVED
        assert approved.approved_by == "lead"
        assert approved.hmac_signature is not None
        assert approved.hmac_salt is not None

    def test_approve_with_wrong_password_locks(
        self, workflow: ApprovalWorkflow, case_and_finding: tuple[Case, Finding]
    ) -> None:
        case, finding = case_and_finding
        workflow.set_case_password(case, "secret")
        for _ in range(3):
            with pytest.raises(ApprovalPasswordError):
                workflow.approve(case, finding, "wrong", approved_by="lead")
        with pytest.raises(ApprovalLockedError):
            workflow.approve(case, finding, "wrong", approved_by="lead")

    def test_approve_resets_lockout_on_success(
        self, workflow: ApprovalWorkflow, case_and_finding: tuple[Case, Finding]
    ) -> None:
        case, finding = case_and_finding
        workflow.set_case_password(case, "secret")
        with pytest.raises(ApprovalPasswordError):
            workflow.approve(case, finding, "wrong")
        approved = workflow.approve(case, finding, "secret")
        assert approved.approval_state == ApprovalState.APPROVED
        with pytest.raises(ApprovalPasswordError):
            workflow.approve(case, finding, "wrong")

    def test_reject_finding(
        self, workflow: ApprovalWorkflow, case_and_finding: tuple[Case, Finding]
    ) -> None:
        case, finding = case_and_finding
        workflow.set_case_password(case, "secret")
        rejected = workflow.reject(
            case, finding, "secret", reason="False positive"
        )
        assert rejected.approval_state == ApprovalState.REJECTED
        assert rejected.rejection_reason == "False positive"
        assert rejected.rejected_by == "system"

    def test_verify_finding_signature(
        self, workflow: ApprovalWorkflow, case_and_finding: tuple[Case, Finding]
    ) -> None:
        case, finding = case_and_finding
        workflow.set_case_password(case, "secret")
        workflow.approve(case, finding, "secret", approved_by="lead")
        assert workflow.verify_finding_signature(case, finding, "secret") is True
        assert workflow.verify_finding_signature(case, finding, "wrong") is False

    def test_tampered_finding_fails_signature(
        self, workflow: ApprovalWorkflow, case_and_finding: tuple[Case, Finding]
    ) -> None:
        case, finding = case_and_finding
        workflow.set_case_password(case, "secret")
        workflow.approve(case, finding, "secret")
        finding.title = "Changed title"
        assert workflow.verify_finding_signature(case, finding, "secret") is False

    def test_no_password_set_raises(
        self, workflow: ApprovalWorkflow, case_and_finding: tuple[Case, Finding]
    ) -> None:
        case, finding = case_and_finding
        with pytest.raises(ApprovalError):
            workflow.approve(case, finding, "secret")


class TestApprovalPersistence:
    def test_approved_finding_persists_and_verifies(self, tmp_path: Path) -> None:
        db = tmp_path / "cases.db"
        store = SQLiteStore(db)
        workflow = ApprovalWorkflow()
        case = Case(
            id="CASE-P1",
            name="INC-Persist",
            description="persist",
            status=CaseStatus.OPEN,
            severity=FindingSeverity.MEDIUM,
            created_at=datetime.now(UTC),
            created_by="analyst",
        )
        store.save_case(case)
        workflow.set_case_password(case, "secret")
        store.save_case(case)

        finding = Finding(
            id="FIND-P1",
            case_id=case.id,
            title="Bad thing",
            description="details",
            severity=FindingSeverity.HIGH,
            artifact_id=None,
            technique_ids=["T1003"],
            created_at=datetime.now(UTC),
            created_by="system",
            approval_state=ApprovalState.DRAFT,
        )
        store.save_finding(finding)
        workflow.approve(case, finding, "secret", approved_by="lead")
        store.save_finding(finding)
        store.close()

        store2 = SQLiteStore(db)
        case2 = store2.get_case(case.id)
        finding2 = store2.get_finding(finding.id)
        assert case2 is not None
        assert finding2 is not None
        assert finding2.approval_state == ApprovalState.APPROVED
        assert finding2.hmac_signature is not None
        assert workflow.verify_finding_signature(case2, finding2, "secret") is True
        store2.close()

    def test_rejected_finding_clears_signature(self, tmp_path: Path) -> None:
        store = SQLiteStore(tmp_path / "cases.db")
        workflow = ApprovalWorkflow()
        case = Case(
            id="CASE-P2",
            name="INC-Reject",
            description="reject",
            status=CaseStatus.OPEN,
            severity=FindingSeverity.LOW,
            created_at=datetime.now(UTC),
            created_by="analyst",
        )
        store.save_case(case)
        workflow.set_case_password(case, "secret")
        finding = Finding(
            id="FIND-P2",
            case_id=case.id,
            title="Maybe bad",
            description="details",
            severity=FindingSeverity.LOW,
            artifact_id=None,
            technique_ids=[],
            created_at=datetime.now(UTC),
            created_by="system",
            approval_state=ApprovalState.DRAFT,
        )
        store.save_finding(finding)
        workflow.approve(case, finding, "secret")
        assert finding.hmac_signature is not None
        workflow.reject(case, finding, "secret", reason="FP")
        assert finding.approval_state == ApprovalState.REJECTED
        assert finding.hmac_signature is None
        assert finding.hmac_salt is None
        store.close()
