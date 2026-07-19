"""CaseManager — high-level CRUD over cases, findings, evidence, and audit.

Wraps the SQLiteStore and AuditChain together. All write operations are
appended to the audit chain automatically.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.case.approval import get_default_workflow
from nexus.case.audit import AuditChain
from nexus.case.schemas import (
    ApprovalState,
    AuditAction,
    AuditEntry,
    Case,
    CaseStatus,
    EvidenceRecord,
    Finding,
    FindingSeverity,
)
from nexus.case.secrets import get_audit_secret
from nexus.case.store import SQLiteStore
from nexus.ingest.schemas import Artifact

log = logging.getLogger(__name__)


class CaseManager:
    """High-level case management.

    Usage:
        mgr = CaseManager(db_path="./data/cases.db")
        case = mgr.create_case(name="INC-001", description="...", severity=FindingSeverity.HIGH)
        mgr.add_finding(case.id, title="LSASS dump", severity=FindingSeverity.CRITICAL, ...)
        mgr.add_evidence_from_artifact(case.id, artifact, collected_by="analyst")
        mgr.close_case(case.id, closed_by="lead")
        ok, errors = mgr.verify_audit_chain(case.id)
    """

    def __init__(self, db_path: Path | str, secret_key: bytes | None = None) -> None:
        self.store = SQLiteStore(db_path)
        self._secret_key = secret_key if secret_key is not None else get_audit_secret()
        self._approval = get_default_workflow()

    def close(self) -> None:
        """Close the underlying database."""
        self.store.close()

    # =============================================================
    # Case operations
    # =============================================================

    def create_case(
        self,
        name: str,
        description: str = "",
        severity: FindingSeverity = FindingSeverity.MEDIUM,
        created_by: str = "system",
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Case:
        """Create a new case and append a CASE_CREATED entry to the audit chain."""
        case = Case(
            id=Case.new_id(),
            name=name,
            description=description,
            status=CaseStatus.OPEN,
            severity=FindingSeverity.normalize(severity),
            created_at=datetime.now(UTC),
            created_by=created_by,
            tags=list(tags or []),
            metadata=dict(metadata or {}),
        )
        self.store.save_case(case)
        chain = self._load_audit_chain(case.id)
        chain.append(
            AuditAction.CASE_CREATED,
            actor=created_by,
            payload={
                "case_id": case.id,
                "name": case.name,
                "severity": case.severity.value,
                "description": description[:200],
            },
        )
        self._save_audit_chain(chain)
        return case

    def get_case(self, case_id: str) -> Case | None:
        """Fetch a case by ID."""
        return self.store.get_case(case_id)

    def list_cases(self, status: CaseStatus | None = None) -> list[Case]:
        """List all cases, optionally filtered by status."""
        return self.store.list_cases(status.value if status else None)

    def update_status(
        self,
        case_id: str,
        status: CaseStatus,
        actor: str = "system",
    ) -> Case | None:
        """Update a case's status."""
        case = self.store.get_case(case_id)
        if case is None:
            return None
        old_status = case.status
        case.status = status
        self.store.save_case(case)
        chain = self._load_audit_chain(case_id)
        chain.append(
            AuditAction.CASE_STATUS_CHANGED,
            actor=actor,
            payload={
                "case_id": case_id,
                "old_status": old_status.value,
                "new_status": status.value,
            },
        )
        self._save_audit_chain(chain)
        return case

    def close_case(self, case_id: str, closed_by: str = "system") -> Case | None:
        """Close a case (set status=closed, record closed_at)."""
        case = self.store.get_case(case_id)
        if case is None:
            return None
        if case.status == CaseStatus.CLOSED:
            return case
        case.status = CaseStatus.CLOSED
        case.closed_at = datetime.now(UTC)
        case.closed_by = closed_by
        self.store.save_case(case)
        chain = self._load_audit_chain(case_id)
        chain.append(
            AuditAction.CASE_CLOSED,
            actor=closed_by,
            payload={"case_id": case_id, "closed_at": case.closed_at.isoformat()},
        )
        self._save_audit_chain(chain)
        return case

    def delete_case(self, case_id: str) -> bool:
        """Delete a case (and all its findings/evidence/audit log)."""
        return self.store.delete_case(case_id)

    # =============================================================
    # Finding operations
    # =============================================================

    def add_finding(
        self,
        case_id: str,
        title: str,
        description: str = "",
        severity: FindingSeverity = FindingSeverity.MEDIUM,
        artifact_id: str | None = None,
        technique_ids: list[str] | None = None,
        created_by: str = "system",
        metadata: dict[str, Any] | None = None,
        initial_state: ApprovalState = ApprovalState.DRAFT,
    ) -> Finding | None:
        """Record a finding against a case."""
        case = self.store.get_case(case_id)
        if case is None:
            return None
        meta = dict(metadata or {})
        effective_state = initial_state
        if initial_state == ApprovalState.APPROVED:
            effective_state = ApprovalState.DRAFT
            meta["auto_approve_blocked"] = True
        finding = Finding(
            id=Finding.new_id(),
            case_id=case_id,
            title=title,
            description=description,
            severity=FindingSeverity.normalize(severity),
            artifact_id=artifact_id,
            technique_ids=list(technique_ids or []),
            created_at=datetime.now(UTC),
            created_by=created_by,
            metadata=meta,
            approval_state=effective_state,
        )
        self.store.save_finding(finding)
        chain = self._load_audit_chain(case_id)
        chain.append(
            AuditAction.FINDING_RECORDED,
            actor=created_by,
            payload={
                "finding_id": finding.id,
                "case_id": case_id,
                "title": title,
                "severity": finding.severity.value,
                "artifact_id": artifact_id,
                "technique_ids": list(technique_ids or []),
                "initial_state": finding.approval_state.value,
            },
        )
        self._save_audit_chain(chain)
        return finding

    def list_findings(self, case_id: str) -> list[Finding]:
        """List all findings for a case."""
        return self.store.list_findings(case_id)

    def get_finding(self, finding_id: str) -> Finding | None:
        """Get a finding by ID."""
        return self.store.get_finding(finding_id)

    # =============================================================
    # DRAFT / HITL approval workflow
    # =============================================================

    def set_case_approval_password(
        self, case_id: str, password: str
    ) -> Case | None:
        """Set or change the approval password for a case."""
        case = self.store.get_case(case_id)
        if case is None:
            return None
        self._approval.set_case_password(case, password)
        self.store.save_case(case)
        return case

    def approve_finding(
        self,
        finding_id: str,
        password: str,
        approved_by: str = "system",
        note: str = "",
    ) -> Finding | None:
        """Approve a finding with password-gated HMAC signing."""
        finding = self.store.get_finding(finding_id)
        if finding is None:
            return None
        case = self.store.get_case(finding.case_id)
        if case is None:
            return None
        finding = self._approval.approve(case, finding, password, approved_by, note)
        self.store.save_finding(finding)
        chain = self._load_audit_chain(case.id)
        chain.append(
            AuditAction.FINDING_APPROVED,
            actor=approved_by,
            payload={
                "finding_id": finding.id,
                "case_id": case.id,
                "approved_by": approved_by,
                "note": note,
            },
        )
        self._save_audit_chain(chain)
        return finding

    def reject_finding(
        self,
        finding_id: str,
        password: str,
        rejected_by: str = "system",
        reason: str = "",
    ) -> Finding | None:
        """Reject a finding with password verification."""
        finding = self.store.get_finding(finding_id)
        if finding is None:
            return None
        case = self.store.get_case(finding.case_id)
        if case is None:
            return None
        finding = self._approval.reject(case, finding, password, rejected_by, reason)
        self.store.save_finding(finding)
        chain = self._load_audit_chain(case.id)
        chain.append(
            AuditAction.FINDING_REJECTED,
            actor=rejected_by,
            payload={
                "finding_id": finding.id,
                "case_id": case.id,
                "rejected_by": rejected_by,
                "reason": reason,
            },
        )
        self._save_audit_chain(chain)
        return finding

    def list_review_queue(
        self, case_id: str | None = None
    ) -> list[Finding]:
        """List findings awaiting review (DRAFT or PENDING_REVIEW)."""
        if case_id is not None:
            findings = self.store.list_findings(case_id)
        else:
            findings = []
            for case in self.store.list_cases():
                findings.extend(self.store.list_findings(case.id))
        return [
            f for f in findings
            if f.approval_state in (ApprovalState.DRAFT, ApprovalState.PENDING_REVIEW)
        ]

    def verify_approval_signatures(
        self, case_id: str, password: str
    ) -> tuple[bool, list[str]]:
        """Verify HMAC signatures on all approved findings in a case."""
        case = self.store.get_case(case_id)
        if case is None:
            return False, [f"Case not found: {case_id}"]
        errors: list[str] = []
        for finding in self.store.list_findings(case_id):
            if finding.approval_state != ApprovalState.APPROVED:
                continue
            if not finding.hmac_signature:
                errors.append(f"Finding {finding.id} approved but has no signature")
                continue
            if not self._approval.verify_finding_signature(case, finding, password):
                errors.append(f"Finding {finding.id} signature verification failed")
        return (len(errors) == 0, errors)

    # =============================================================
    # Evidence operations
    # =============================================================

    def add_evidence(
        self,
        case_id: str,
        name: str,
        description: str = "",
        file_path: str | None = None,
        file_hash_md5: str | None = None,
        file_hash_sha1: str | None = None,
        file_hash_sha256: str | None = None,
        artifact_id: str | None = None,
        collected_by: str = "system",
        chain_of_custody: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvidenceRecord | None:
        """Register a piece of evidence in a case."""
        case = self.store.get_case(case_id)
        if case is None:
            return None
        evidence = EvidenceRecord(
            id=EvidenceRecord.new_id(),
            case_id=case_id,
            artifact_id=artifact_id,
            name=name,
            description=description,
            file_path=file_path,
            file_hash_md5=file_hash_md5,
            file_hash_sha1=file_hash_sha1,
            file_hash_sha256=file_hash_sha256,
            collected_at=datetime.now(UTC),
            collected_by=collected_by,
            chain_of_custody=list(chain_of_custody or []),
            metadata=dict(metadata or {}),
        )
        self.store.save_evidence(evidence)
        chain = self._load_audit_chain(case_id)
        chain.append(
            AuditAction.EVIDENCE_REGISTERED,
            actor=collected_by,
            payload={
                "evidence_id": evidence.id,
                "case_id": case_id,
                "name": name,
                "file_path": file_path,
                "file_hash_sha256": file_hash_sha256,
                "artifact_id": artifact_id,
            },
        )
        self._save_audit_chain(chain)
        return evidence

    def add_evidence_from_artifact(
        self,
        case_id: str,
        artifact: Artifact,
        collected_by: str = "system",
        description: str | None = None,
    ) -> EvidenceRecord | None:
        """Convenience: register an Artifact as evidence."""
        desc = description or artifact.description
        return self.add_evidence(
            case_id=case_id,
            name=f"{artifact.source.value}: {artifact.artifact_type.value}",
            description=desc,
            artifact_id=artifact.id,
            file_hash_md5=artifact.file_hash_md5,
            file_hash_sha1=artifact.file_hash_sha1,
            file_hash_sha256=artifact.file_hash_sha256,
            collected_by=collected_by,
            metadata={
                "host": artifact.host,
                "user": artifact.user,
                "source_ip": artifact.source_ip,
                "dest_ip": artifact.dest_ip,
                "process_name": artifact.process_name,
                "command_line": artifact.command_line,
                "timestamp": artifact.timestamp.isoformat(),
                "technique_ids": list(artifact.technique_ids),
            },
        )

    def list_evidence(self, case_id: str) -> list[EvidenceRecord]:
        """List all evidence for a case."""
        return self.store.list_evidence(case_id)

    # =============================================================
    # Audit chain
    # =============================================================

    def _load_audit_chain(self, case_id: str) -> AuditChain:
        """Load the audit chain for a case from SQLite."""
        chain = AuditChain(case_id, secret_key=self._secret_key)
        for _seq, entry in self.store.list_audit_entries(case_id):
            chain._entries.append(entry)
        return chain

    def _save_audit_chain(self, chain: AuditChain) -> None:
        """Append the last entry of the chain to SQLite."""
        if not chain.entries():
            return
        last = chain.entries()[-1]
        seq = len(chain.entries())
        self.store.save_audit_entry(chain.case_id, seq, last)

    def get_audit_log(self, case_id: str) -> list[AuditEntry]:
        """Return all audit entries for a case (in order)."""
        return [entry for _seq, entry in self.store.list_audit_entries(case_id)]

    def verify_audit_chain(self, case_id: str) -> tuple[bool, list[str]]:
        """Verify the integrity of a case's audit chain."""
        chain = self._load_audit_chain(case_id)
        return chain.verify()
