"""Schemas for the Case module (Evidence Platform)."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class CaseStatus(StrEnum):
    """Lifecycle status of a case."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
    ARCHIVED = "archived"


class FindingSeverity(StrEnum):
    """Severity of a finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @classmethod
    def normalize(cls, value: Any) -> FindingSeverity:
        """Map arbitrary input to enum."""
        if value is None:
            return cls.INFORMATIONAL
        if isinstance(value, cls):
            return value
        s = str(value).strip().lower()
        mapping = {
            "1": cls.CRITICAL, "critical": cls.CRITICAL, "crit": cls.CRITICAL,
            "2": cls.HIGH, "high": cls.HIGH, "error": cls.HIGH,
            "3": cls.MEDIUM, "medium": cls.MEDIUM, "med": cls.MEDIUM, "warning": cls.MEDIUM,
            "4": cls.LOW, "low": cls.LOW,
            "5": cls.INFORMATIONAL, "info": cls.INFORMATIONAL,
            "informational": cls.INFORMATIONAL,
        }
        return mapping.get(s, cls.INFORMATIONAL)


class ApprovalState(StrEnum):
    """Approval lifecycle of a finding."""

    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"


class AuditAction(StrEnum):
    """Types of actions that can be audited."""

    CASE_CREATED = "case_created"
    CASE_OPENED = "case_opened"
    CASE_CLOSED = "case_closed"
    CASE_STATUS_CHANGED = "case_status_changed"
    EVIDENCE_REGISTERED = "evidence_registered"
    FINDING_RECORDED = "finding_recorded"
    FINDING_UPDATED = "finding_updated"
    FINDING_APPROVED = "finding_approved"
    FINDING_REJECTED = "finding_rejected"
    ARTIFACT_LINKED = "artifact_linked"
    NOTE_ADDED = "note_added"


@dataclass
class Case:
    """An investigation case."""

    id: str
    name: str
    description: str
    status: CaseStatus
    severity: FindingSeverity
    created_at: datetime
    created_by: str
    closed_at: datetime | None = None
    closed_by: str | None = None
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    approval_password_hash: str | None = None
    approval_password_salt: str | None = None
    approval_iterations: int = 600000

    @staticmethod
    def new_id() -> str:
        """Generate a new case ID."""
        return f"CASE-{uuid.uuid4().hex[:8].upper()}"

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        d["created_at"] = self.created_at.isoformat()
        d["closed_at"] = self.closed_at.isoformat() if self.closed_at else None
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Case:
        """Construct from a dict (inverse of to_dict)."""
        d = dict(data)
        d["status"] = CaseStatus(d["status"])
        d["severity"] = FindingSeverity(d["severity"])
        for key in ("created_at", "closed_at"):
            if isinstance(d.get(key), str):
                d[key] = datetime.fromisoformat(d[key])
        return cls(**d)


@dataclass
class Finding:
    """A finding within a case."""

    id: str
    case_id: str
    title: str
    description: str
    severity: FindingSeverity
    artifact_id: str | None
    technique_ids: list[str]
    created_at: datetime
    created_by: str
    metadata: dict[str, Any] = field(default_factory=dict)
    approval_state: ApprovalState = ApprovalState.DRAFT
    approved_by: str | None = None
    approved_at: datetime | None = None
    rejected_by: str | None = None
    rejected_at: datetime | None = None
    rejection_reason: str | None = None
    hmac_signature: str | None = None
    hmac_salt: str | None = None

    @staticmethod
    def new_id() -> str:
        """Generate a new finding ID."""
        return f"FIND-{uuid.uuid4().hex[:8].upper()}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["approval_state"] = self.approval_state.value
        d["created_at"] = self.created_at.isoformat()
        d["approved_at"] = self.approved_at.isoformat() if self.approved_at else None
        d["rejected_at"] = self.rejected_at.isoformat() if self.rejected_at else None
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        d = dict(data)
        d["severity"] = FindingSeverity(d["severity"])
        d["approval_state"] = ApprovalState(d.get("approval_state", "draft"))
        for key in ("created_at", "approved_at", "rejected_at"):
            if isinstance(d.get(key), str):
                d[key] = datetime.fromisoformat(d[key])
        return cls(**d)


@dataclass
class EvidenceRecord:
    """A registered piece of evidence in a case."""

    id: str
    case_id: str
    artifact_id: str | None
    name: str
    description: str
    file_path: str | None
    file_hash_md5: str | None
    file_hash_sha1: str | None
    file_hash_sha256: str | None
    collected_at: datetime
    collected_by: str
    chain_of_custody: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def new_id() -> str:
        """Generate a new evidence ID."""
        return f"EV-{uuid.uuid4().hex[:8].upper()}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["collected_at"] = self.collected_at.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceRecord:
        d = dict(data)
        if isinstance(d.get("collected_at"), str):
            d["collected_at"] = datetime.fromisoformat(d["collected_at"])
        return cls(**d)


@dataclass
class AuditEntry:
    """A single entry in the HMAC audit chain.

    Each entry contains the previous entry's hash, the current payload, and
    a new hash computed as HMAC-SHA256(secret, prev_hash || payload).
    """

    id: str
    case_id: str
    action: AuditAction
    timestamp: datetime
    actor: str
    payload: dict[str, Any]
    prev_hash: str  # hex
    hash: str       # hex
    signature: str  # hex HMAC

    @staticmethod
    def new_id() -> str:
        """Generate a new audit entry ID."""
        return f"AUD-{uuid.uuid4().hex[:12].upper()}"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["action"] = self.action.value
        d["timestamp"] = self.timestamp.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        d = dict(data)
        d["action"] = AuditAction(d["action"])
        if isinstance(d.get("timestamp"), str):
            d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        return cls(**d)
