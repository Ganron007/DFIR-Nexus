"""Case stack schemas and (eventually) persistence/management."""

from __future__ import annotations

from nexus.case.approval_service import (
    ApprovalError,
    ApprovalLockedError,
    ApprovalPasswordError,
)
from nexus.case.audit import AuditChain, AuditChainError
from nexus.case.compat import LegacyJsonImporter, get_sqlite_manager, sync_sqlite_to_flat
from nexus.case.manager import CaseManager, materialize_case_dir
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

__all__ = [
    "ApprovalError",
    "ApprovalLockedError",
    "ApprovalPasswordError",
    "ApprovalState",
    "AuditAction",
    "AuditChain",
    "AuditChainError",
    "AuditEntry",
    "Case",
    "CaseManager",
    "CaseStatus",
    "EvidenceRecord",
    "Finding",
    "FindingSeverity",
    "LegacyJsonImporter",
    "SQLiteStore",
    "get_audit_secret",
    "get_sqlite_manager",
    "materialize_case_dir",
    "sync_sqlite_to_flat",
]
