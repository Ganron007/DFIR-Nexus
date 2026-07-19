"""SQLite-backed persistent store for cases, findings, evidence, and audit log.

Single-file SQLite database. Schema is created on first use.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path

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

log = logging.getLogger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    closed_at TEXT,
    closed_by TEXT,
    tags_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    approval_password_hash TEXT,
    approval_password_salt TEXT,
    approval_iterations INTEGER NOT NULL DEFAULT 600000
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    artifact_id TEXT,
    technique_ids_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    approval_state TEXT NOT NULL DEFAULT 'draft',
    approved_by TEXT,
    approved_at TEXT,
    rejected_by TEXT,
    rejected_at TEXT,
    rejection_reason TEXT,
    hmac_signature TEXT,
    hmac_salt TEXT,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE INDEX IF NOT EXISTS idx_findings_case_id ON findings(case_id);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    artifact_id TEXT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    file_path TEXT,
    file_hash_md5 TEXT,
    file_hash_sha1 TEXT,
    file_hash_sha256 TEXT,
    collected_at TEXT NOT NULL,
    collected_by TEXT NOT NULL,
    chain_of_custody_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    seq INTEGER NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id)
);

CREATE INDEX IF NOT EXISTS idx_audit_case_id ON audit_log(case_id);
CREATE INDEX IF NOT EXISTS idx_audit_case_seq ON audit_log(case_id, seq);
"""


class SQLiteStore:
    """Persistent store backed by a single SQLite database file.

    Schema is created lazily on first use. Provides CRUD for all case-related
    entities. Thread-safe via check_same_thread=False (caller's responsibility).
    """

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        self._conn.close()

    # ----- Cases -----

    def save_case(self, case: Case) -> None:
        """Insert or update a case."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO cases (
                id, name, description, status, severity,
                created_at, created_by, closed_at, closed_by,
                tags_json, metadata_json,
                approval_password_hash, approval_password_salt, approval_iterations
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case.id,
                case.name,
                case.description,
                case.status.value,
                case.severity.value,
                case.created_at.isoformat(),
                case.created_by,
                case.closed_at.isoformat() if case.closed_at else None,
                case.closed_by,
                json.dumps(case.tags),
                json.dumps(case.metadata),
                case.approval_password_hash,
                case.approval_password_salt,
                case.approval_iterations,
            ),
        )
        self._conn.commit()

    def get_case(self, case_id: str) -> Case | None:
        """Fetch a case by ID."""
        row = self._conn.execute(
            "SELECT * FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_case(row)

    def list_cases(self, status: str | None = None) -> list[Case]:
        """List all cases, optionally filtered by status."""
        if status:
            rows = self._conn.execute(
                "SELECT * FROM cases WHERE status = ? ORDER BY created_at DESC",
                (status,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM cases ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_case(r) for r in rows]

    def delete_case(self, case_id: str) -> bool:
        """Delete a case and all related data. Returns True if deleted."""
        # Cascade delete: findings, evidence, audit log, then case
        self._conn.execute("DELETE FROM audit_log WHERE case_id = ?", (case_id,))
        self._conn.execute("DELETE FROM findings WHERE case_id = ?", (case_id,))
        self._conn.execute("DELETE FROM evidence WHERE case_id = ?", (case_id,))
        cur = self._conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        self._conn.commit()
        return cur.rowcount > 0

    @staticmethod
    def _row_to_case(row: sqlite3.Row) -> Case:
        return Case(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            status=CaseStatus(row["status"]),
            severity=FindingSeverity(row["severity"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            created_by=row["created_by"],
            closed_at=datetime.fromisoformat(row["closed_at"]) if row["closed_at"] else None,
            closed_by=row["closed_by"],
            tags=json.loads(row["tags_json"]),
            metadata=json.loads(row["metadata_json"]),
            approval_password_hash=row["approval_password_hash"],
            approval_password_salt=row["approval_password_salt"],
            approval_iterations=row["approval_iterations"] or 600000,
        )

    # ----- Findings -----

    def save_finding(self, finding: Finding) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO findings (
                id, case_id, title, description, severity,
                artifact_id, technique_ids_json, created_at, created_by, metadata_json,
                approval_state, approved_by, approved_at, rejected_by, rejected_at,
                rejection_reason, hmac_signature, hmac_salt
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.id,
                finding.case_id,
                finding.title,
                finding.description,
                finding.severity.value,
                finding.artifact_id,
                json.dumps(finding.technique_ids),
                finding.created_at.isoformat(),
                finding.created_by,
                json.dumps(finding.metadata),
                finding.approval_state.value,
                finding.approved_by,
                finding.approved_at.isoformat() if finding.approved_at else None,
                finding.rejected_by,
                finding.rejected_at.isoformat() if finding.rejected_at else None,
                finding.rejection_reason,
                finding.hmac_signature,
                finding.hmac_salt,
            ),
        )
        self._conn.commit()

    def list_findings(self, case_id: str) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE case_id = ? ORDER BY created_at DESC",
            (case_id,),
        ).fetchall()
        return [self._row_to_finding(r) for r in rows]

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self._conn.execute(
            "SELECT * FROM findings WHERE id = ?", (finding_id,)
        ).fetchone()
        return self._row_to_finding(row) if row else None

    @staticmethod
    def _row_to_finding(row: sqlite3.Row) -> Finding:
        return Finding(
            id=row["id"],
            case_id=row["case_id"],
            title=row["title"],
            description=row["description"],
            severity=FindingSeverity(row["severity"]),
            artifact_id=row["artifact_id"],
            technique_ids=json.loads(row["technique_ids_json"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            created_by=row["created_by"],
            metadata=json.loads(row["metadata_json"]),
            approval_state=ApprovalState(row["approval_state"] or "draft"),
            approved_by=row["approved_by"],
            approved_at=datetime.fromisoformat(row["approved_at"]) if row["approved_at"] else None,
            rejected_by=row["rejected_by"],
            rejected_at=datetime.fromisoformat(row["rejected_at"]) if row["rejected_at"] else None,
            rejection_reason=row["rejection_reason"],
            hmac_signature=row["hmac_signature"],
            hmac_salt=row["hmac_salt"],
        )

    # ----- Evidence -----

    def save_evidence(self, evidence: EvidenceRecord) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO evidence (
                id, case_id, artifact_id, name, description,
                file_path, file_hash_md5, file_hash_sha1, file_hash_sha256,
                collected_at, collected_by, chain_of_custody_json, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence.id,
                evidence.case_id,
                evidence.artifact_id,
                evidence.name,
                evidence.description,
                evidence.file_path,
                evidence.file_hash_md5,
                evidence.file_hash_sha1,
                evidence.file_hash_sha256,
                evidence.collected_at.isoformat(),
                evidence.collected_by,
                json.dumps(evidence.chain_of_custody),
                json.dumps(evidence.metadata),
            ),
        )
        self._conn.commit()

    def list_evidence(self, case_id: str) -> list[EvidenceRecord]:
        rows = self._conn.execute(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY collected_at DESC",
            (case_id,),
        ).fetchall()
        return [self._row_to_evidence(r) for r in rows]

    @staticmethod
    def _row_to_evidence(row: sqlite3.Row) -> EvidenceRecord:
        return EvidenceRecord(
            id=row["id"],
            case_id=row["case_id"],
            artifact_id=row["artifact_id"],
            name=row["name"],
            description=row["description"],
            file_path=row["file_path"],
            file_hash_md5=row["file_hash_md5"],
            file_hash_sha1=row["file_hash_sha1"],
            file_hash_sha256=row["file_hash_sha256"],
            collected_at=datetime.fromisoformat(row["collected_at"]),
            collected_by=row["collected_by"],
            chain_of_custody=json.loads(row["chain_of_custody_json"]),
            metadata=json.loads(row["metadata_json"]),
        )

    # ----- Audit log -----

    def save_audit_entry(self, case_id: str, seq: int, entry: AuditEntry) -> None:
        self._conn.execute(
            """
            INSERT OR REPLACE INTO audit_log (
                id, case_id, action, timestamp, actor, payload_json,
                prev_hash, hash, signature, seq
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.id,
                case_id,
                entry.action.value,
                entry.timestamp.isoformat(),
                entry.actor,
                json.dumps(entry.payload),
                entry.prev_hash,
                entry.hash,
                entry.signature,
                seq,
            ),
        )
        self._conn.commit()

    def list_audit_entries(self, case_id: str) -> list[tuple[int, AuditEntry]]:
        """Return (seq, entry) tuples ordered by seq ascending."""
        rows = self._conn.execute(
            "SELECT * FROM audit_log WHERE case_id = ? ORDER BY seq ASC",
            (case_id,),
        ).fetchall()
        out: list[tuple[int, AuditEntry]] = []
        for row in rows:
            entry = AuditEntry(
                id=row["id"],
                case_id=row["case_id"],
                action=AuditAction(row["action"]),
                timestamp=datetime.fromisoformat(row["timestamp"]),
                actor=row["actor"],
                payload=json.loads(row["payload_json"]),
                prev_hash=row["prev_hash"],
                hash=row["hash"],
                signature=row["signature"],
            )
            out.append((row["seq"], entry))
        return out
