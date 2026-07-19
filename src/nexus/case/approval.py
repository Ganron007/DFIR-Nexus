"""DRAFT / HITL approval workflow.

Provides password-gated approval/rejection of findings with PBKDF2-derived
HMAC-SHA256 signing. Every approved finding carries a signature that can be
verified independently with the case approval password.

Design:
- Each case has an approval password, stored as PBKDF2-HMAC-SHA256 hash.
- Findings are created in DRAFT or APPROVED state.
- Approving/rejecting a finding requires the case password.
- 3 failed password attempts lock the finding for 15 minutes.
- Approved findings are signed with a PBKDF2-derived key (password + per-finding salt).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from nexus.case.schemas import ApprovalState, Case, Finding

log = logging.getLogger(__name__)


DEFAULT_PBKDF2_ITERATIONS = 600_000
LOCKOUT_MAX_ATTEMPTS = 3
LOCKOUT_SECONDS = 15 * 60


class ApprovalError(Exception):
    """Raised when an approval operation fails."""


class ApprovalLockedError(ApprovalError):
    """Raised when too many failed password attempts have occurred."""


class ApprovalPasswordError(ApprovalError):
    """Raised when the provided approval password is incorrect."""


@dataclass(frozen=True)
class PBKDF2Key:
    """Password-derived key material."""

    password: str
    salt: bytes
    iterations: int = DEFAULT_PBKDF2_ITERATIONS

    def derive(self) -> bytes:
        """Derive a 32-byte key via PBKDF2-HMAC-SHA256."""
        return hashlib.pbkdf2_hmac(
            "sha256", self.password.encode("utf-8"), self.salt, self.iterations
        )

    def hash(self) -> bytes:
        """Derive a password hash for storage."""
        return self.derive()


class HMACSigner:
    """Sign/verify bytes with HMAC-SHA256."""

    def __init__(self, key: bytes) -> None:
        self._key = key

    def sign(self, data: bytes) -> str:
        """Return hex signature."""
        return hmac.new(self._key, data, hashlib.sha256).hexdigest()

    def verify(self, data: bytes, signature: str) -> bool:
        """Constant-time verify."""
        expected = self.sign(data)
        return hmac.compare_digest(expected, signature)


class ApprovalLockout:
    """In-memory failed-attempt lockout tracker.

    Tracks failures per finding ID. 3 failures within 15 minutes lock the
    operation. Successful authentication resets the counter.
    """

    def __init__(self) -> None:
        self._attempts: dict[str, list[float]] = {}

    def is_locked(self, key: str) -> bool:
        now = time.time()
        cutoff = now - LOCKOUT_SECONDS
        attempts = [t for t in self._attempts.get(key, []) if t > cutoff]
        self._attempts[key] = attempts
        return len(attempts) >= LOCKOUT_MAX_ATTEMPTS

    def record_failure(self, key: str) -> None:
        now = time.time()
        attempts = self._attempts.setdefault(key, [])
        attempts.append(now)
        cutoff = now - LOCKOUT_SECONDS
        self._attempts[key] = [t for t in attempts if t > cutoff]

    def reset(self, key: str) -> None:
        self._attempts.pop(key, None)


class ApprovalWorkflow:
    """High-level approval workflow for findings.

    Usage:
        workflow = ApprovalWorkflow()
        workflow.set_case_password(case, "hunter2")
        workflow.approve(case, finding, "hunter2", approved_by="lead")
        workflow.reject(case, finding, "hunter2", reason="FP")
    """

    def __init__(self, lockout: ApprovalLockout | None = None) -> None:
        self.lockout = lockout or ApprovalLockout()

    # ------------------------------------------------------------------
    # Password management
    # ------------------------------------------------------------------

    def set_case_password(self, case: Case, password: str) -> None:
        """Set or change a case's approval password.

        Stores PBKDF2 hash + salt + iteration count on the case object.
        """
        salt = secrets.token_bytes(32)
        key = PBKDF2Key(password, salt, iterations=DEFAULT_PBKDF2_ITERATIONS)
        case.approval_password_hash = key.hash().hex()
        case.approval_password_salt = salt.hex()
        case.approval_iterations = DEFAULT_PBKDF2_ITERATIONS

    def _verify_password(self, case: Case, password: str) -> None:
        """Verify the provided password against the case's stored hash.

        Raises ApprovalPasswordError on mismatch.
        """
        if not case.approval_password_hash:
            raise ApprovalError("Case has no approval password set")
        salt = bytes.fromhex(case.approval_password_salt or "")
        key = PBKDF2Key(password, salt, iterations=case.approval_iterations)
        expected = bytes.fromhex(case.approval_password_hash)
        if not hmac.compare_digest(key.hash(), expected):
            raise ApprovalPasswordError("Invalid approval password")

    def _derive_signing_key(self, case: Case, password: str, finding_salt: bytes) -> bytes:
        """Derive a signing key from password + per-finding salt."""
        return PBKDF2Key(password, finding_salt, iterations=case.approval_iterations).derive()

    # ------------------------------------------------------------------
    # Finding approval / rejection
    # ------------------------------------------------------------------

    def approve(
        self,
        case: Case,
        finding: Finding,
        password: str,
        approved_by: str = "system",
        note: str = "",
    ) -> Finding:
        """Approve a finding with password-gated HMAC signing."""
        lock_key = f"{finding.case_id}:{finding.id}"
        if self.lockout.is_locked(lock_key):
            raise ApprovalLockedError(
                f"Finding {finding.id} is locked due to too many failed attempts"
            )

        try:
            self._verify_password(case, password)
        except ApprovalPasswordError:
            self.lockout.record_failure(lock_key)
            raise

        self.lockout.reset(lock_key)

        finding_salt = secrets.token_bytes(32)
        key = self._derive_signing_key(case, password, finding_salt)
        signer = HMACSigner(key)

        # Sign canonical finding data (excluding signature fields)
        payload = self._canonical_finding_payload(finding)
        signature = signer.sign(payload)

        finding.approval_state = ApprovalState.APPROVED
        finding.approved_by = approved_by
        finding.approved_at = datetime.now(UTC)
        finding.rejected_by = None
        finding.rejected_at = None
        finding.rejection_reason = None
        finding.hmac_salt = finding_salt.hex()
        finding.hmac_signature = signature

        log.info("Finding %s approved by %s", finding.id, approved_by)
        return finding

    def reject(
        self,
        case: Case,
        finding: Finding,
        password: str,
        rejected_by: str = "system",
        reason: str = "",
    ) -> Finding:
        """Reject a finding with password verification."""
        lock_key = f"{finding.case_id}:{finding.id}"
        if self.lockout.is_locked(lock_key):
            raise ApprovalLockedError(
                f"Finding {finding.id} is locked due to too many failed attempts"
            )

        try:
            self._verify_password(case, password)
        except ApprovalPasswordError:
            self.lockout.record_failure(lock_key)
            raise

        self.lockout.reset(lock_key)

        finding.approval_state = ApprovalState.REJECTED
        finding.approved_by = None
        finding.approved_at = None
        finding.rejected_by = rejected_by
        finding.rejected_at = datetime.now(UTC)
        finding.rejection_reason = reason
        finding.hmac_salt = None
        finding.hmac_signature = None

        log.info("Finding %s rejected by %s: %s", finding.id, rejected_by, reason)
        return finding

    def verify_finding_signature(
        self,
        case: Case,
        finding: Finding,
        password: str,
    ) -> bool:
        """Verify the HMAC signature on an approved finding."""
        if finding.approval_state != ApprovalState.APPROVED:
            return False
        if not finding.hmac_signature or not finding.hmac_salt:
            return False
        try:
            self._verify_password(case, password)
        except ApprovalPasswordError:
            return False

        finding_salt = bytes.fromhex(finding.hmac_salt)
        key = self._derive_signing_key(case, password, finding_salt)
        signer = HMACSigner(key)
        payload = self._canonical_finding_payload(finding)
        return signer.verify(payload, finding.hmac_signature)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _canonical_finding_payload(finding: Finding) -> bytes:
        """Build canonical bytes for signing.

        Excludes mutable state that should not be part of the signature:
        approval_state, approved_by, approved_at, rejected_by, rejected_at,
        rejection_reason, hmac_signature, hmac_salt.
        """
        data = {
            "id": finding.id,
            "case_id": finding.case_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "artifact_id": finding.artifact_id,
            "technique_ids": sorted(finding.technique_ids),
            "created_at": finding.created_at.isoformat(),
            "created_by": finding.created_by,
            "metadata": finding.metadata,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


# Global lockout instance (per-process). In a multi-process deployment this
# would move to Redis or a shared store, but for the single-process DFIR-Nexus
# model an in-memory dict is sufficient.
_default_lockout = ApprovalLockout()


def get_default_workflow() -> ApprovalWorkflow:
    """Return the process-default ApprovalWorkflow."""
    return ApprovalWorkflow(lockout=_default_lockout)
