"""HMAC Audit Chain.

Each case maintains a chained log of actions. Each entry's hash includes the
previous entry's hash, so any tampering breaks the chain. The signature is
HMAC-SHA256(secret_key, payload_json) — provides both integrity and
authentication.

Genesis entry: prev_hash = "0" * 64, hash = HMAC(secret, "0"*64 || payload).

Use:
    chain = AuditChain(case_id, secret_key)
    chain.append(AuditAction.CASE_CREATED, actor="analyst", payload={...})
    chain.append(AuditAction.EVIDENCE_REGISTERED, ...)
    ok, errors = chain.verify()  # returns (bool, list[str])
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import UTC, datetime
from typing import Any

from nexus.case.schemas import AuditAction, AuditEntry

log = logging.getLogger(__name__)


GENESIS_HASH = "0" * 64


class AuditChainError(Exception):
    """Raised when the audit chain fails verification."""


class AuditChain:
    """HMAC-SHA256 chained audit log for a single case.

    The chain is append-only: each new entry references the previous entry's
    hash, forming a tamper-evident sequence.
    """

    def __init__(self, case_id: str, secret_key: bytes | None = None) -> None:
        """Initialize a new audit chain.

        Args:
            case_id: The case this chain belongs to.
            secret_key: HMAC secret. If None, a deterministic per-case key is
                derived from the case_id (NOT cryptographically secure — only
                suitable for testing; in production, pass a real key).
        """
        self.case_id = case_id
        if secret_key is None:
            # WARNING: deterministic key for development. Replace in production.
            secret_key = hashlib.sha256(f"nexus-default:{case_id}".encode()).digest()
        self._secret_key = secret_key
        self._entries: list[AuditEntry] = []

    @staticmethod
    def _canonical_json(payload: dict[str, Any]) -> bytes:
        """Serialize payload to deterministic JSON bytes."""
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _compute_hash(
        self,
        prev_hash: str,
        payload: dict[str, Any],
        entry_id: str,
        timestamp: datetime,
    ) -> str:
        """Compute the HMAC-SHA256 hash for an entry.

        Includes prev_hash, payload, entry_id, and timestamp for full coverage.
        """
        msg = (
            prev_hash.encode("utf-8")
            + self._canonical_json(payload)
            + entry_id.encode("utf-8")
            + timestamp.isoformat().encode("utf-8")
        )
        return hmac.new(self._secret_key, msg, hashlib.sha256).hexdigest()

    def append(
        self,
        action: AuditAction,
        actor: str,
        payload: dict[str, Any],
    ) -> AuditEntry:
        """Append a new entry to the chain.

        Args:
            action: The AuditAction being recorded.
            actor: Who performed the action.
            payload: Action-specific data.

        Returns:
            The newly created AuditEntry.
        """
        prev_hash = self._entries[-1].hash if self._entries else GENESIS_HASH
        entry_id = AuditEntry.new_id()
        timestamp = datetime.now(UTC)
        hash_value = self._compute_hash(prev_hash, payload, entry_id, timestamp)
        entry = AuditEntry(
            id=entry_id,
            case_id=self.case_id,
            action=action,
            timestamp=timestamp,
            actor=actor,
            payload=payload,
            prev_hash=prev_hash,
            hash=hash_value,
            signature=hash_value,  # same value — single HMAC covers both
        )
        self._entries.append(entry)
        return entry

    def entries(self) -> list[AuditEntry]:
        """Return all entries in the chain (read-only copy)."""
        return list(self._entries)

    def verify(self) -> tuple[bool, list[str]]:
        """Verify the entire chain.

        Returns:
            (True, []) if valid.
            (False, [error_messages]) if any entry has been tampered with or
            the chain has gaps.
        """
        errors: list[str] = []
        expected_prev = GENESIS_HASH
        for i, entry in enumerate(self._entries):
            if entry.prev_hash != expected_prev:
                errors.append(
                    f"Entry {i} ({entry.id}): prev_hash mismatch "
                    f"(expected {expected_prev[:16]}..., got {entry.prev_hash[:16]}...)"
                )
            # Recompute hash
            recomputed = self._compute_hash(
                entry.prev_hash, entry.payload, entry.id, entry.timestamp
            )
            if recomputed != entry.hash:
                errors.append(
                    f"Entry {i} ({entry.id}): hash mismatch "
                    f"(expected {recomputed[:16]}..., got {entry.hash[:16]}...)"
                )
            if entry.signature != entry.hash:
                errors.append(
                    f"Entry {i} ({entry.id}): signature/hash mismatch"
                )
            expected_prev = entry.hash
        return (len(errors) == 0, errors)

    def to_list(self) -> list[dict[str, Any]]:
        """Return entries as list of dicts."""
        return [e.to_dict() for e in self._entries]

    @classmethod
    def from_entries(
        cls, case_id: str, entries: list[AuditEntry], secret_key: bytes | None = None
    ) -> AuditChain:
        """Rebuild a chain from existing entries (e.g., from SQLite)."""
        chain = cls(case_id, secret_key=secret_key)
        chain._entries = list(entries)
        return chain
