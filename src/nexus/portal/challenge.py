"""Generic HMAC challenge-response authentication for the portal layer."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass, field

DEFAULT_PBKDF2_ITERATIONS = int(
    os.environ.get("NEXUS_CHALLENGE_PBKDF2_ITERATIONS", "600000")
)
DEFAULT_CHALLENGE_TTL_SECONDS = int(
    os.environ.get("NEXUS_CHALLENGE_TTL_SECONDS", "300")
)


@dataclass
class ChallengeRecord:
    """Server-side challenge state."""

    challenge_id: str
    nonce: bytes
    salt: bytes
    iterations: int
    password_hash: bytes
    created_at: float = field(default_factory=time.time)

    def is_expired(self, ttl: float) -> bool:
        return (time.time() - self.created_at) > ttl


class ChallengeStore:
    """In-memory challenge store for HMAC challenge-response login."""

    def __init__(
        self,
        pbkdf2_iterations: int | None = None,
        challenge_ttl: int | None = None,
    ) -> None:
        self._iterations = (
            DEFAULT_PBKDF2_ITERATIONS
            if pbkdf2_iterations is None
            else pbkdf2_iterations
        )
        self._ttl = (
            DEFAULT_CHALLENGE_TTL_SECONDS if challenge_ttl is None else challenge_ttl
        )
        self._challenges: dict[str, ChallengeRecord] = {}

    def create_challenge(self, password: str) -> dict[str, str]:
        """Issue a challenge for the client to prove password knowledge."""
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(32)
        iterations = self._iterations
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
        challenge_id = secrets.token_urlsafe(16)
        self._challenges[challenge_id] = ChallengeRecord(
            challenge_id=challenge_id,
            nonce=nonce,
            salt=salt,
            iterations=iterations,
            password_hash=password_hash,
        )
        return {
            "challenge_id": challenge_id,
            "nonce": nonce.hex(),
            "salt": salt.hex(),
            "iterations": str(iterations),
        }

    def verify_response(self, challenge_id: str, client_proof: str) -> bool:
        """Verify HMAC-SHA256(PBKDF2(password, salt), nonce) from client."""
        record = self._challenges.get(challenge_id)
        if record is None or record.is_expired(self._ttl):
            self._challenges.pop(challenge_id, None)
            return False
        try:
            proof_bytes = bytes.fromhex(client_proof)
        except ValueError:
            return False
        expected = hmac.new(
            record.password_hash, record.nonce, hashlib.sha256
        ).digest()
        ok = hmac.compare_digest(proof_bytes, expected)
        if ok:
            self._challenges.pop(challenge_id, None)
        return ok

    def purge_expired(self) -> int:
        """Remove expired challenges and return the count removed."""
        expired = [cid for cid, r in self._challenges.items() if r.is_expired(self._ttl)]
        for cid in expired:
            del self._challenges[cid]
        return len(expired)
