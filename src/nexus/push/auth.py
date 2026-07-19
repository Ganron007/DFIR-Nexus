"""Push ingest authentication — global + per-case tokens."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _secure_write_atomic(path: Path, data: str) -> None:
    """Write ``data`` to ``path`` atomically with owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(data, encoding="utf-8")
    try:
        # Owner read/write only (ignored on Windows, but harmless).
        os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    temp_path.replace(path)


@dataclass
class PushTokenRecord:
    case_id: str
    token_hash: str
    label: str = "default"
    created_at: float = field(default_factory=time.time)
    revoked: bool = False


class PushTokenStore:
    """Persist push tokens alongside cases (JSON file)."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._global_hash: str | None = None
        self._case_tokens: dict[str, list[PushTokenRecord]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        self._global_hash = data.get("global_token_hash")
        for case_id, rows in (data.get("case_tokens") or {}).items():
            self._case_tokens[case_id] = [
                PushTokenRecord(
                    case_id=case_id,
                    token_hash=row["token_hash"],
                    label=row.get("label", "default"),
                    created_at=float(row.get("created_at", 0)),
                    revoked=bool(row.get("revoked", False)),
                )
                for row in rows
            ]

    def _save(self) -> None:
        payload = {
            "global_token_hash": self._global_hash,
            "case_tokens": {
                cid: [
                    {
                        "token_hash": r.token_hash,
                        "label": r.label,
                        "created_at": r.created_at,
                        "revoked": r.revoked,
                    }
                    for r in rows
                ]
                for cid, rows in self._case_tokens.items()
            },
        }
        _secure_write_atomic(self.path, json.dumps(payload, indent=2))

    def set_global_token(self, token: str) -> None:
        self._global_hash = _hash_token(token)
        self._save()

    def generate_case_token(self, case_id: str, *, label: str = "default") -> str:
        token = secrets.token_urlsafe(32)
        record = PushTokenRecord(case_id=case_id, token_hash=_hash_token(token), label=label)
        self._case_tokens.setdefault(case_id, []).append(record)
        self._save()
        return token

    def revoke_case_tokens(self, case_id: str) -> int:
        rows = self._case_tokens.get(case_id, [])
        count = 0
        for row in rows:
            if not row.revoked:
                row.revoked = True
                count += 1
        if count:
            self._save()
        return count

    def list_case_tokens(self, case_id: str) -> list[dict[str, Any]]:
        return [
            {
                "case_id": case_id,
                "label": r.label,
                "created_at": r.created_at,
                "revoked": r.revoked,
                "token_hint": r.token_hash[:8] + "...",
            }
            for r in self._case_tokens.get(case_id, [])
        ]

    def verify(self, token: str, case_id: str | None = None) -> bool:
        digest = _hash_token(token)
        if case_id:
            for row in self._case_tokens.get(case_id, []):
                if not row.revoked and hmac.compare_digest(row.token_hash, digest):
                    return True
            return False
        if self._global_hash and hmac.compare_digest(self._global_hash, digest):
            return True
        return False
