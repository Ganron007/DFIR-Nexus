"""Hash-chained transparency log for tamper-evident approval chains.

Each entry is linked to the previous entry via SHA-256 hash, forming
a hash chain. Tampering with any entry breaks the chain and is
detectable without trusting ~/.nexus/verification/.

Usage:
    from nexus.transparency import transparency_append, transparency_verify

    entry = {"finding_id": "F-001", "status": "APPROVED"}
    transparency_append("CASE-001", entry)
    # -> appends {"entry": ..., "previous_hash": "...", "hash": "...",
    #             "timestamp": "..."}

    status = transparency_verify("CASE-001")
    # -> {"valid": True, "entries": 42, "tampered": None}
"""

import hashlib
import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path

logger = logging.getLogger(__name__)

TRANSPARENCY_DIR = Path.home() / ".nexus" / "transparency"


def transparency_append(case_id: str, entry: dict) -> dict | None:
    """Append an entry to the hash-chained transparency log.

    Each entry stores the hash of the previous entry, creating an
    immutable chain. Returns the stored envelope dict, or None on failure.

    Args:
        case_id: Case identifier
        entry: Dict to record (typically finding approval data)

    Returns:
        The envelope dict with hash fields added, or None.
    """
    try:
        TRANSPARENCY_DIR.mkdir(parents=True, exist_ok=True)
        path = TRANSPARENCY_DIR / f"{case_id}.jsonl"

        # Read previous hash from last line
        previous_hash = _get_last_hash(path)
        now = datetime.now(UTC).isoformat()

        envelope = {
            "entry": entry,
            "previous_hash": previous_hash,
            "timestamp": now,
        }
        envelope["hash"] = hashlib.sha256(
            json.dumps(envelope, sort_keys=True, default=str).encode()
        ).hexdigest()

        with open(path, "a") as f:
            f.write(json.dumps(envelope) + "\n")
            f.flush()
            os.fsync(f.fileno())

        return envelope
    except Exception as e:
        logger.error("Transparency append failed: %s", e)
        return None


def transparency_verify(case_id: str) -> dict:
    """Verify the integrity of a hash chain for a case.

    Walks the entire chain, verifying each link. Returns a dict with
    valid flag, entry count, and tampering details.

    Returns:
        {"valid": True, "entries": N}
        {"valid": False, "entries": N, "tampered": index, "expected": str, "actual": str}
    """
    path = TRANSPARENCY_DIR / f"{case_id}.jsonl"
    if not path.exists():
        return {"valid": False, "entries": 0, "error": "No transparency log found"}

    entries = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            return {"valid": False, "entries": len(entries), "tampered": "parse_error"}

    expected_previous = ""
    for i, envelope in enumerate(entries):
        # Recompute hash
        recomputed = hashlib.sha256(
            json.dumps({
                "entry": envelope["entry"],
                "previous_hash": envelope["previous_hash"],
                "timestamp": envelope["timestamp"],
            }, sort_keys=True, default=str).encode()
        ).hexdigest()

        if recomputed != envelope.get("hash", ""):
            return {
                "valid": False, "entries": len(entries),
                "tampered": i,
                "expected": recomputed,
                "actual": envelope.get("hash", ""),
            }

        if envelope.get("previous_hash", "") != expected_previous:
            return {
                "valid": False, "entries": len(entries),
                "tampered": i,
                "expected_previous": expected_previous,
                "actual_previous": envelope.get("previous_hash", ""),
            }

        expected_previous = envelope["hash"]

    return {"valid": True, "entries": len(entries)}


def _get_last_hash(path: Path) -> str:
    """Read the hash of the last entry in the chain."""
    if not path.exists():
        return ""
    try:
        lines = path.read_text().splitlines()
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line).get("hash", "")
            except json.JSONDecodeError:
                continue
    except OSError:
        pass
    return ""
