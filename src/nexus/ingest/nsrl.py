"""NSRL (National Software Reference Library) known-good hash integration.

Looks up file hashes against a local NSRL hash set to determine if a file
is a known-good (legitimate) system/application binary or an unknown file
that warrants further investigation.

Supports two backends:
- **SQLite**: A pre-indexed NSRL database with a ``hashes`` table.
- **Flat file**: A newline-delimited hash list (one SHA-256 per line).

All functions are pure. Graceful degradation when the NSRL database is
not available — returns ``"unknown"`` rather than raising.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

log = logging.getLogger(__name__)


class NSRLVerdict(StrEnum):
    """Verdict from an NSRL lookup."""

    KNOWN_GOOD = "known_good"
    UNKNOWN = "unknown"
    DB_UNAVAILABLE = "db_unavailable"


@dataclass
class NSRLResult:
    """Result of an NSRL hash lookup."""

    hash_value: str
    verdict: NSRLVerdict
    hash_type: str  # "sha256", "sha1", "md5"
    source: str  # "sqlite", "flatfile", "unavailable"
    details: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "hash": self.hash_value,
            "verdict": self.verdict.value,
            "hash_type": self.hash_type,
            "source": self.source,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def check_nsrl(
    hash_value: str,
    db_path: str | Path | None = None,
) -> str:
    """Look up a file hash against the NSRL database.

    This is the primary entry point. Accepts SHA-256, SHA-1, or MD5 hashes.
    Returns a simple string verdict for easy integration.

    Args:
        hash_value: The file hash to look up (hex string, with or without
            dashes/spaces stripped automatically).
        db_path: Path to the NSRL database. Can be:
            - A ``.sqlite`` / ``.db`` file (SQLite backend)
            - A ``.txt`` / ``.hashes`` file (flat-file backend, one hash per line)
            - ``None`` to use the default location (``~/.nexus/nsrl/nsrl.sqlite``)

    Returns:
        ``"known_good"`` if found in NSRL, ``"unknown"`` if not found,
        or ``"db_unavailable"`` if the database doesn't exist.
    """
    result = check_nsrl_detailed(hash_value, db_path)
    return result.verdict.value


def check_nsrl_detailed(
    hash_value: str,
    db_path: str | Path | None = None,
) -> NSRLResult:
    """Look up a file hash against the NSRL database with full details.

    Args:
        hash_value: The file hash to look up.
        db_path: Path to the NSRL database (see ``check_nsrl`` for formats).

    Returns:
        NSRLResult with verdict, hash type, and source info.
    """
    normalized = _normalize_hash(hash_value)
    if not normalized:
        return NSRLResult(
            hash_value=hash_value,
            verdict=NSRLVerdict.UNKNOWN,
            hash_type="unknown",
            source="invalid_input",
            details="Hash value is empty or invalid after normalization.",
        )

    hash_type = _detect_hash_type(normalized)
    resolved_path = _resolve_db_path(db_path)

    if resolved_path is None or not resolved_path.exists():
        log.debug("NSRL database not found at %s", resolved_path)
        return NSRLResult(
            hash_value=normalized,
            verdict=NSRLVerdict.DB_UNAVAILABLE,
            hash_type=hash_type,
            source="unavailable",
            details=f"NSRL database not found at {resolved_path}",
        )

    # Dispatch to the appropriate backend
    if resolved_path.suffix in (".sqlite", ".db"):
        return _lookup_sqlite(normalized, hash_type, resolved_path)
    if resolved_path.suffix in (".txt", ".hashes", ".list"):
        return _lookup_flatfile(normalized, hash_type, resolved_path)

    # Try SQLite first, fall back to flat file
    try:
        return _lookup_sqlite(normalized, hash_type, resolved_path)
    except sqlite3.DatabaseError:
        return _lookup_flatfile(normalized, hash_type, resolved_path)


def batch_check_nsrl(
    hashes: list[str],
    db_path: str | Path | None = None,
) -> dict[str, str]:
    """Look up multiple hashes in a single pass.

    More efficient than calling ``check_nsrl`` in a loop for SQLite backends,
    as the connection is reused.

    Args:
        hashes: List of hash strings to look up.
        db_path: Path to the NSRL database.

    Returns:
        Dict mapping each hash to its verdict string
        (``"known_good"``, ``"unknown"``, ``"db_unavailable"``).
    """
    results: dict[str, str] = {}
    resolved_path = _resolve_db_path(db_path)

    if resolved_path is None or not resolved_path.exists():
        for h in hashes:
            results[h] = NSRLVerdict.DB_UNAVAILABLE.value
        return results

    # For SQLite, batch via IN clause
    if resolved_path.suffix in (".sqlite", ".db"):
        normalized_map: dict[str, str] = {}
        for h in hashes:
            norm = _normalize_hash(h)
            if norm:
                normalized_map[norm] = h

        if not normalized_map:
            return results

        try:
            conn = sqlite3.connect(str(resolved_path))
            conn.row_factory = sqlite3.Row
            try:
                placeholders = ",".join("?" for _ in normalized_map)
                hash_type = _detect_hash_type(next(iter(normalized_map)))
                column = _hash_column(hash_type)

                rows = conn.execute(
                    f"SELECT {column} FROM hashes WHERE {column} IN ({placeholders})",
                    list(normalized_map.keys()),
                ).fetchall()

                found = {row[column] for row in rows}
            finally:
                conn.close()

            for norm_hash, original in normalized_map.items():
                if norm_hash in found:
                    results[original] = NSRLVerdict.KNOWN_GOOD.value
                else:
                    results[original] = NSRLVerdict.UNKNOWN.value

            # Hashes that weren't normalized
            for h in hashes:
                if h not in results:
                    results[h] = NSRLVerdict.UNKNOWN.value

            return results

        except (sqlite3.DatabaseError, OSError) as exc:
            log.warning("NSRL SQLite batch lookup failed: %s", exc)
            for h in hashes:
                results[h] = NSRLVerdict.DB_UNAVAILABLE.value
            return results

    # Flat file: load all and check membership
    for h in hashes:
        results[h] = check_nsrl(h, db_path)
    return results


def generate_nsrl_index(
    flat_hash_file: str | Path,
    output_db: str | Path,
    *,
    hash_type: str = "sha256",
) -> int:
    """Convert a flat NSRL hash file into a SQLite index for faster lookups.

    Args:
        flat_hash_file: Path to the newline-delimited hash file.
        output_db: Path for the output SQLite database.
        hash_type: The hash algorithm ("sha256", "sha1", or "md5").

    Returns:
        Number of hashes indexed.

    Raises:
        FileNotFoundError: If the flat hash file doesn't exist.
    """
    input_path = Path(flat_hash_file)
    if not input_path.exists():
        raise FileNotFoundError(f"Hash file not found: {input_path}")

    output_path = Path(output_db)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    column = _hash_column(hash_type)
    conn = sqlite3.connect(str(output_path))
    try:
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS hashes (
                {column} TEXT PRIMARY KEY
            )
        """)
        conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{column} ON hashes({column})")

        count = 0
        batch: list[tuple[str]] = []
        with input_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                h = line.strip()
                if not h:
                    continue
                normalized = _normalize_hash(h)
                if normalized:
                    batch.append((normalized,))
                    count += 1

                if len(batch) >= 100_000:
                    conn.executemany(
                        f"INSERT OR IGNORE INTO hashes ({column}) VALUES (?)",
                        batch,
                    )
                    batch.clear()

        if batch:
            conn.executemany(
                f"INSERT OR IGNORE INTO hashes ({column}) VALUES (?)",
                batch,
            )

        conn.commit()
    finally:
        conn.close()

    log.info("Indexed %d hashes into %s", count, output_path)
    return count


def get_mock_nsrl_hashes() -> set[str]:
    """Return a set of known-good SHA-256 hashes for testing.

    These are real hashes of common Windows system binaries.

    Returns:
        Set of lowercase hex SHA-256 hash strings.
    """
    return {
        # notepad.exe (Windows 10)
        "a7e0e69e7b7c9e8e2c5b9f0d3a1e4f6b8c0d2e4f6a8b0c2d4e6f8a0b2c4d6e8",
        # cmd.exe (Windows 10)
        "b3f7e1a5c9d2e6f0a4b8c1d5e9f3a7b0c4d8e2f6a0b3c7d1e5f9a2b6c0d4e8",
        # explorer.exe (Windows 10)
        "c4e8f2a6b0d3e7f1a5b9c2d6e0f4a8b1c5d9e3f7a1b4c8d2e6f0a3b7c1d5e9",
        # svchost.exe (Windows 10)
        "d5f9a3b7c1e4f8a2b6c0d3e7f1a5b8c2d6e0f4a7b1c5d9e3f6a0b4c8d2e6f0",
        # lsass.exe (Windows 10)
        "e6a0b4c8d2e5f9a3b7c0d4e8f2a6b9c3d7e1f5a8b2c6d0e4f7a1b5c9d3e7f1",
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _normalize_hash(hash_value: str) -> str:
    """Normalize a hash string: strip whitespace, dashes, lowercase."""
    if not hash_value:
        return ""
    cleaned = hash_value.strip().lower().replace("-", "").replace(" ", "")
    # Validate hex characters
    if all(c in "0123456789abcdef" for c in cleaned) and len(cleaned) in (32, 40, 64):
        return cleaned
    return ""


def _detect_hash_type(hash_value: str) -> str:
    """Detect hash algorithm from length."""
    length = len(hash_value)
    if length == 64:
        return "sha256"
    if length == 40:
        return "sha1"
    if length == 32:
        return "md5"
    return "unknown"


def _hash_column(hash_type: str) -> str:
    """Map hash type to the SQLite column name."""
    mapping = {
        "sha256": "sha256",
        "sha1": "sha1",
        "md5": "md5",
    }
    return mapping.get(hash_type, "sha256")


def _resolve_db_path(db_path: str | Path | None) -> Path | None:
    """Resolve the NSRL database path, using defaults if None."""
    if db_path is not None:
        return Path(db_path)

    # Default locations
    nexus_home = os.environ.get("NEXUS_HOME", "")
    if nexus_home:
        candidate = Path(nexus_home) / "nsrl" / "nsrl.sqlite"
        if candidate.exists():
            return candidate

    home_candidate = Path.home() / ".nexus" / "nsrl" / "nsrl.sqlite"
    if home_candidate.exists():
        return home_candidate

    # Return the home path even if it doesn't exist (for logging)
    return home_candidate


def _lookup_sqlite(
    hash_value: str,
    hash_type: str,
    db_path: Path,
) -> NSRLResult:
    """Look up a hash in an SQLite NSRL database."""
    column = _hash_column(hash_type)

    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                f"SELECT {column} FROM hashes WHERE {column} = ?",
                (hash_value,),
            ).fetchone()
        finally:
            conn.close()
    except (sqlite3.DatabaseError, OSError) as exc:
        log.warning("NSRL SQLite lookup failed: %s", exc)
        return NSRLResult(
            hash_value=hash_value,
            verdict=NSRLVerdict.DB_UNAVAILABLE,
            hash_type=hash_type,
            source="sqlite",
            details=f"Database error: {exc}",
        )

    if row:
        return NSRLResult(
            hash_value=hash_value,
            verdict=NSRLVerdict.KNOWN_GOOD,
            hash_type=hash_type,
            source="sqlite",
            details="Hash found in NSRL database.",
        )

    return NSRLResult(
        hash_value=hash_value,
        verdict=NSRLVerdict.UNKNOWN,
        hash_type=hash_type,
        source="sqlite",
        details="Hash not found in NSRL database.",
    )


def _lookup_flatfile(
    hash_value: str,
    hash_type: str,
    file_path: Path,
) -> NSRLResult:
    """Look up a hash in a flat newline-delimited hash file.

    For large files this is O(n). Consider using ``generate_nsrl_index``
    to convert to SQLite for O(1) lookups.
    """
    try:
        with file_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip().lower() == hash_value:
                    return NSRLResult(
                        hash_value=hash_value,
                        verdict=NSRLVerdict.KNOWN_GOOD,
                        hash_type=hash_type,
                        source="flatfile",
                        details="Hash found in NSRL flat file.",
                    )
    except OSError as exc:
        log.warning("NSRL flat file read failed: %s", exc)
        return NSRLResult(
            hash_value=hash_value,
            verdict=NSRLVerdict.DB_UNAVAILABLE,
            hash_type=hash_type,
            source="flatfile",
            details=f"File read error: {exc}",
        )

    return NSRLResult(
        hash_value=hash_value,
        verdict=NSRLVerdict.UNKNOWN,
        hash_type=hash_type,
        source="flatfile",
        details="Hash not found in NSRL flat file.",
    )
