"""Engine-level read-only safety for in-evidence SQLite databases (WP 10.40 / T2-24).

Enforces read-only execution at the SQLite engine level using sqlite3.set_authorizer
(blocking INSERT/UPDATE/DELETE/ATTACH/DETACH/DDL/load_extension), opening via
URI mode=ro, applying row and column caps, and recording audit telemetry.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import sqlite3
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Forbidden authorizer action codes
_FORBIDDEN_ACTIONS = {
    sqlite3.SQLITE_INSERT,
    sqlite3.SQLITE_UPDATE,
    sqlite3.SQLITE_DELETE,
    sqlite3.SQLITE_ATTACH,
    sqlite3.SQLITE_DETACH,
    sqlite3.SQLITE_ALTER_TABLE,
    sqlite3.SQLITE_DROP_TABLE,
    sqlite3.SQLITE_DROP_INDEX,
    sqlite3.SQLITE_DROP_VIEW,
    sqlite3.SQLITE_DROP_TRIGGER,
    sqlite3.SQLITE_CREATE_TABLE,
    sqlite3.SQLITE_CREATE_INDEX,
    sqlite3.SQLITE_CREATE_VIEW,
    sqlite3.SQLITE_CREATE_TRIGGER,
}


class DatabaseSecurityError(PermissionError):
    """Raised when an operation attempts unauthorized mutation on an in-evidence database."""


def _authorizer_callback(action_code: int, arg1: str | None, arg2: str | None, db_name: str | None, trigger_name: str | None) -> int:
    """Authorizer callback invoked by the SQLite engine for every statement compile step."""
    if action_code in _FORBIDDEN_ACTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


class ReadOnlyEvidenceDatabase:
    """Safe wrapper for querying forensic SQLite databases inside evidence."""

    def __init__(
        self,
        db_path: Path | str,
        *,
        max_rows: int = 1000,
        max_cols: int = 50,
        audit_log_path: Path | None = None,
    ) -> None:
        self.db_path = Path(db_path).resolve()
        if not self.db_path.is_file():
            raise FileNotFoundError(f"Evidence database not found: {self.db_path}")
        self.max_rows = max_rows
        self.max_cols = max_cols
        self.audit_log_path = audit_log_path

    def _open_connection(self) -> sqlite3.Connection:
        # Open in URI read-only mode
        uri = f"file:{self.db_path.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=10.0)
        # Register engine-level authorizer
        conn.set_authorizer(_authorizer_callback)
        # Explicitly disable load extension if supported
        if hasattr(conn, "enable_load_extension"):
            with contextlib.suppress(Exception):
                conn.enable_load_extension(False)
        return conn

    def query(
        self,
        sql: str,
        params: tuple | dict | None = None,
    ) -> dict[str, Any]:
        """Execute query safely under engine-level read-only enforcement."""
        start_time = time.perf_counter()
        query_hash = hashlib.sha256(sql.strip().encode("utf-8")).hexdigest()[:16]
        conn = self._open_connection()
        try:
            cursor = conn.cursor()
            try:
                cursor.execute(sql, params or ())
            except sqlite3.DatabaseError as exc:
                if "not authorized" in str(exc).lower():
                    raise DatabaseSecurityError(
                        f"Database mutation rejected: query attempted unauthorized operation ({exc})"
                    ) from exc
                raise

            columns = [d[0] for d in cursor.description] if cursor.description else []
            if len(columns) > self.max_cols:
                columns = columns[:self.max_cols]

            raw_rows = cursor.fetchmany(self.max_rows + 1)
            truncated = len(raw_rows) > self.max_rows
            rows = [list(r[:self.max_cols]) for r in raw_rows[:self.max_rows]]

            elapsed_ms = (time.perf_counter() - start_time) * 1000.0

            # Record audit telemetry
            self._record_audit(
                sql=sql,
                query_hash=query_hash,
                row_count=len(rows),
                truncated=truncated,
                elapsed_ms=elapsed_ms,
            )

            return {
                "columns": columns,
                "rows": rows,
                "row_count": len(rows),
                "truncated": truncated,
                "elapsed_ms": elapsed_ms,
            }
        finally:
            conn.close()

    def list_tables(self) -> list[str]:
        """List table names in the evidence database."""
        res = self.query("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        return [r[0] for r in res["rows"]]

    def get_table_schema(self, table_name: str) -> list[dict[str, Any]]:
        """Get column schema info for a specific table."""
        # Sanitize table name to prevent SQL injection in pragma
        safe_name = "".join(c for c in table_name if c.isalnum() or c in ("_", "-"))
        res = self.query(f"PRAGMA table_info({safe_name})")
        schema = []
        for r in res["rows"]:
            # cid, name, type, notnull, dflt_value, pk
            schema.append({
                "cid": r[0],
                "name": r[1],
                "type": r[2],
                "notnull": bool(r[3]),
                "default": r[4],
                "pk": bool(r[5]),
            })
        return schema

    def _record_audit(
        self,
        sql: str,
        query_hash: str,
        row_count: int,
        truncated: bool,
        elapsed_ms: float,
    ) -> None:
        audit_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "db_path": str(self.db_path),
            "query_hash": query_hash,
            "sql": sql[:200],
            "row_count": row_count,
            "truncated": truncated,
            "elapsed_ms": round(elapsed_ms, 2),
        }
        logger.debug("Evidence DB query: %s", audit_entry)
        if self.audit_log_path:
            try:
                self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
                with self.audit_log_path.open("a", encoding="utf-8") as f:
                    import json
                    f.write(json.dumps(audit_entry) + "\n")
            except Exception as exc:
                logger.warning("Failed writing evidence DB audit: %s", exc)


def query_evidence_sqlite(
    db_path: Path | str,
    query: str,
    params: tuple | dict | None = None,
    *,
    max_rows: int = 1000,
    max_cols: int = 50,
) -> dict[str, Any]:
    """Convenience helper to safely query an in-evidence SQLite database."""
    session = ReadOnlyEvidenceDatabase(db_path, max_rows=max_rows, max_cols=max_cols)
    return session.query(query, params)
