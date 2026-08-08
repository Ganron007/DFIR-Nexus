"""Dynamic tables — LLM-created persistent SQLite tables at runtime.

Allows the LLM agent to create, populate, query, and drop arbitrary
SQLite tables for structured analysis output.  Pre-built tables are
created on first use for common DFIR workflows:
- ``gap_analyses``: Detection gap analysis results
- ``source_comparisons``: Cross-source comparison data
- ``threat_actor_profiles``: Extended actor profile notes

No external dependencies — uses only ``sqlite3``.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_PRE_BUILT_TABLES: dict[str, str] = {
    "gap_analyses": """
        CREATE TABLE IF NOT EXISTS gap_analyses (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            technique_id    TEXT NOT NULL,
            technique_name  TEXT NOT NULL DEFAULT '',
            tactic          TEXT NOT NULL DEFAULT '',
            status          TEXT NOT NULL DEFAULT 'uncovered',
            rule_count      INTEGER NOT NULL DEFAULT 0,
            actor_overlap   TEXT NOT NULL DEFAULT '[]',
            recommendation  TEXT NOT NULL DEFAULT '',
            properties      TEXT NOT NULL DEFAULT '{}',
            created_at      TEXT NOT NULL
        )
    """,
    "source_comparisons": """
        CREATE TABLE IF NOT EXISTS source_comparisons (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            artifact_type   TEXT NOT NULL,
            source_a        TEXT NOT NULL DEFAULT '',
            source_b        TEXT NOT NULL DEFAULT '',
            field_name      TEXT NOT NULL DEFAULT '',
            value_a         TEXT NOT NULL DEFAULT '',
            value_b         TEXT NOT NULL DEFAULT '',
            match_status    TEXT NOT NULL DEFAULT 'unknown',
            notes           TEXT NOT NULL DEFAULT '',
            properties      TEXT NOT NULL DEFAULT '{}',
            created_at      TEXT NOT NULL
        )
    """,
    "threat_actor_profiles": """
        CREATE TABLE IF NOT EXISTS threat_actor_profiles (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id        TEXT NOT NULL,
            actor_name      TEXT NOT NULL DEFAULT '',
            campaign        TEXT NOT NULL DEFAULT '',
            ttps            TEXT NOT NULL DEFAULT '[]',
            indicators      TEXT NOT NULL DEFAULT '[]',
            assessment      TEXT NOT NULL DEFAULT '',
            confidence      REAL NOT NULL DEFAULT 0.5,
            properties      TEXT NOT NULL DEFAULT '{}',
            created_at      TEXT NOT NULL
        )
    """,
}

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()


def _validate_identifier(name: str) -> None:
    """Raise ``ValueError`` if *name* is not a safe SQL identifier."""
    if not _IDENTIFIER_RE.match(name):
        raise ValueError(
            f"Invalid identifier {name!r}. "
            "Must start with a letter/underscore and contain only alphanumeric characters/underscores."
        )


class DynamicTableManager:
    """Manages LLM-created persistent SQLite tables.

    Args:
        db_path: Path to the SQLite database file.  Created on first use.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._conn: sqlite3.Connection | None = None
        self._initialized = False

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(
                str(self._path),
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        if not self._initialized:
            self._ensure_prebuilt_tables()
            self._initialized = True
        return self._conn

    def _ensure_prebuilt_tables(self) -> None:
        """Create pre-built tables if they don't already exist."""
        conn = self._conn
        if conn is None:
            return
        for name, ddl in _PRE_BUILT_TABLES.items():
            try:
                conn.execute(ddl)
            except Exception as e:
                log.warning("Failed to create pre-built table %s: %s", name, e)
        conn.commit()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ── Core operations ───────────────────────────────────────────────

    def create_table(
        self,
        table_name: str,
        columns: dict[str, str],
        *,
        if_not_exists: bool = True,
    ) -> bool:
        """Create a new table with the given columns.

        Args:
            table_name: Name of the table (alphanumeric + underscores).
            columns: Mapping of column name to SQL type definition,
                e.g. ``{"name": "TEXT NOT NULL", "score": "REAL"}``.
            if_not_exists: If ``True`` (default), use ``IF NOT EXISTS``.

        Returns:
            ``True`` on success.

        Raises:
            ValueError: If *table_name* is not a safe identifier.
        """
        _validate_identifier(table_name)
        exists_clause = "IF NOT EXISTS " if if_not_exists else ""
        col_defs = ", ".join(
            f"{col_name} {col_type}" for col_name, col_type in columns.items()
        )
        # Always include an auto-increment id and created_at
        ddl = (
            f"CREATE TABLE {exists_clause}{table_name} ("
            f"  id INTEGER PRIMARY KEY AUTOINCREMENT, "
            f"  {col_defs}, "
            f"  created_at TEXT NOT NULL"
            f")"
        )
        conn = self._get_conn()
        conn.execute(ddl)
        conn.commit()
        return True

    def insert_row(
        self,
        table_name: str,
        data: dict[str, Any],
    ) -> int:
        """Insert a row into a dynamic table.

        Args:
            table_name: Target table.
            data: Column-value mapping.  ``created_at`` is auto-set.

        Returns:
            The ``id`` of the inserted row.

        Raises:
            ValueError: If *table_name* is not a safe identifier.
        """
        _validate_identifier(table_name)
        now = _utcnow()
        data_with_ts = {**data, "created_at": now}
        cols = list(data_with_ts.keys())
        placeholders = ", ".join(["?"] * len(cols))
        col_names = ", ".join(cols)
        values = [
            json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v
            for v in data_with_ts.values()
        ]
        conn = self._get_conn()
        cur = conn.execute(
            f"INSERT INTO {table_name} ({col_names}) VALUES ({placeholders})",
            values,
        )
        conn.commit()
        return cur.lastrowid or 0

    def query(
        self,
        table_name: str,
        *,
        where: str | None = None,
        params: list[Any] | None = None,
        order_by: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query rows from a dynamic table.

        Args:
            table_name: Table to query.
            where: Optional WHERE clause (without the ``WHERE`` keyword).
            params: Bind parameters for the WHERE clause.
            order_by: Optional ORDER BY clause.
            limit: Max rows to return (default 100).
            offset: Row offset.

        Returns:
            List of row dicts.
        """
        _validate_identifier(table_name)
        sql = f"SELECT * FROM {table_name}"
        bind: list[Any] = list(params or [])
        if where:
            sql += f" WHERE {where}"
        if order_by:
            sql += f" ORDER BY {order_by}"
        sql += " LIMIT ? OFFSET ?"
        bind.extend([limit, offset])

        conn = self._get_conn()
        rows = conn.execute(sql, bind).fetchall()
        return [dict(r) for r in rows]

    def drop_table(self, table_name: str) -> bool:
        """Drop a table.  Returns ``True`` if the table existed.

        Pre-built tables can also be dropped (use with caution).

        Raises:
            ValueError: If *table_name* is not a safe identifier.
        """
        _validate_identifier(table_name)
        conn = self._get_conn()
        try:
            conn.execute(f"DROP TABLE IF EXISTS {table_name}")
            conn.commit()
            return True
        except Exception:
            return False

    def list_tables(self) -> list[str]:
        """List all user-created and pre-built tables in the database."""
        rows = self._get_conn().execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        return [r["name"] for r in rows]

    def describe_table(self, table_name: str) -> list[dict[str, str]]:
        """Return column info for a table (name, type, nullable, default)."""
        _validate_identifier(table_name)
        rows = self._get_conn().execute(f"PRAGMA table_info({table_name})").fetchall()
        return [
            {
                "name": r["name"],
                "type": r["type"],
                "notnull": str(r["notnull"]),
                "default": str(r["dflt_value"]),
            }
            for r in rows
        ]

    def count_rows(self, table_name: str) -> int:
        """Return the number of rows in a table."""
        _validate_identifier(table_name)
        row = self._get_conn().execute(
            f"SELECT COUNT(*) as cnt FROM {table_name}"
        ).fetchone()
        return row["cnt"] if row else 0
