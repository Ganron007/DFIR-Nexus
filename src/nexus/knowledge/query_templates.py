"""Query templates — save and execute parameterized SQL templates.

Provides a registry of reusable, parameterized query templates with
``{{placeholder}}`` syntax.  Templates are persisted in SQLite with
usage tracking (execution count, last used timestamp).

No external dependencies — uses only ``sqlite3``.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_TEMPLATE_DDL = """
CREATE TABLE IF NOT EXISTS query_templates (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    description     TEXT NOT NULL DEFAULT '',
    sql_template    TEXT NOT NULL,
    placeholders    TEXT NOT NULL DEFAULT '[]',
    default_params  TEXT NOT NULL DEFAULT '{}',
    category        TEXT NOT NULL DEFAULT '',
    usage_count     INTEGER NOT NULL DEFAULT 0,
    last_used_at    TEXT,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_qt_name ON query_templates(name);
CREATE INDEX IF NOT EXISTS idx_qt_category ON query_templates(category);
"""

_PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex[:16]


def _extract_placeholders(sql: str) -> list[str]:
    """Extract unique ``{{name}}`` placeholders from a SQL template string."""
    return list(dict.fromkeys(_PLACEHOLDER_RE.findall(sql)))


def _render_template(sql: str, params: dict[str, Any]) -> tuple[str, list[Any]]:
    """Replace ``{{name}}`` placeholders with ``?`` and return (sql, values).

    Raises:
        KeyError: If a placeholder has no corresponding param.
    """
    placeholders = _extract_placeholders(sql)
    values: list[Any] = []
    rendered = sql
    for ph in placeholders:
        if ph not in params:
            raise KeyError(f"Missing parameter for placeholder '{{{{{ph}}}}}'")
        values.append(params[ph])
        rendered = rendered.replace(f"{{{{{ph}}}}}", "?", 1)
    return rendered, values


class QueryTemplateManager:
    """Manage parameterized query templates in SQLite.

    Args:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._path = Path(db_path)
        self._conn: sqlite3.Connection | None = None

    def _get_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(
                str(self._path),
                check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_TEMPLATE_DDL)
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ── CRUD ──────────────────────────────────────────────────────────

    def create_template(
        self,
        name: str,
        sql_template: str,
        *,
        description: str = "",
        default_params: dict[str, Any] | None = None,
        category: str = "",
        template_id: str | None = None,
    ) -> str:
        """Register a new query template.

        Placeholders are auto-extracted from *sql_template* using
        ``{{name}}`` syntax.

        Args:
            name: Unique template name.
            sql_template: SQL with ``{{placeholder}}`` tokens.
            description: Human-readable description.
            default_params: Default values for placeholders.
            category: Optional grouping label.
            template_id: Optional caller-supplied ID.

        Returns:
            The template ID.

        Raises:
            sqlite3.IntegrityError: If *name* already exists.
        """
        tid = template_id or _new_id()
        now = _utcnow()
        placeholders = _extract_placeholders(sql_template)
        conn = self._get_conn()
        conn.execute(
            "INSERT INTO query_templates "
            "(id, name, description, sql_template, placeholders, default_params, category, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tid,
                name,
                description,
                sql_template,
                json.dumps(placeholders),
                json.dumps(default_params or {}, ensure_ascii=False),
                category,
                now,
                now,
            ),
        )
        conn.commit()
        return tid

    def get_template(self, name_or_id: str) -> dict[str, Any] | None:
        """Retrieve a template by name or ID."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM query_templates WHERE name = ? OR id = ?",
            (name_or_id, name_or_id),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "sql_template": row["sql_template"],
            "placeholders": json.loads(row["placeholders"]),
            "default_params": json.loads(row["default_params"]),
            "category": row["category"],
            "usage_count": row["usage_count"],
            "last_used_at": row["last_used_at"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def execute_template(
        self,
        name_or_id: str,
        params: dict[str, Any] | None = None,
        *,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Execute a parameterized template and return results.

        Merges *default_params* with the caller-supplied *params*
        (caller values take precedence).

        Args:
            name_or_id: Template name or ID.
            params: Values for ``{{placeholder}}`` tokens.
            limit: Max rows to return.

        Returns:
            List of result row dicts.

        Raises:
            KeyError: If a required placeholder has no value.
            ValueError: If the template is not found.
        """
        tmpl = self.get_template(name_or_id)
        if tmpl is None:
            raise ValueError(f"Template not found: {name_or_id}")

        merged = {**tmpl["default_params"], **(params or {})}
        rendered_sql, values = _render_template(tmpl["sql_template"], merged)
        rendered_sql += " LIMIT ?"
        values.append(limit)

        conn = self._get_conn()
        try:
            rows = conn.execute(rendered_sql, values).fetchall()
            results = [dict(r) for r in rows]
        except Exception as e:
            log.error("Template execution failed for %s: %s", name_or_id, e)
            raise

        # Update usage stats
        now = _utcnow()
        conn.execute(
            "UPDATE query_templates SET usage_count = usage_count + 1, last_used_at = ? WHERE id = ?",
            (now, tmpl["id"]),
        )
        conn.commit()

        return results

    def update_template(
        self,
        name_or_id: str,
        *,
        description: str | None = None,
        sql_template: str | None = None,
        default_params: dict[str, Any] | None = None,
        category: str | None = None,
    ) -> bool:
        """Update an existing template.  Returns ``True`` if changed."""
        tmpl = self.get_template(name_or_id)
        if tmpl is None:
            return False
        now = _utcnow()
        new_desc = description if description is not None else tmpl["description"]
        new_sql = sql_template if sql_template is not None else tmpl["sql_template"]
        new_defaults = (
            json.dumps(default_params, ensure_ascii=False)
            if default_params is not None
            else json.dumps(tmpl["default_params"], ensure_ascii=False)
        )
        new_cat = category if category is not None else tmpl["category"]
        new_placeholders = json.dumps(_extract_placeholders(new_sql))
        conn = self._get_conn()
        conn.execute(
            "UPDATE query_templates SET description = ?, sql_template = ?, placeholders = ?, "
            "default_params = ?, category = ?, updated_at = ? WHERE id = ?",
            (new_desc, new_sql, new_placeholders, new_defaults, new_cat, now, tmpl["id"]),
        )
        conn.commit()
        return True

    def delete_template(self, name_or_id: str) -> bool:
        """Delete a template.  Returns ``True`` if deleted."""
        tmpl = self.get_template(name_or_id)
        if tmpl is None:
            return False
        self._get_conn().execute(
            "DELETE FROM query_templates WHERE id = ?", (tmpl["id"],)
        )
        self._get_conn().commit()
        return True

    def list_templates(
        self,
        *,
        category: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List registered templates, optionally filtered by category."""
        conn = self._get_conn()
        if category:
            rows = conn.execute(
                "SELECT * FROM query_templates WHERE category = ? ORDER BY usage_count DESC, name LIMIT ?",
                (category, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM query_templates ORDER BY usage_count DESC, name LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "description": r["description"],
                "sql_template": r["sql_template"],
                "placeholders": json.loads(r["placeholders"]),
                "default_params": json.loads(r["default_params"]),
                "category": r["category"],
                "usage_count": r["usage_count"],
                "last_used_at": r["last_used_at"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]
