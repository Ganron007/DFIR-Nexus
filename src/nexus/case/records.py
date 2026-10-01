"""Canonical case records (WO-B1).

SQLite holds the document. The flat JSON file is a mirror written in the same
transaction's success path, so existing readers keep working. A failed database
write does not publish a mirror that the database does not have.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS case_records (
    case_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    record_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    doc_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (case_id, kind, record_id)
)
"""


def records_db_path() -> Path:
    from nexus.config import settings

    root = Path(settings.cases_root)
    root.mkdir(parents=True, exist_ok=True)
    return root / "cases.db"


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute(_SCHEMA)
    return conn


def save_records(
    case_dir: Path | str,
    kind: str,
    records: list[dict[str, Any]],
    *,
    mirror_name: str,
    id_field: str = "id",
    db_path: Path | None = None,
) -> None:
    """Replace one kind for this case and rewrite the flat mirror."""
    case_dir = Path(case_dir)
    case_id = case_dir.name
    db_path = db_path or records_db_path()
    now = datetime.now(UTC).isoformat()
    conn = _connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "DELETE FROM case_records WHERE case_id = ? AND kind = ?",
            (case_id, kind),
        )
        for position, doc in enumerate(records):
            record_id = str(
                doc.get(id_field)
                or doc.get("finding_id")
                or doc.get("event_id")
                or doc.get("id")
                or position
            )
            conn.execute(
                """
                INSERT INTO case_records
                    (case_id, kind, record_id, position, doc_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    kind,
                    record_id,
                    position,
                    json.dumps(doc, default=str),
                    now,
                ),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    mirror = case_dir / mirror_name
    mirror.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(records, indent=2, default=str)
    tmp = mirror.with_name(mirror.name + ".tmp")
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(mirror)


def load_records(
    case_dir: Path | str,
    kind: str,
    *,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    case_id = Path(case_dir).name
    db_path = db_path or records_db_path()
    if not db_path.is_file():
        return []
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT doc_json FROM case_records
            WHERE case_id = ? AND kind = ?
            ORDER BY position
            """,
            (case_id, kind),
        ).fetchall()
    finally:
        conn.close()
    return [json.loads(row["doc_json"]) for row in rows]


def save_findings(
    case_dir: Path | str,
    findings: list[dict[str, Any]],
    *,
    db_path: Path | None = None,
) -> None:
    save_records(
        case_dir,
        "finding",
        findings,
        mirror_name="findings.json",
        db_path=db_path,
    )


def save_timeline(
    case_dir: Path | str,
    events: list[dict[str, Any]],
    *,
    db_path: Path | None = None,
) -> None:
    save_records(
        case_dir,
        "timeline_event",
        events,
        mirror_name="timeline.json",
        id_field="event_id",
        db_path=db_path,
    )


def save_todos(
    case_dir: Path | str,
    todos: list[dict[str, Any]],
    *,
    db_path: Path | None = None,
) -> None:
    save_records(
        case_dir,
        "todo",
        todos,
        mirror_name="todos.json",
        id_field="id",
        db_path=db_path,
    )


def save_iocs(
    case_dir: Path | str,
    iocs: list[dict[str, Any]],
    *,
    db_path: Path | None = None,
) -> None:
    save_records(
        case_dir,
        "ioc",
        iocs,
        mirror_name="iocs.json",
        id_field="id",
        db_path=db_path,
    )
