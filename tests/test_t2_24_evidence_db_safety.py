"""Tests for In-Evidence Database Safety (WP 10.40 / T2-24)."""

import json
import sqlite3
from pathlib import Path

import pytest

from nexus.tools.evidence_db import (
    DatabaseSecurityError,
    ReadOnlyEvidenceDatabase,
    query_evidence_sqlite,
)


@pytest.fixture
def sample_evidence_db(tmp_path: Path) -> Path:
    db_file = tmp_path / "browser_history.sqlite"
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)")
    cur.execute("CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, received_bytes INTEGER)")
    for i in range(1, 25):
        cur.execute(
            "INSERT INTO visits VALUES (?, ?, ?, ?)",
            (i, f"https://example.com/page{i}", f"Page {i}", i * 2),
        )
    conn.commit()
    conn.close()
    return db_file


def test_select_queries_allowed(sample_evidence_db: Path):
    """Legitimate analytical SELECT queries must succeed."""
    res = query_evidence_sqlite(
        sample_evidence_db,
        "SELECT id, url, title FROM visits WHERE id <= 5 ORDER BY id",
    )
    assert res["columns"] == ["id", "url", "title"]
    assert len(res["rows"]) == 5
    assert res["rows"][0] == [1, "https://example.com/page1", "Page 1"]
    assert res["row_count"] == 5
    assert not res["truncated"]


def test_insert_blocked_by_engine_authorizer(sample_evidence_db: Path):
    """INSERT statements must be rejected by the engine-level authorizer."""
    db = ReadOnlyEvidenceDatabase(sample_evidence_db)
    with pytest.raises(DatabaseSecurityError, match="Database mutation rejected"):
        db.query("INSERT INTO visits VALUES (999, 'https://evil.com', 'Evil', 1)")


def test_update_and_delete_blocked(sample_evidence_db: Path):
    """UPDATE and DELETE statements must be rejected."""
    db = ReadOnlyEvidenceDatabase(sample_evidence_db)
    with pytest.raises(DatabaseSecurityError, match="Database mutation rejected"):
        db.query("UPDATE visits SET title = 'Hacked' WHERE id = 1")

    with pytest.raises(DatabaseSecurityError, match="Database mutation rejected"):
        db.query("DELETE FROM visits WHERE id = 1")


def test_ddl_and_attach_blocked(sample_evidence_db: Path, tmp_path: Path):
    """DROP, ALTER, CREATE, and ATTACH statements must be rejected."""
    db = ReadOnlyEvidenceDatabase(sample_evidence_db)
    with pytest.raises(DatabaseSecurityError, match="Database mutation rejected"):
        db.query("DROP TABLE visits")

    with pytest.raises(DatabaseSecurityError, match="Database mutation rejected"):
        db.query("ALTER TABLE visits ADD COLUMN hacked TEXT")

    with pytest.raises(DatabaseSecurityError, match="Database mutation rejected"):
        db.query("CREATE TABLE rogue (id INT)")

    external_db = tmp_path / "external.db"
    with pytest.raises(DatabaseSecurityError, match="Database mutation rejected"):
        db.query(f"ATTACH DATABASE '{external_db.as_posix()}' AS ext")


def test_row_and_column_caps(sample_evidence_db: Path):
    """Results must honor configured max_rows and max_cols."""
    db = ReadOnlyEvidenceDatabase(sample_evidence_db, max_rows=10, max_cols=2)
    res = db.query("SELECT * FROM visits ORDER BY id")
    assert len(res["rows"]) == 10
    assert res["truncated"] is True
    # Only 2 columns preserved
    assert len(res["columns"]) == 2
    assert len(res["rows"][0]) == 2


def test_schema_and_table_listing(sample_evidence_db: Path):
    """Listing tables and schema extraction must work cleanly."""
    db = ReadOnlyEvidenceDatabase(sample_evidence_db)
    tables = db.list_tables()
    assert "visits" in tables
    assert "downloads" in tables

    schema = db.get_table_schema("visits")
    col_names = [c["name"] for c in schema]
    assert "id" in col_names
    assert "url" in col_names
    assert "title" in col_names
    assert "visit_count" in col_names


def test_audit_logging(sample_evidence_db: Path, tmp_path: Path):
    """Audit log must record telemetry for queries."""
    audit_file = tmp_path / "audit" / "db_audit.jsonl"
    db = ReadOnlyEvidenceDatabase(sample_evidence_db, audit_log_path=audit_file)
    db.query("SELECT COUNT(*) FROM visits")

    assert audit_file.is_file()
    lines = audit_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["row_count"] == 1
    assert "SELECT COUNT(*)" in record["sql"]
    assert record["truncated"] is False
    assert "elapsed_ms" in record
