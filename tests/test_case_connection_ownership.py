"""D416: each temporary finding-store owner closes its own SQLite connection."""
from __future__ import annotations

import sqlite3

import pytest


@pytest.fixture
def opened_managers(monkeypatch):
    from nexus.case import compat

    original = compat.get_sqlite_manager
    managers = []

    def open_manager(*args, **kwargs):
        manager = original(*args, **kwargs)
        managers.append(manager)
        return manager

    monkeypatch.setattr(compat, "get_sqlite_manager", open_manager)
    yield managers
    for manager in managers:
        manager.close()


def assert_closed(managers):
    assert managers
    for manager in managers:
        with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
            manager.store._conn.execute("SELECT 1")


@pytest.mark.parametrize("candidate", ["F-resource-001", "not-a-sequence"])
def test_uniqueness_lookup_closes_its_manager_on_every_return(candidate, opened_managers):
    from nexus.case_manager import _global_unique_finding_id

    assert _global_unique_finding_id(candidate, "CASE-RESOURCE") == candidate
    assert_closed(opened_managers)


def test_uniqueness_lookup_closes_its_manager_on_read_failure(opened_managers, monkeypatch):
    from nexus.case.store import SQLiteStore
    from nexus.case_manager import _global_unique_finding_id

    def fail_read(*args):
        raise sqlite3.OperationalError("diagnostic read failure")

    monkeypatch.setattr(SQLiteStore, "get_finding", fail_read)
    assert _global_unique_finding_id("F-resource-001", "CASE-RESOURCE") == "F-resource-001"
    assert_closed(opened_managers)


@pytest.mark.parametrize("fail_write", [False, True])
def test_real_staging_closes_lookup_and_dual_write_connections(
    tmp_path, opened_managers, monkeypatch, fail_write,
):
    from nexus.audit import AuditWriter
    from nexus.case import CaseManager
    from nexus.case.store import SQLiteStore
    from nexus.case_manager import CaseManager as FlatManager
    from nexus.config import settings

    manager = CaseManager(settings.cases_root / "cases.db")
    try:
        case = manager.create_case(name="Connection ownership")
    finally:
        manager.close()
    case_dir = settings.cases_root / case.id
    marker = tmp_path / "resource-lifetime.txt"
    marker.write_text("connection ownership fixture", encoding="utf-8")
    audit = AuditWriter("resource", audit_dir=case_dir / "audit")
    aid = audit.log("read_file", params={"path": str(marker)},
                    result_summary={"text": marker.read_text(encoding="utf-8")})
    assert aid
    if fail_write:
        def fail_save(*args):
            raise sqlite3.OperationalError("diagnostic write failure")
        monkeypatch.setattr(SQLiteStore, "save_finding", fail_save)
    result = FlatManager().record_finding({
        "title": "Resource lifetime fixture was read",
        "observation": marker.read_text(encoding="utf-8"),
        "interpretation": "Unit-test resource ownership control",
        "confidence": "LOW", "confidence_justification": "Resource ownership control only",
        "audit_ids": [aid], "evidence": [{"audit_id": aid, "source": "read_file", "path": str(marker)}],
    }, case_dir=case_dir)
    assert result["status"] == "STAGED", result
    assert len(opened_managers) == 2
    assert_closed(opened_managers)
    if not fail_write:
        manager = CaseManager(settings.cases_root / "cases.db")
        try:
            assert manager.get_finding(result["finding_id"]) is not None
        finally:
            manager.close()
