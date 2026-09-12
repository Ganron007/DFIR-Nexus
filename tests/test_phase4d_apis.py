"""Tests for Phase 4d workflow APIs: filesystem picker + parser ledger."""
import sys

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.dashboard.app import create_dashboard


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    dashboard = create_dashboard()
    app = Starlette(routes=dashboard)
    return TestClient(app)


def test_fs_list_drives(client):
    """Drive roots listed when no path given (Windows-only; POSIX lists /)."""
    if sys.platform != "win32":
        pytest.skip("drive-letter listing is Windows-only")
    r = client.get("/portal/api/fs/list")
    assert r.status_code == 200
    body = r.json()
    assert body["drives"] is True
    assert isinstance(body["entries"], list)


def test_fs_list_root_posix(client):
    """No path on POSIX → root listing, not drive letters."""
    if sys.platform == "win32":
        pytest.skip("POSIX-only behavior")
    r = client.get("/portal/api/fs/list")
    assert r.status_code == 200
    body = r.json()
    assert body["drives"] is False
    assert isinstance(body["entries"], list)


def test_fs_list_directory(client, tmp_path):
    """Directory listing returns dirs + files with sizes."""
    (tmp_path / "sub").mkdir()
    (tmp_path / "file.csv").write_text("a,b\n", encoding="utf-8")
    r = client.get(f"/portal/api/fs/list?path={tmp_path}")
    assert r.status_code == 200
    body = r.json()
    assert body["drives"] is False
    names = [e["name"] for e in body["entries"]]
    assert "sub" in names
    assert "file.csv" in {e["name"] for e in body["entries"] if not e["is_dir"]}


def test_fs_list_missing(client):
    r = client.get("/portal/api/fs/list?path=Z:\\definitely-not-here-12345")
    assert r.status_code == 404


def test_pipeline_ledger_no_run(client):
    """Ledger with no run returns an empty ledger, not an error."""
    r = client.post("/portal/api/case/create", json={"name": "Ledger Test"})
    assert r.status_code == 200
    case_id = r.json()["case_id"]
    r = client.get("/portal/api/pipeline/ledger", headers={"X-Nexus-Case": case_id})
    assert r.status_code == 200
    body = r.json()
    assert body["ledger"] == []
    assert body["run_id"] == ""
