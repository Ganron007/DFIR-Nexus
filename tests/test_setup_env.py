"""Environment preflight — .env writer + /portal/api/setup/* endpoints."""

from __future__ import annotations

import os
import sys

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nexus import envfile
from nexus.dashboard.app import create_dashboard


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    dashboard = create_dashboard()
    return TestClient(Starlette(routes=dashboard))


# --- envfile.apply_env -------------------------------------------------------


def test_apply_env_merges_and_preserves(tmp_path):
    """Existing comments/keys survive; allowlisted keys update in place."""
    env_path = tmp_path / ".env"
    env_path.write_text(
        "# comment\nNEXUS_LLM_MODEL=old-model\nOTHER_KEY=keepme\n"
    )
    monkey_env: dict[str, str] = {}
    # apply_env resolves the path via env_file_path() — patch it to tmp.
    import nexus.envfile as ef

    orig = ef.env_file_path
    ef.env_file_path = lambda: env_path
    try:
        applied = ef.apply_env(
            {"NEXUS_LLM_MODEL": "new-model", "NEXUS_ES_URL": "http://127.0.0.1:9200"},
            environ=monkey_env,
        )
    finally:
        ef.env_file_path = orig

    text = env_path.read_text()
    assert "# comment" in text
    assert "OTHER_KEY=keepme" in text
    assert "NEXUS_LLM_MODEL=new-model" in text
    assert "old-model" not in text
    assert "NEXUS_ES_URL=http://127.0.0.1:9200" in text
    assert monkey_env["NEXUS_ES_URL"] == "http://127.0.0.1:9200"
    assert applied["NEXUS_LLM_MODEL"] == "new-model"


def test_apply_env_remove_and_mask(tmp_path):
    """Empty value removes the key; secret values are masked in the return."""
    env_path = tmp_path / ".env"
    env_path.write_text("NEXUS_ES_URL=http://x\n")
    import nexus.envfile as ef
    orig = ef.env_file_path
    ef.env_file_path = lambda: env_path
    environ = {"NEXUS_ES_URL": "http://x"}
    try:
        applied = ef.apply_env(
            {"NEXUS_ES_URL": "", "NEXUS_LLM_API_KEY": "secret123"},
            environ=environ,
        )
    finally:
        ef.env_file_path = orig
    text = env_path.read_text()
    assert "NEXUS_ES_URL" not in text
    assert "NEXUS_ES_URL" not in environ
    assert environ["NEXUS_LLM_API_KEY"] == "secret123"
    assert applied["NEXUS_LLM_API_KEY"] == "***"


def test_apply_env_rejects_disallowed_key(tmp_path):
    import nexus.envfile as ef
    orig = ef.env_file_path
    ef.env_file_path = lambda: tmp_path / ".env"
    try:
        with pytest.raises(ValueError, match="not allowed"):
            ef.apply_env({"PATH": "C:\\evil"}, environ={})
        with pytest.raises(ValueError, match="no keys"):
            ef.apply_env({}, environ={})
    finally:
        ef.env_file_path = orig


# --- /portal/api/setup endpoints --------------------------------------------


def test_setup_env_endpoint(client, tmp_path, monkeypatch):
    """POST /setup/env applies allowlisted keys; response masks secrets."""
    monkeypatch.setattr(envfile, "env_file_path", lambda: tmp_path / ".env")
    saved = {k: os.environ.get(k) for k in ("NEXUS_ES_URL", "NEXUS_LLM_API_KEY")}
    try:
        r = client.post("/portal/api/setup/env", json={
            "NEXUS_ES_URL": "http://127.0.0.1:9200",
            "NEXUS_LLM_API_KEY": "topsecret",
        })
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["applied"]["NEXUS_LLM_API_KEY"] == "***"
        assert "topsecret" not in str(body)
        # os.environ was applied live
        assert os.environ.get("NEXUS_ES_URL") == "http://127.0.0.1:9200"
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_setup_env_endpoint_rejects_bad_key(client):
    r = client.post("/portal/api/setup/env", json={"NEXUS_AUDIT_SECRET": "x"})
    assert r.status_code == 400
    assert "not allowed" in r.json()["error"]


def test_setup_rag_conflict_when_running(client, monkeypatch):
    """409 while a download is already in flight."""
    from nexus.dashboard import app as app_mod

    monkeypatch.setitem(app_mod._SETUP_TASKS, "rag", {"status": "running"})
    r = client.post("/portal/api/setup/rag")
    assert r.status_code == 409
    assert "already running" in r.json()["error"]


def test_setup_status_endpoint(client):
    r = client.get("/portal/api/setup/status")
    assert r.status_code == 200
    assert "tasks" in r.json()


def test_system_health_includes_fixes_and_parser_detail(client):
    r = client.get("/portal/api/system/health")
    assert r.status_code == 200
    body = r.json()
    assert body["backend"] == "ok"
    assert "fixes" in body
    assert "rag" in body["fixes"]
