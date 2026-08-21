"""Phase B leftovers: CLI ingest --source/audit_id and doctor /health probe."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from nexus.cli.doctor_cmd import probe_http_health, resolve_health_url
from nexus.cli.main import app

runner = CliRunner()


def test_probe_health_not_listening(monkeypatch):
    import httpx

    def _raise(*_a, **_k):
        raise httpx.ConnectError("Connection refused")

    monkeypatch.setattr("httpx.get", _raise)
    ok, fail_golden, detail = probe_http_health("http://127.0.0.1:4508")
    assert ok is True
    assert fail_golden is False
    assert "not listening" in detail


def test_probe_health_ok(monkeypatch):
    class _Resp:
        status_code = 200

        def json(self):
            return {"status": "ok", "service": "dfir-nexus"}

    monkeypatch.setattr("httpx.get", lambda *a, **k: _Resp())
    ok, fail_golden, detail = probe_http_health("http://127.0.0.1:4508")
    assert ok is True
    assert fail_golden is False
    assert "200" in detail


def test_probe_health_bad_status(monkeypatch):
    class _Resp:
        status_code = 200

        def json(self):
            return {"status": "degraded"}

    monkeypatch.setattr("httpx.get", lambda *a, **k: _Resp())
    ok, fail_golden, detail = probe_http_health("http://127.0.0.1:4508")
    assert ok is False
    assert fail_golden is True
    assert "unexpected" in detail


def test_resolve_health_url_skip(monkeypatch):
    monkeypatch.delenv("NEXUS_HEALTH_URL", raising=False)
    assert resolve_health_url("skip") is None
    monkeypatch.setenv("NEXUS_HEALTH_URL", "skip")
    assert resolve_health_url("") is None


def test_cli_ingest_source_and_audit_id(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NEXUS_AUDIT_DIR", str(tmp_path / "audit"))
    csv = tmp_path / "events.csv"
    csv.write_text("col1,col2,col3\na,b,c\nd,e,f\n", encoding="utf-8")
    result = runner.invoke(app, ["ingest", str(csv), "--source", "generic_csv"])
    assert result.exit_code == 0, result.output
    assert "audit_id=" in result.output
    assert "generic_csv" in result.output
    assert "audit_id=-" not in result.output


def test_cli_ingest_bad_source(tmp_path: Path):
    csv = tmp_path / "events.csv"
    csv.write_text("col1,col2\na,b\n", encoding="utf-8")
    result = runner.invoke(app, ["ingest", str(csv), "--source", "nope"])
    assert result.exit_code == 1
    assert "Unknown source" in result.output
