"""`nexus data download-rag` must call the tool synchronously (WO-1 regression).

The offload wrap registers tools async; the CLI resolves the original sync
callable through ``nexus.app.in_process_tool``. Reaching into
``server._tool_manager._tools[...].fn`` directly returns a coroutine and the
command silently no-ops.
"""
from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner


def test_data_download_rag_cli_calls_the_tool_synchronously(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    called: dict = {}
    import nexus.app as app_mod

    def fake_in_process_tool(server, name):
        def _call(**kwargs):
            called["name"] = name
            called["kwargs"] = kwargs
            return {"status": "ok", **kwargs}

        return _call

    monkeypatch.setattr(app_mod, "in_process_tool", fake_in_process_tool)

    from nexus.cli.main import app

    result = CliRunner().invoke(app, ["data", "download-rag"])
    assert result.exit_code == 0, result.output
    assert called.get("name") == "forensic_rag_download"
    assert called["kwargs"].get("force") is False
    assert "ok" in result.output

    result = CliRunner().invoke(app, ["data", "download-rag", "--force"])
    assert result.exit_code == 0, result.output
    assert called["kwargs"].get("force") is True
