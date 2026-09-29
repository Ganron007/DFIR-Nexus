"""A per-call stdio MCP child must never reap run records.

2026-09-29: the flow test's pipeline spawned stdio children; every child ran
``serve`` -> ``_reap_stale_runs`` and marked its own caller's live lane run
``interrupted``, so the status poll never saw complete/error and hung for the
full hour. Children are now marked ``NEXUS_MCP_CHILD`` and skip the reaper.
"""
from __future__ import annotations

from typer.testing import CliRunner


def test_stdio_env_marks_the_child(monkeypatch):
    from nexus.langgraph.llm_pipeline import _stdio_mcp_env

    monkeypatch.delenv("NEXUS_MCP_CHILD", raising=False)
    assert _stdio_mcp_env()["NEXUS_MCP_CHILD"] == "1"


def test_is_pipeline_child_reads_the_marker(monkeypatch):
    from nexus.cli.main import _is_pipeline_child

    monkeypatch.delenv("NEXUS_MCP_CHILD", raising=False)
    assert _is_pipeline_child() is False
    monkeypatch.setenv("NEXUS_MCP_CHILD", "1")
    assert _is_pipeline_child() is True


def _stub_server(monkeypatch, calls: list[str]) -> None:
    class _StubServer:
        def run(self) -> None:
            calls.append("served")

    import nexus.app as app_mod

    monkeypatch.setattr(app_mod, "create_server", lambda host="127.0.0.1": _StubServer())


def test_stdio_serve_as_a_child_does_not_reap(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr("nexus.cli.main._reap_stale_runs", lambda: calls.append("reaped"))
    monkeypatch.setenv("NEXUS_MCP_CHILD", "1")
    _stub_server(monkeypatch, calls)

    from nexus.cli.main import app

    result = CliRunner().invoke(app, ["serve"])
    assert result.exit_code == 0, result.output
    assert calls == ["served"]


def test_stdio_serve_as_an_owner_reaps(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr("nexus.cli.main._reap_stale_runs", lambda: calls.append("reaped"))
    monkeypatch.delenv("NEXUS_MCP_CHILD", raising=False)
    _stub_server(monkeypatch, calls)

    from nexus.cli.main import app

    result = CliRunner().invoke(app, ["serve"])
    assert result.exit_code == 0, result.output
    assert calls == ["reaped", "served"]
