"""`run_windows_command` must never let a tool inherit the caller's stdin.

2026-09-30: inside a stdio MCP child the server's stdin is the JSON-RPC
protocol pipe. Zircolite.exe inherited it and blocked forever (0 CPU, 30 min
lane stall); the same call returns in ~1 s with stdin=DEVNULL.
"""
from __future__ import annotations

import subprocess


def _tool(tmp_path):
    from mcp.server.fastmcp import FastMCP

    from nexus.audit import AuditWriter
    from nexus.tools import windows as win

    server = FastMCP("stdin-guard-test")
    win.register_tools(server, AuditWriter("t", audit_dir=tmp_path / "audit"))
    return server._tool_manager._tools["run_windows_command"].fn


def test_run_windows_command_does_not_inherit_stdin(tmp_path, monkeypatch):
    import nexus.tools.windows as win

    captured: dict = {}

    class _Result:
        returncode = 0
        stdout = "ok"
        stderr = ""

    def _fake_run(parts, **kwargs):
        captured["parts"] = parts
        captured.update(kwargs)
        return _Result()

    monkeypatch.setattr(win.subprocess, "run", _fake_run)

    result = _tool(tmp_path)(
        command=["mftecmd", "--help"],
        purpose="stdin guard regression",
        save_output=False,
    )
    assert result.get("success") is True, result
    assert captured.get("stdin") is subprocess.DEVNULL
    assert captured.get("shell") is False
