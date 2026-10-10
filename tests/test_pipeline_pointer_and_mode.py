"""The pipeline never reaches this machine's global active-case pointer through the SIFT tool, and it
names the mode it runs (2026-10-11).

Reproduced on CASE-C5B04D31: a tools run with --from-case moved ~/.nexus/active_case to the case's
path. The lane's SIFT alignment called tools.get("case_activate"); after the Windows-wins merge in
llm_pipeline._load_mcp_tools that name is the examiner host's tool, and tools/case.py writes the
global pointer. The SIFT copy is stored as _sift_case_activate. The CLI also printed
"Interpret from existing case ..." for a tools run.
"""
from __future__ import annotations

import asyncio

from nexus.langgraph import llm_pipeline


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name


def test_the_sift_activation_tool_is_kept_apart_from_the_examiner_host_copy(monkeypatch):
    server_tools = {
        "nexus-windows": [_Tool("case_activate"), _Tool("run_windows_command")],
        "nexus-sift": [_Tool("case_activate"), _Tool("run_command")],
    }

    class _FakeClient:
        def __init__(self, servers):
            self._server = next(iter(servers))

        async def get_tools(self):
            return list(server_tools[self._server])

    import langchain_mcp_adapters.client as adapter_client

    monkeypatch.setattr(adapter_client, "MultiServerMCPClient", _FakeClient)
    config = {
        "nexus-windows": {"transport": "streamable_http", "url": "http://127.0.0.1:4508/mcp"},
        "nexus-sift": {"transport": "streamable_http", "url": "http://192.168.77.135:4508/mcp"},
    }

    tools = asyncio.run(llm_pipeline._load_mcp_tools(config))

    assert tools["case_activate"] is server_tools["nexus-windows"][0], "plain name = examiner host (Windows wins)"
    assert tools["_sift_case_activate"] is server_tools["nexus-sift"][0], "the SIFT host's tool is kept apart"
    assert tools["_sift_case_activate"] is not tools["case_activate"]


def test_a_tools_run_on_an_existing_case_is_not_announced_as_interpret(monkeypatch):
    from typer.testing import CliRunner

    from nexus.cli.main import app

    seen: dict = {}

    async def fake_run_pipeline(**kwargs):
        seen.update(kwargs)
        return {}

    monkeypatch.setattr(llm_pipeline, "run_pipeline", fake_run_pipeline)
    result = CliRunner().invoke(app, ["pipeline", "--mode", "tools", "--from-case", "CASE-TEST01"])

    assert result.exit_code == 0, result.output
    assert "Interpret from existing case" not in result.output
    assert "Mode tools on existing case CASE-TEST01" in result.output
    assert seen["mode"] == "tools"
    assert seen["case_id"] == "CASE-TEST01"


def test_the_pipeline_never_calls_the_examiner_host_activation():
    """The plain `case_activate` is the examiner host's tool after the Windows-wins merge, and calling it
    writes this machine's global active-case pointer. An existing case is bound by its id instead."""
    import inspect

    src = inspect.getsource(llm_pipeline)
    assert 'tools.get("case_activate")' not in src
