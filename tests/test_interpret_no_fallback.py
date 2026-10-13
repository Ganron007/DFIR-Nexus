"""D131: Mode 1's bounded interpret loop is the only interpreter.

A single-pass ReAct agent used to run whenever the loop raised or returned no findings, and
only a log line said so. It overrode a legitimate "nothing found" and hid loop failures.
These drive the real `interpret` node; only the loop and the digest builder are replaced, to
fix what they return.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
import yaml


def _case(root: Path, case_id: str) -> Path:
    case = root / case_id
    (case / "analysis").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "CASE.yaml").write_text(
        yaml.safe_dump({"case_id": case_id, "status": "created"}), encoding="utf-8")
    return case


@pytest.fixture()
def interp(monkeypatch):
    import langgraph.prebuilt as prebuilt

    import nexus.langgraph.case_digest as case_digest
    from nexus.config import settings
    from nexus.langgraph import llm_pipeline
    from nexus.langgraph.pipeline_runs import create_run

    def _no_agent(*_a, **_k):
        raise AssertionError("a ReAct agent was built behind the interpret loop")

    monkeypatch.setattr(prebuilt, "create_react_agent", _no_agent)
    monkeypatch.setattr(case_digest, "build_case_digest",
                        lambda *_a, **_k: {"backend": "elasticsearch", "inventory": {"evtxecmd": 3}})
    monkeypatch.setattr(case_digest, "render_digest_markdown", lambda *_a, **_k: "(digest)")
    case = _case(settings.cases_root, "CASE-NOFALLBACK")
    run = create_run(case, "interpret")
    state = {"case_id": case.name, "run_id": run.run_id, "pipeline_mode": "interpret",
             "tool_run_ledger": [], "case_context": {}, "rag_notes": [], "messages": []}
    return llm_pipeline, case, run, state


def test_a_loop_that_finds_nothing_ends_the_node(interp, monkeypatch):
    llm_pipeline, _case_dir, _run, state = interp
    import nexus.langgraph.interpret_loop as interpret_loop

    async def _zero(**_kw):
        return {"findings_emitted": 0, "rounds_run": 2, "rounds_requested": 3,
                "stop_reason": "settled", "unaddressed": [],
                "messages": [{"role": "assistant", "content": "[]"}]}

    monkeypatch.setattr(interpret_loop, "run_interpret_loop", _zero)
    out = asyncio.run(llm_pipeline.interpret(dict(state), {}, object()))
    assert not out.get("error")
    assert out["messages"] == [{"role": "assistant", "content": "[]"}]
    assert "0 finding candidate(s)" in out["step_log"][0]


def test_a_loop_failure_fails_the_node_and_its_run(interp, monkeypatch):
    llm_pipeline, _case_dir, run, state = interp
    import nexus.langgraph.interpret_loop as interpret_loop

    async def _boom(**_kw):
        raise RuntimeError("model endpoint refused")

    monkeypatch.setattr(interpret_loop, "run_interpret_loop", _boom)
    out = asyncio.run(llm_pipeline.interpret(dict(state), {}, object()))
    assert "model endpoint refused" in out["error"]
    manifest = json.loads((run.path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert "model endpoint refused" in manifest.get("error", "")


def test_no_digest_fails_with_the_reason(interp, monkeypatch):
    llm_pipeline, _case_dir, _run, state = interp
    import nexus.langgraph.case_digest as case_digest

    def _broken(*_a, **_k):
        raise OSError("index unreadable")

    monkeypatch.setattr(case_digest, "build_case_digest", _broken)
    out = asyncio.run(llm_pipeline.interpret(dict(state), {}, object()))
    assert "case digest could not be built" in out["error"]
    assert "index unreadable" in out["error"]
