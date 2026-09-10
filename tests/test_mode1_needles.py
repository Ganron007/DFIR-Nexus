"""Mode 1 needle quality (Phase 4g).

- Entity extraction: the examiner's own identifiers are always needles.
- Grounded scribe context: families / playbook terms / searched needles.
- Ranking: structural identifiers outrank generic vocabulary.
- API wiring: `/mode1/ask` returns entities + grounded needles without an LLM.
"""
from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.langgraph.mode1 import (
    _context_block,
    extract_entities,
    nl_to_needles,
)
from nexus.langgraph.query_pack import finalize_hits


def test_extract_entities_identifiers():
    question = (
        "Did 10.0.0.5 or evil.example.com touch "
        r"C:\Temp\payload.exe" " or bob@corp.local?"
    )
    entities = extract_entities(question)
    assert "10.0.0.5" in entities.get("ipv4", [])
    assert "evil.example.com" in entities.get("domain", [])
    assert any(p.endswith("payload.exe") for p in entities.get("windows_path", []))
    assert "bob@corp.local" in entities.get("email", [])


def test_extract_entities_hash_and_user():
    sha = "a" * 64
    entities = extract_entities(f"hash {sha} and CHILD\\analyst_t1 ran it")
    assert sha in entities.get("sha256", [])
    assert "CHILD\\analyst_t1" in entities.get("domain_user", [])


def test_entities_become_needles_first():
    result = nl_to_needles("Did 10.0.0.5 reach evil.example.com?", model=None)
    assert result["source"] == "heuristic"
    assert result["needles"][0] == "10.0.0.5"
    assert "evil.example.com" in result["needles"]
    assert result["entities"]["ipv4"] == ["10.0.0.5"]


def test_llm_needles_keep_entities():
    from unittest.mock import MagicMock

    model = MagicMock()
    model.invoke.return_value = MagicMock(
        content='{"needles": ["powershell"], "window": "", "rationale": "exec"}'
    )
    result = nl_to_needles(
        "Did 10.0.0.5 run powershell?", model=model, context=None
    )
    assert result["source"] == "llm"
    assert result["needles"][0] == "10.0.0.5"
    assert "powershell" in result["needles"]
    assert result["rationale"] == "exec"


def test_context_block_includes_grounding():
    block = _context_block({
        "families": ["evtxecmd", "hayabusa"],
        "playbook_terms": ["sdelete", "USBSTOR"],
        "searched": ["prefetch"],
        "intake": {"subjects": "fredr"},
    })
    assert "evtxecmd" in block and "USBSTOR" in block
    assert "Already searched" in block
    assert "fredr" in block


def test_finalize_hits_prefers_structural_identifiers():
    hits = [
        {"family": "evtxecmd", "file": "a.csv", "line": "1", "terms": "security", "text": "security"},
        {"family": "evtxecmd", "file": "a.csv", "line": "2", "terms": "10.0.0.5", "text": "10.0.0.5"},
    ]
    ranked = finalize_hits(hits, ["security", "10.0.0.5"])
    assert ranked[0]["line"] == "2"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)

    from nexus.dashboard.app import create_dashboard

    return TestClient(Starlette(routes=create_dashboard()))


def test_api_ask_returns_entities_without_llm(client, monkeypatch):
    import nexus.langgraph.llm_pipeline as lp

    def _no_model(*_args, **_kwargs):
        raise RuntimeError("no LLM in test")

    monkeypatch.setattr(lp, "get_model", _no_model)

    created = client.post("/portal/api/case/create", json={"name": "Needle Case"})
    case_id = created.json()["case_id"]
    r = client.post(
        "/portal/api/mode1/ask",
        headers={"X-Nexus-Case": case_id},
        json={"question": "Did 10.0.0.5 reach evil.example.com?"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "10.0.0.5" in body["needles"]
    assert body["entities"]["ipv4"] == ["10.0.0.5"]
    assert body["source"] == "heuristic"


def test_chat_stream_mode1_uses_grounded_context(client, monkeypatch):
    """The UI path (/chat/stream) must ground the scribe like /mode1/ask."""
    import nexus.langgraph.mode1 as mode1

    captured: dict = {}
    real = mode1.nl_to_needles

    def spy(question, model=None, context=None):
        captured["context"] = context
        return real(question, model=None, context=context)

    monkeypatch.setattr(mode1, "nl_to_needles", spy)

    created = client.post("/portal/api/case/create", json={"name": "Stream Case"})
    case_id = created.json()["case_id"]
    r = client.post(
        "/portal/api/chat/stream",
        headers={"X-Nexus-Case": case_id},
        json={"message": "Did 10.0.0.5 use powershell?", "mode": "mode1"},
    )
    assert r.status_code == 200, r.text
    context = captured.get("context")
    assert context is not None, "chat stream dropped the grounded context"
    assert "searched" in context and "sources" in context
    assert "event: done" in r.text or "Needles:" in r.text
