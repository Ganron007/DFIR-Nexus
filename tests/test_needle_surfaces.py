"""F6 follow-up: the vocabulary gate on every needle *surface*.

The gate started at the scan/export accessors; these tests pin it on the
surfaces that *propose* vocabulary (Mode 1 NL ask, Explore suggestions, the
examiner overlay) and on the prompt renderers (ATT&CK/Sigma contexts).
"""

from __future__ import annotations

import re

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

CONTAINER = re.compile(r"\.(evtx|csv|log|txt)$", re.IGNORECASE)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    monkeypatch.setenv("NEXUS_NEEDLE_OVERLAY", str(tmp_path / "overlay.yaml"))
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)

    from nexus.dashboard.app import create_dashboard

    return TestClient(Starlette(routes=create_dashboard()))


def test_nl_to_needles_gates_context_terms():
    """Search needles never include event IDs / container names from context."""
    from nexus.langgraph.mode1 import nl_to_needles

    result = nl_to_needles(
        "anything else",
        model=None,
        context={
            "atomic_needles": ["106", "1102", "ftp.txt", "evil.exe"],
            "car_needles": ["3", "17", ".lnk"],
            "evtx_needles": ["C:\\sensitive\\data.txt"],
            "sigma_needles": ["lsass", "7045"],
        },
    )
    needles = [str(n) for n in result["needles"]]
    assert "evil.exe" in needles and "lsass" in needles
    for junk in ("106", "1102", "3", "17", "7045"):
        assert junk not in needles, junk
    for junk in ("ftp.txt", "C:\\sensitive\\data.txt"):
        assert junk not in needles, junk


def test_attack_context_splits_typed_hints():
    from nexus.knowledge.attack_needles import attack_context_for

    block = attack_context_for([{
        "technique": "T1003",
        "name": "OS Credential Dumping",
        "needles": ["lsass", "mimikatz", "4656", "security.evtx"],
        "caveats": ["dual use"],
    }])
    assert "lsass" in block and "mimikatz" in block
    assert "event ids: 4656" in block
    assert "artifact files: security.evtx" in block
    term_part = block.split(" | event ids:")[0]
    assert "4656" not in term_part and "security.evtx" not in term_part


def test_sigma_context_splits_typed_hints():
    from nexus.knowledge.sigma_needles import sigma_context_for

    block = sigma_context_for([{
        "name": "Persistence",
        "needles": ["currentversion\\run", "7045", "system.evtx"],
        "caveats": ["c"],
    }])
    assert "currentversion\\run" in block
    assert "event ids: 7045" in block
    assert "artifact files: system.evtx" in block


def test_orchestrator_sigma_context_has_no_numeric_needles():
    from nexus.langgraph.orchestrator import _sigma_for_family

    block = _sigma_for_family(["hayabusa"])
    assert "Detection fields:" in block
    for line in block.splitlines():
        if line.startswith("Detection fields:"):
            tokens = [t.strip() for t in line.split(":", 1)[1].split(",")]
            assert not any(t.isdigit() for t in tokens), line


def test_suggestion_vocabulary_helper_routes_hints():
    from nexus.dashboard.app import _gate_suggestion_vocabulary

    suggestion = {"needles": ["mimikatz", "1102", "security.evtx", "4656"], "strong_needles": []}
    _gate_suggestion_vocabulary(suggestion)
    assert suggestion["needles"] == ["mimikatz"]
    assert suggestion["event_ids"] == ["1102", "4656"]
    assert suggestion["artifacts"] == ["security.evtx"]


def test_explore_suggestions_gated(client):
    """No promotable suggestion offers a bare number / container as a needle."""
    r = client.get(
        "/portal/api/playbook/needles",
        params={"families": "evtxecmd,hayabusa,prefetch,recmd,memory"},
    )
    payload = r.json()
    assert payload["total"] > 0
    for suggestion in payload["suggestions"]:
        for term in list(suggestion.get("needles") or []) + list(
            suggestion.get("strong_needles") or []
        ):
            text = str(term).strip()
            assert not text.isdigit(), (suggestion.get("source"), term)
            assert not CONTAINER.search(text), (suggestion.get("source"), term)
    # Event IDs survive as typed hints instead of needles.
    assert any(s.get("event_ids") for s in payload["suggestions"])


def test_attack_for_family_uses_real_technique_and_typed_hints():
    from nexus.langgraph.orchestrator import _attack_for_family

    families = ["evtxecmd", "hayabusa", "prefetch", "recmd", "memory", "lnk", "jumplists"]
    block = _attack_for_family(families)
    assert "--- T" in block
    header = [ln for ln in block.splitlines() if ln.startswith("--- ")][0]
    technique = header.split("--- ", 1)[1].split(" ")[0]
    assert technique != "T", "technique_id key bug: expected the real technique"
    assert "Needles:" in block
    needles_line = [ln for ln in block.splitlines() if ln.startswith("Needles:")][0]
    assert not any(
        tok.strip().isdigit() for tok in needles_line.split(":", 1)[1].split(",")
    )
    assert "Event IDs (typed probe):" in block


def test_mode2_bare_needle_fallback_gated():
    from nexus.langgraph.mode2 import _bare_needles

    parsed = {
        "needles": ["mimikatz", "1102", "security.evtx", "psexec"],
        "queries": [{"dsl": "family:hayabusa AND 4624"}],
    }
    assert _bare_needles(parsed) == ["mimikatz", "psexec"]


def test_briefing_directions_gate_llm_needles(tmp_path):
    from nexus.langgraph.briefing import llm_directions

    class _Resp:
        content = (
            '{"directions": [{"title": "t", "why": "w", '
            '"needles": ["mimikatz", "1102", "security.evtx"], "family": "evtx"}]}'
        )

    class _Model:
        def invoke(self, _messages):
            return _Resp()

    out = llm_directions(tmp_path, {"families": ["evtx"]}, model=_Model())
    assert out and out[0]["needles"] == ["mimikatz"]


def test_overlay_promote_and_load_are_gated(tmp_path, monkeypatch):
    overlay_path = tmp_path / "overlay.yaml"
    monkeypatch.setenv("NEXUS_NEEDLE_OVERLAY", str(overlay_path))
    from nexus.knowledge import needle_overlay as no

    result = no.promote_needles("evtx", ["badguy.exe", "1102", "security.evtx", "4662"])
    assert result["count"] == 1
    assert result["terms"] == ["badguy.exe"]
    assert result["skipped"] == ["1102", "security.evtx", "4662"]
    assert no.overlay_terms_for_families({"evtx"}) == ["badguy.exe"]

    # A legacy overlay written before the gate is filtered on read.
    overlay_path.write_text("evtx:\n- badguy.exe\n- '4662'\n- x\n", encoding="utf-8")
    assert no.overlay_terms_for_families({"evtx"}) == ["badguy.exe"]
