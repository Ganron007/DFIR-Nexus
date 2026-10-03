"""Register D20: the suite must not reach the network for an LLM.

Before this, `nexus/__init__` loaded the developer's `.env`, so any test that
reached a model made a REAL call to the hosted provider. The suite's wall time
became the provider's latency (2308 s / 2674 s / 2683 s for one tree) and a
provider outage read as a test failure — and it defeated tests written for the
deterministic path, whose own docstrings say "with no model configured".

`NEXUS_TESTS_LIVE_LLM=1` opts back in when the live provider path is what is
under test.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest


def test_no_llm_is_configured_during_a_test():
    """conftest neutralizes the provider config for every test."""
    if os.environ.get("NEXUS_TESTS_LIVE_LLM") == "1":
        pytest.skip("live-LLM mode requested")
    for key in ("NEXUS_LLM_MODEL", "NEXUS_MODEL", "NEXUS_LLM_BASE_URL",
                "NEXUS_LLM_API_KEY"):
        assert os.environ.get(key, "") == "", f"{key} was not neutralized"


def test_get_model_refuses_rather_than_reaching_out():
    """The neutralized config must raise, not dial the provider.

    Choosing this assertion deliberately: a RuntimeError is the documented
    "no LLM configured" contract, and the deterministic paths already handle
    it (they catch it and fall back). If this ever starts returning a model,
    the suite has regained an external dependency.
    """
    if os.environ.get("NEXUS_TESTS_LIVE_LLM") == "1":
        pytest.skip("live-LLM mode requested")
    from nexus.langgraph.llm_pipeline import get_model

    with pytest.raises(RuntimeError):
        get_model()


def test_env_file_cannot_refill_the_neutralized_keys():
    """The keys are empty but PRESENT, which is what blocks the `.env` refill.

    `_load_dotenv` fills only absent keys, and `get_model` re-loads `.env` on
    every call — so a deleted variable would simply come back.
    """
    if os.environ.get("NEXUS_TESTS_LIVE_LLM") == "1":
        pytest.skip("live-LLM mode requested")
    assert "NEXUS_LLM_MODEL" in os.environ, "must be present-but-empty, not deleted"
    assert os.environ["NEXUS_LLM_MODEL"] == ""


def test_the_es_redirect_survives_the_env_reload():
    """WO-V7/D23: the ES redirect must be present-but-empty, not popped.

    The session fixture used to `pop` `NEXUS_ES_URL`, and `_load_dotenv` fills
    any ABSENT key — so the real URL came back on the first model call made
    outside a test's window, after which every per-test monkeypatch restored it
    at teardown. The tripwire could only report the leak at session end; this
    makes it impossible. Same mechanism as the LLM keys above.
    """
    import nexus.langgraph.llm_pipeline as lp

    assert os.environ.get("NEXUS_ES_URL") == ""
    # Present, so the `.env` value cannot be refilled into it. The per-test
    # fixture deliberately sets this one to "0"; the point is that it is set.
    assert "NEXUS_ES_AUTOINDEX" in os.environ

    lp._load_dotenv()

    assert os.environ.get("NEXUS_ES_URL") == "", (
        "the .env reload refilled NEXUS_ES_URL — the real cluster is reachable again"
    )
    assert os.environ.get("NEXUS_ES_AUTOINDEX") != "1", (
        "the .env reload refilled NEXUS_ES_AUTOINDEX — auto-indexing is on again"
    )


def test_a_popped_key_is_refilled_by_the_env_reload():
    """The mechanism, stated as a test: absent is what `_load_dotenv` fills.

    This is the defect V7 fixes, kept visible so a future `pop` regresses loudly
    rather than silently reopening the leak.
    """
    import nexus.langgraph.llm_pipeline as lp

    env_file = Path(__file__).resolve().parent.parent / ".env"
    if not env_file.is_file():
        pytest.skip("no .env in this checkout")
    keys = [
        line.split("=", 1)[0].strip()
        for line in env_file.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("NEXUS_ES_URL=")
    ]
    if not keys:
        pytest.skip("this .env does not define NEXUS_ES_URL")

    saved = os.environ.get("NEXUS_ES_URL")
    try:
        os.environ.pop("NEXUS_ES_URL", None)
        lp._load_dotenv()
        assert os.environ.get("NEXUS_ES_URL"), (
            "expected the absent key to be refilled from .env — if this now "
            "fails, `_load_dotenv` changed and the reasoning for V7 needs review"
        )
    finally:
        if saved is None:
            os.environ.pop("NEXUS_ES_URL", None)
        else:
            os.environ["NEXUS_ES_URL"] = saved


def test_the_script_guard_reports_only_real_changes():
    """The script suites' guard (V9) is the only protection they have.

    Kept here with the other isolation tests: the guard exists because these
    scripts run outside pytest and import no fixture.
    """
    from _nexus_guard import nexus_diff

    assert nexus_diff({}, {}) == []
    assert nexus_diff({"a": (1, 1)}, {"a": (1, 1)}) == [], "an untouched file is not a change"
    assert nexus_diff({"a": (1, 1)}, {"a": (2, 1)}) == ["~ modified a"]
    assert nexus_diff({"a": (1, 1)}, {"a": (1, 2)}) == ["~ modified a"]
    assert nexus_diff({"a": (1, 1)}, {}) == ["- deleted  a"]
    assert nexus_diff({}, {"a": (1, 1)}) == ["+ created  a"]
