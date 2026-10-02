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
