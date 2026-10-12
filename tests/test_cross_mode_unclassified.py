"""D112 (2026-10-13): a claim whose category is ``other`` is counted as unclassified and is not compared.

Two ``other`` claims used to match on the entity alone, which joined rows that share nothing but a name. A claim
with a category is compared as before.
"""
from __future__ import annotations

from nexus.analysis.cross_mode import check_cross_mode, render_consistency_markdown


def _claim(mode: str, entity: str, category: str, polarity: str = "affirm") -> dict:
    return {
        "mode": mode, "source": f"finding:{mode}-1", "key": ["process", entity, category],
        "polarity": polarity, "audit_ids": [f"nx-audit-{mode}"], "title": f"{entity} {polarity}",
        "confidence": "high",
    }


def test_other_claims_on_one_entity_are_not_compared_and_are_counted():
    r = check_cross_mode(claims_by_mode={
        "1": [_claim("1", "chrome.exe", "other")],
        "2": [_claim("2", "chrome.exe", "other", polarity="deny")],
        "3": [_claim("3", "chrome.exe", "other")],
    })
    assert r["contradictions"] == []
    assert r["shared"] == []
    assert r["comparable_claims"] == 0
    assert r["unclassified"] == {
        "claims": 3,
        "by_mode": {"Mode 1 (LLM)": 1, "Mode 2 (multi-role)": 1, "Mode 3 (multi-agent)": 1},
    }
    assert r["verdict"] == "unknown"


def test_classified_claims_are_still_compared_beside_unclassified_ones():
    r = check_cross_mode(claims_by_mode={
        "1": [_claim("1", "chrome.exe", "process_creation"), _claim("1", "x.exe", "other")],
        "2": [_claim("2", "chrome.exe", "process_creation", polarity="deny")],
        "3": [],
    })
    assert r["verdict"] == "contradictory"
    assert len(r["contradictions"]) == 1
    assert r["comparable_claims"] == 2
    assert r["unclassified"]["claims"] == 1


def test_the_markdown_names_the_unclassified_claims():
    r = check_cross_mode(claims_by_mode={
        "1": [_claim("1", "x.exe", "other")], "2": [_claim("2", "x.exe", "other")], "3": [_claim("3", "x.exe", "other")],
    })
    text = render_consistency_markdown(r)
    assert "- Unclassified, not compared (no category): 3 (Mode 1 (LLM): 1, Mode 2 (multi-role): 1, " \
           "Mode 3 (multi-agent): 1)" in text
    assert "- Claims compared (with a category): 0" in text
