"""D87 (2026-10-13): a time_order claim names two entities and an ordering, not one subject.

The subject is the entity the cited rows give. The second entity is kept only when a cited row carries it. The pair
is joined on its sorted order, so two orderings of one pair conflict, and an affirmation and a denial of one ordering
conflict too. Two events have one order, so "B before A" is "A after B".
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nexus.analysis.cross_mode import _claim_from_finding
from nexus.langgraph.subject import attach_subjects, ground_other_entity
from nexus.modes.multi_agent import (
    _claim_key,
    _fingerprint,
    _time_order_canonical,
    accept_claim,
    find_disputes,
    settled_candidates,
)


def _to(
    subject: tuple[str, str] | None = ("process", "a.exe"),
    other: tuple[str, str] | None = ("process", "b.exe"),
    value: str = "before",
    polarity: str = "affirm",
) -> dict[str, Any]:
    """A time_order claim as the board holds it: the subject attach_subjects gave, and the grounded second entity."""
    claim: dict[str, Any] = {
        "claim_kind": "time_order", "value": value, "polarity": polarity,
        "audit_ids": ["nx-audit-to1"], "confidence_justification": "the cited rows show the order",
        "subject": {"type": subject[0], "value": subject[1], "category": "process_creation"} if subject else {},
    }
    if other:
        claim["other_subject"] = {"type": other[0], "value": other[1]}
    return claim


def _board(*claims: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"agent_id": f"s{i}", "role": f"role{i}", "family": "prefetch", "claims": [claim]}
            for i, claim in enumerate(claims, start=1)]


# ---- acceptance and the join key -----------------------------------------------------------------

def test_a_time_order_claim_needs_a_direction_and_a_grounded_distinct_second_entity():
    assert accept_claim(_to(value="")).startswith("TO-1")
    assert accept_claim(_to(value="during")).startswith("TO-1")
    assert accept_claim(_to(other=None)).startswith("TO-2")
    assert accept_claim(_to(other=("process", "a.exe"))).startswith("TO-2")
    assert accept_claim(_to()) == ""


def test_a_time_order_claim_without_its_pair_has_no_key_and_a_grounded_one_joins_on_the_pair():
    assert _claim_key(_to(other=None)) is None
    assert _claim_key(_to()) == ("pair", "process:a.exe|process:b.exe", "time_order")


def test_canonical_polarity_puts_both_orders_of_a_pair_on_one_side():
    pair = "process:a.exe|process:b.exe"
    assert _time_order_canonical(_to(value="before")) == (pair, "affirm")
    assert _time_order_canonical(_to(subject=("process", "b.exe"), other=("process", "a.exe"),
                                     value="before")) == (pair, "deny")
    assert _time_order_canonical(_to(value="after")) == (pair, "deny")
    assert _time_order_canonical(_to(subject=("process", "b.exe"), other=("process", "a.exe"),
                                     value="after")) == (pair, "affirm")
    assert _time_order_canonical(_to(value="before", polarity="deny")) == (pair, "deny")


# ---- disputes, agreement and the fingerprint -----------------------------------------------------

def test_two_orderings_of_one_pair_are_a_dispute():
    disputes = find_disputes(_board(_to(value="before"), _to(subject=("process", "b.exe"),
                                                              other=("process", "a.exe"), value="before")))
    assert len(disputes) == 1
    assert disputes[0]["claim_kind"] == "time_order"
    assert disputes[0]["entity_value"] == "process:a.exe|process:b.exe"


def test_the_same_ordering_stated_two_ways_is_agreement():
    assert find_disputes(_board(
        _to(value="before"),
        _to(subject=("process", "b.exe"), other=("process", "a.exe"), value="after"),
    )) == []


def test_an_affirmation_and_a_denial_of_one_ordering_conflict():
    disputes = find_disputes(_board(_to(value="before"), _to(value="before", polarity="deny")))
    assert len(disputes) == 1


def test_the_fingerprint_follows_the_canonical_polarity():
    same = _fingerprint(_board(_to(value="before")))
    assert _fingerprint(_board(_to(subject=("process", "b.exe"), other=("process", "a.exe"),
                                   value="after"))) == same
    assert _fingerprint(_board(_to(subject=("process", "b.exe"), other=("process", "a.exe"),
                                   value="before"))) != same


# ---- grounding and the candidate ------------------------------------------------------------------

def test_the_second_entity_is_kept_only_when_a_cited_row_holds_it():
    rows = [{"fields": {"ExecutableName": "CHROME.EXE"}, "detail": "parent WINWORD.EXE started it",
             "loc": "x.csv:1"}]
    assert ground_other_entity("process", "winword.exe", rows) == {"type": "process", "value": "winword.exe"}
    assert ground_other_entity("process", "notepad.exe", rows) == {}
    assert ground_other_entity("process", "word", rows) == {}
    assert ground_other_entity("widget", "winword.exe", rows) == {}
    assert ground_other_entity("process", "-", rows) == {}
    assert ground_other_entity("account", "DOMAIN\\CHROME.EXE", rows) == {"type": "account", "value": "chrome.exe"}


def test_attach_subjects_grounds_the_second_entity_in_the_stored_rows(tmp_path: Path):
    case = tmp_path / "CASE-TO00001"
    (case / "audit").mkdir(parents=True)
    row = {"loc": "a.csv:1", "detail": "powershell.exe started winword.exe",
           "provider": "Microsoft-Windows-Sysmon", "event_id": "1", "process": "powershell.exe"}
    (case / "audit" / "nexus.jsonl").write_text(
        json.dumps({"audit_id": "nx-audit-to1", "result_summary": {"evidence_rows": [row]}}) + "\n",
        encoding="utf-8",
    )
    base = {"claim_kind": "time_order", "value": "after", "audit_ids": ["nx-audit-to1"],
            "confidence_justification": "the cited rows show the order"}
    grounded = {**base, "other_entity_type": "process", "other_entity_value": "winword.exe"}
    absent = {**base, "other_entity_type": "process", "other_entity_value": "notepad.exe"}
    attach_subjects([grounded, absent], case)
    assert grounded["subject"]["value"] == "powershell.exe"
    assert grounded["other_subject"] == {"type": "process", "value": "winword.exe"}
    assert absent["other_subject"] == {}
    assert accept_claim(absent).startswith("TO-2")


def test_a_settled_time_order_candidate_carries_its_pair_and_canonical_polarity():
    candidates, _gaps = settled_candidates(
        _board(_to(subject=("process", "b.exe"), other=("process", "a.exe"), value="before")), [],
    )
    assert len(candidates) == 1
    assert candidates[0]["claim_kind"] == "time_order"
    assert candidates[0]["subject_pair"] == "process:a.exe|process:b.exe"
    assert candidates[0]["polarity"] == "deny"


def test_cross_mode_compares_a_time_order_candidate_as_its_pair():
    candidate = {
        "id": "C1", "title": "a.exe ran before b.exe", "claim_kind": "time_order",
        "subject_pair": "process:a.exe|process:b.exe", "polarity": "deny",
        "audit_ids": ["nx-audit-9"], "confidence": "HIGH",
    }
    rows = _claim_from_finding("3", candidate)
    assert rows[0]["key"] == ["pair", "process:a.exe|process:b.exe", "time_order"]
    assert rows[0]["polarity"] == "deny"
