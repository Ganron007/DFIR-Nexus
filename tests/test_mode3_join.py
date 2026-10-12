"""Mode 3 join: claims are compared by the subject their cited rows give, not by the seats' wording.

Operator decision 2026-10-12. Each claim here cites a call whose rows the case's audit trail keeps
(``_audit_rows.cite_rows``), so the subject is what those rows are about, the same way it is for a real call.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from _audit_rows import cite_rows

from nexus.langgraph.subject import attach_subjects
from nexus.modes.multi_agent import (
    _claim_key,
    _fingerprint,
    _pivot_entities,
    find_disputes,
    run_mode3,
    settled_candidates,
)


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-JOIN"
    case.mkdir()
    (case / "analysis").mkdir()
    return case


def _host_row(host: str) -> dict[str, Any]:
    return {"loc": f"{host}.csv:1", "detail": "a logon row for the host", "host": host}


def _claim(audit_id: str, *, label: str, polarity: str = "affirm", value: str = "4624 logon") -> dict[str, Any]:
    return {
        "entity_type": "host",
        "entity_value": label,
        "claim_kind": "presence",
        "polarity": polarity,
        "value": value,
        "audit_ids": [audit_id],
        "confidence": "MEDIUM",
        "confidence_justification": "the cited row",
    }


def _board(case: Path, *seats: tuple[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """The board as the seats post it: each claim carries the subject its cited rows give."""
    board = [{"agent_id": f"{role}-1", "role": role, "claims": claims} for role, claims in seats]
    attach_subjects([claim for entry in board for claim in entry["claims"]], case)
    return board


def test_one_host_under_two_labels_is_one_subject_and_a_polarity_conflict_is_a_dispute(tmp_path):
    case = _case(tmp_path)
    affirmed = cite_rows(case, [_host_row("ws01")])
    denied = cite_rows(case, [_host_row("ws01")])
    board = _board(
        case,
        ("evidence", [_claim(affirmed, label="ws01")]),
        ("pattern", [_claim(denied, label="WS01.corp.local", polarity="deny", value="none")]),
    )
    [dispute] = find_disputes(board)
    assert (dispute["entity_type"], dispute["entity_value"], dispute["claim_kind"]) == (
        "host", "ws01", "presence",
    )
    assert dispute["seats"] == ["evidence", "pattern"]


def test_differing_wording_with_the_same_polarity_is_not_a_dispute(tmp_path):
    case = _case(tmp_path)
    first = cite_rows(case, [_host_row("ws01")])
    second = cite_rows(case, [_host_row("ws01")])
    board = _board(
        case,
        ("evidence", [_claim(first, label="ws01", value="4624 logon")]),
        ("pattern", [_claim(second, label="WS01", value="interactive logon, event 4624")]),
    )
    assert find_disputes(board) == []


def test_a_claim_whose_rows_name_no_subject_is_not_compared(tmp_path):
    case = _case(tmp_path)
    first = cite_rows(case, [{"loc": "a.csv:1", "detail": "a row that names no subject"}])
    second = cite_rows(case, [{"loc": "b.csv:1", "detail": "another row that names no subject"}])
    board = _board(
        case,
        ("evidence", [_claim(first, label="ws01")]),
        ("pattern", [_claim(second, label="ws01", polarity="deny", value="none")]),
    )
    claim = board[0]["claims"][0]
    assert claim["subject"] == {}
    assert _claim_key(claim) is None
    assert find_disputes(board) == []


def test_the_fingerprint_ignores_wording_and_keeps_the_polarity(tmp_path):
    case = _case(tmp_path)
    cited = cite_rows(case, [_host_row("ws01")])
    worded = _board(case, ("evidence", [_claim(cited, label="ws01", value="4624 logon")]))
    reworded = _board(case, ("evidence", [_claim(cited, label="WS01", value="interactive logon")]))
    denied = _board(case, ("evidence", [_claim(cited, label="ws01", polarity="deny", value="4624 logon")]))
    assert _fingerprint(worded) == _fingerprint(reworded)
    assert _fingerprint(worded) != _fingerprint(denied)


def test_a_seat_attaches_the_subject_its_cited_rows_give_before_the_claim_reaches_the_board(tmp_path):
    case = _case(tmp_path)
    cited = cite_rows(case, [_host_row("ws01")])

    def seat(spawn, _board, step):
        role = spawn["role"]
        return {
            "entry_id": f"{role}-{step}",
            "agent_id": f"{role}-{step}",
            "role": role,
            "family": spawn.get("family") or "",
            "superstep": step,
            "claims": [_claim(cited, label="WS01.corp.local")] if role == "evidence" else [],
            "open_questions": [],
        }

    record = run_mode3(case, "logons on ws01", families=[("evtx", 3)], seat_fn=seat, es_ok=True)
    claims = [claim for entry in record["board"] for claim in entry.get("claims") or []]
    assert claims, "the evidence seat's claim must reach the board"
    assert {(claim["subject"]["type"], claim["subject"]["value"]) for claim in claims} == {("host", "ws01")}


def test_the_pivot_map_follows_the_derived_subject_types():
    board = [{"agent_id": "evidence-1", "role": "evidence", "claims": [
        {"claim_kind": "presence", "polarity": "affirm",
         "subject": {"type": kind, "value": value, "category": "other"}}
        for kind, value in (
            ("process", "cmd.exe"),
            ("address", "10.0.0.5"),
            ("account", "alice"),
            ("file", "c:/tmp/a.exe"),
            ("registry", "hkcu/run"),
            ("host", "ws01"),
        )
    ]}]
    pivots = _pivot_entities(board, {})
    assert {pivot["entity_type"] for pivot in pivots} == {"process", "address", "account", "file", "registry"}
    assert all(pivot["why"] for pivot in pivots)


def test_the_candidate_title_names_the_subject_its_rows_give(tmp_path):
    case = _case(tmp_path)
    cited = cite_rows(case, [_host_row("rd01")])
    board = _board(case, ("evidence", [_claim(cited, label="WS01", value="")]))
    [candidate], _gaps = settled_candidates(board, [], case_dir=case)
    assert candidate["entity"] == {"type": "host", "value": "rd01"}
    assert candidate["title"].startswith("rd01 ")
    assert "ws01" not in candidate["title"].lower()
