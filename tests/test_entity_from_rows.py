"""WO-1C item 4, option (b): a finding's entity is derived from the rows it cites (operator decision 2026-10-11).

The entity is the event id of a cited row, else its host, else its user, read in location order, so the
same citation gives the same entity in every mode, whatever a model wrote. The duplicate rule identifies a
row by its location, so two modes citing the same row share one DRAFT identity.
"""

from __future__ import annotations

import json

from nexus.case_manager import _duplicate_key
from nexus.langgraph.evidence_rows import (
    derive_entity_from_rows,
    evidence_rows_for_audit_ids,
    evidence_rows_for_hits,
)


def _hit(file: str, line: int, **extra) -> dict:
    hit = {"family": "evtxecmd", "file": file, "line": str(line), "host": "", "text": "row",
           "fields": {"EventId": "1004"}}
    hit.update(extra)
    return hit


def test_the_event_id_of_a_cited_row_is_the_entity_whatever_the_wording():
    rows = [
        {"loc": "b.csv:9", "detail": "a host row", "host": "RD01"},
        {"loc": "a.csv:3", "detail": "reworded text entirely", "event_id": "1004", "host": "rd01"},
    ]
    assert derive_entity_from_rows(rows) == {"type": "event_id", "value": "1004"}
    assert derive_entity_from_rows(list(reversed(rows))) == {"type": "event_id", "value": "1004"}


def test_a_host_then_a_user_is_the_entity_when_no_row_has_an_event_id():
    assert derive_entity_from_rows([{"loc": "a:1", "host": "RD01"}]) == {"type": "host", "value": "rd01"}
    assert derive_entity_from_rows([{"loc": "a:1", "user": "Tdungan"}]) == {"type": "user", "value": "tdungan"}


def test_rows_without_identity_give_no_entity():
    assert derive_entity_from_rows([{"loc": "a:1", "detail": "a sentence the model wrote"}]) == {}
    assert derive_entity_from_rows([]) == {}


def test_the_row_keeps_its_identity_even_when_the_field_copy_is_cut():
    fields = {f"Field{i}": "x" for i in range(30)}
    fields["EventId"] = "1004"
    rows = evidence_rows_for_hits([_hit("a.csv", 4, event_id="1004", host="RD01", fields=fields)])
    assert rows[0]["event_id"] == "1004" and rows[0]["host"] == "RD01"
    assert derive_entity_from_rows(rows) == {"type": "event_id", "value": "1004"}


def test_stored_rows_of_a_cited_call_give_the_entity(tmp_path):
    audit = tmp_path / "audit"
    audit.mkdir()
    rows = evidence_rows_for_hits([_hit("a.csv", 4, event_id="1004", host="RD01")])
    (audit / "nexus.jsonl").write_text(
        json.dumps({"audit_id": "nexus-x-1", "tool": "es_search",
                    "result_summary": {"evidence_rows": rows}}) + "\n", encoding="utf-8")
    stored = evidence_rows_for_audit_ids(tmp_path, ["nexus-x-1"])
    assert derive_entity_from_rows(stored) == {"type": "event_id", "value": "1004"}


def test_the_duplicate_rule_identifies_a_row_by_its_location_not_its_wording():
    def finding(detail: str, loc: str = "a.csv:4") -> dict:
        return {"title": "same claim", "entity": {"type": "event_id", "value": "1004"},
                "evidence": [{"loc": loc, "detail": detail}]}

    assert _duplicate_key(finding("Mode 1 wording")) == _duplicate_key(finding("Mode 3 different wording"))
    assert _duplicate_key(finding("same", loc="a.csv:4")) != _duplicate_key(finding("same", loc="a.csv:5"))
