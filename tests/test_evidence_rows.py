"""D70: one evidence-row shape for every mode's DRAFTs.

A hit a real query returned becomes one row (Mode 1 has always built them this way). The
audited ``es_search`` entry keeps the rows it returned, and Mode 2/3 staging reads them back
from the entries a candidate cites, so the same claim on the same rows carries the same
evidence whichever mode proposed it.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph import backbone, es_native
from nexus.langgraph.evidence_rows import (
    EVIDENCE_ROW_CAP,
    evidence_rows_for_audit_ids,
    evidence_rows_for_hits,
    hit_time_of,
)


def _hit(line: int, **over) -> dict:
    hit = {
        "family": "evtxecmd", "file": "a.csv", "line": line,
        "text": f"row {line}", "fields": {"EventId": 1004, "Channel": "Security"},
    }
    hit.update(over)
    return hit


def test_a_hit_becomes_a_row_in_the_mode1_shape():
    (row,) = evidence_rows_for_hits([_hit(7)])
    assert row["source"] == "evtxecmd/a.csv"
    assert row["artifact"] == "a.csv"
    assert row["loc"] == "a.csv:7"
    assert row["detail"], "the rendered hit is the detail the duplicate rule compares"
    assert row["fields"]["EventId"] == "1004"


def test_rows_keep_the_first_hits_in_order_up_to_the_cap():
    rows = evidence_rows_for_hits([_hit(n) for n in range(1, 31)])
    assert len(rows) == EVIDENCE_ROW_CAP
    assert [r["loc"] for r in rows] == [f"a.csv:{n}" for n in range(1, EVIDENCE_ROW_CAP + 1)]


def test_the_time_is_parsed_from_the_row_text_when_the_hit_has_none():
    assert hit_time_of({"time": "2026-01-02T03:04:05"}) == "2026-01-02T03:04:05"
    assert hit_time_of({"text": "2026-01-02 03:04:05 logon"}).startswith("2026-01-02")
    assert hit_time_of({"text": "no timestamp here"}) == ""


def _write_audit(case_dir: Path, entries: list[dict]) -> None:
    (case_dir / "audit").mkdir(parents=True, exist_ok=True)
    (case_dir / "audit" / "nexus.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")


def test_cited_audit_entries_return_their_stored_rows_in_citation_order(tmp_path):
    r1 = {"source": "evtxecmd/a.csv", "loc": "a.csv:1", "detail": "one"}
    r2 = {"source": "evtxecmd/a.csv", "loc": "a.csv:2", "detail": "two"}
    _write_audit(tmp_path, [
        {"audit_id": "A", "tool": "es_search", "result_summary": {"evidence_rows": [r1]}},
        {"audit_id": "B", "tool": "es_search", "result_summary": {"evidence_rows": [r2, r1]}},
        {"audit_id": "C", "tool": "es_search", "result_summary": {"total": 0}},
    ])
    rows = evidence_rows_for_audit_ids(tmp_path, ["B", "A", "C", "missing"])
    assert rows == [r2, r1], "citation order, each row once, ids without rows add nothing"


def test_no_cited_rows_means_no_evidence(tmp_path):
    assert evidence_rows_for_audit_ids(tmp_path, ["A"]) == []
    _write_audit(tmp_path, [{"audit_id": "A", "tool": "es_search", "result_summary": {}}])
    assert evidence_rows_for_audit_ids(tmp_path, ["A"]) == []


def test_the_es_search_audit_entry_stores_the_rows_it_returned(tmp_path, monkeypatch):
    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", tmp_path)
    case_dir = tmp_path / "CASE-ROWS"
    (case_dir / "audit").mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text("name: rows\nstatus: active\n", encoding="utf-8")
    hits = [_hit(3), _hit(4)]

    def fake_es_search(case_id, **kwargs):
        return {"total": 2, "returned": 2, "families": {"evtxecmd": 2}, "hits": hits}

    monkeypatch.setattr(es_native, "es_search", fake_es_search)
    from nexus.audit import AuditWriter

    audit = AuditWriter("nexus", audit_dir=case_dir / "audit")
    result = backbone.backbone_call("es_search", audit=audit, case_dir=case_dir,
                                    query={"match_all": {}})
    assert result["total"] == 2
    cited = result["provenance"]["audit_id"]
    assert cited, "the successful call is audited"
    rows = evidence_rows_for_audit_ids(case_dir, [cited])
    assert [r["loc"] for r in rows] == ["a.csv:3", "a.csv:4"]
    assert rows == evidence_rows_for_hits(hits)
