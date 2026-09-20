"""Phase 4k.6 — typed Mode 1 DSL: catalog fields, operators, hard errors,
ES push-down and CSV parity.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from nexus.langgraph.query_dsl import QuerySyntaxError, parse_query, row_matches

_CATALOG = {
    "channel": {"name": "Channel", "type": "text", "has_kw": True},
    "eventid": {"name": "EventID", "type": "long", "has_kw": True},
    "provider": {"name": "Provider", "type": "text", "has_kw": True},
    "computer": {"name": "Computer", "type": "keyword", "has_kw": True},
    "payloaddata1": {"name": "PayloadData1", "type": "text", "has_kw": True},
    "timecreated": {"name": "TimeCreated", "type": "date", "has_kw": False},
}


def test_parse_typed_operators():
    q = parse_query(
        "Channel:Security EventID:>=4688 EventID:4688..4689 "
        "Provider:*PowerShell* Computer:in:(WS01,WS02) exists:PayloadData1",
        catalog=_CATALOG,
    )
    ops = [(f["name"], f["op"]) for f in q.filters]
    assert ("channel", "contains") in ops
    assert ("eventid", "gte") in ops
    assert ("eventid", "range") in ops
    assert ("provider", "contains") in ops
    assert ("computer", "in") in ops
    assert any(f["op"] == "exists" for f in q.filters)
    assert not q.or_terms, "field filters must never leak into text terms"


def test_parse_exact_and_not_equal():
    q = parse_query("Channel:=Security Channel:!=System", catalog=_CATALOG)
    assert [f["op"] for f in q.filters] == ["eq", "ne"]


def test_unknown_field_is_hard_error():
    with pytest.raises(QuerySyntaxError) as exc:
        parse_query("Chanell:Security", catalog=_CATALOG)
    assert "unknown field" in str(exc.value)
    assert "channel" in str(exc.value).lower()  # suggestion


def test_urls_and_plain_terms_are_not_fields():
    for query in ("http://evil.example/path", "C:\\Windows\\System32", "sdelete"):
        q = parse_query(query, catalog=_CATALOG)
        assert not q.filters, f"{query!r} must stay a plain term"
        assert q.or_terms or q.and_terms


def test_row_matches_typed_filters_and_missing_column_fails():
    q = parse_query(
        "channel:Security eventid:>=4688 computer:in:(WS01,WS02) exists:PayloadData1",
        catalog=_CATALOG,
    )
    good = {"Channel": "Security", "EventID": "4688", "Computer": "WS01",
            "PayloadData1": "sdelete.exe"}
    ok, _ = row_matches(q, line_lower="raw row", row_fields=good)
    assert ok
    assert not row_matches(q, line_lower="raw", row_fields={**good, "EventID": "100"})[0]
    assert not row_matches(q, line_lower="raw", row_fields={**good, "Computer": "WS09"})[0]
    missing = {"Channel": "Security", "EventID": "4688", "Computer": "WS01"}
    assert not row_matches(q, line_lower="raw", row_fields=missing)[0]
    assert not row_matches(q, line_lower="raw", row_fields=None)[0]


def test_row_matches_wildcard_contains_and_exact():
    fields = {"Provider": "Microsoft-Windows-PowerShell", "Channel": "Security"}
    q = parse_query("provider:*PowerShell* channel:=Security", catalog=_CATALOG)
    assert row_matches(q, line_lower="raw", row_fields=fields)[0]

    contains = parse_query("channel:curit", catalog=_CATALOG)
    assert row_matches(contains, line_lower="raw", row_fields=fields)[0]

    exact = parse_query("channel:=securit", catalog=_CATALOG)
    assert not row_matches(exact, line_lower="raw", row_fields=fields)[0]


# ── ES push-down ───────────────────────────────────────────────────────

def test_ast_to_es_typed_filters():
    from nexus.langgraph.case_index import _filter_to_es

    clauses = _filter_to_es(
        {"name": "eventid", "op": "range", "lo": "4688", "hi": "4689"}, _CATALOG,
    )
    assert clauses == [{"range": {"fields.EventID": {"gte": 4688, "lte": 4689}}}]

    clauses = _filter_to_es({"name": "computer", "op": "in",
                             "values": ["WS01", "WS02"]}, _CATALOG)
    assert clauses == [{"terms": {"fields.Computer.kw": ["WS01", "WS02"]}}]

    clauses = _filter_to_es({"name": "payloaddata1", "op": "exists"}, _CATALOG)
    assert clauses == [{"exists": {"field": "fields.PayloadData1.kw"}}]


def test_ast_to_es_type_mismatch_is_hard_error():
    from nexus.langgraph.case_index import _filter_to_es

    with pytest.raises(QuerySyntaxError) as exc:
        _filter_to_es({"name": "channel", "op": "gt", "value": "5"}, _CATALOG)
    assert "numeric/date" in str(exc.value)


def test_ast_to_es_unknown_field_with_catalog_is_hard_error():
    from nexus.langgraph.case_index import _filter_to_es

    with pytest.raises(QuerySyntaxError):
        _filter_to_es({"name": "nope", "op": "eq", "value": "x"}, _CATALOG)


# ── CSV parity end-to-end through n4_query ─────────────────────────────

def _case(tmp_path: Path) -> Path:
    ext = tmp_path / "extractions" / "evtxecmd"
    ext.mkdir(parents=True)
    (ext / "Security.csv").write_text(
        "TimeCreated,Channel,EventID,Provider,Computer,PayloadData1\n"
        "2020-11-14T04:49:43Z,Security,4688,Microsoft-Windows-Security,WS01,sdelete -p 5\n"
        "2020-11-14T05:00:00Z,Security,4624,Microsoft-Windows-Security,WS02,logon\n"
        "2020-11-14T06:00:00Z,System,7045,Service Control Manager,WS01,svc installed\n",
        encoding="utf-8",
    )
    (tmp_path / "CASE.yaml").write_text("intake:\n  question: typed dsl test\n", encoding="utf-8")
    return tmp_path


def test_n4_query_csv_typed_filters(tmp_path, monkeypatch):
    import nexus.langgraph.field_catalog as fc
    from nexus.langgraph.query_pack import n4_query

    case = _case(tmp_path)
    monkeypatch.setattr(fc, "case_field_catalog", lambda _c: dict(_CATALOG))
    monkeypatch.setattr(fc, "_CACHE", {})

    r = n4_query(case, "channel:Security eventid:>=4688", backend="csv")
    assert r.get("error") is None, r
    assert r["count"] == 1 and len(r["hits"]) == 1
    assert "sdelete" in r["hits"][0]["text"]

    r2 = n4_query(case, "computer:in:(WS01) channel:System", backend="csv")
    assert r2["count"] == 1 and "svc installed" in r2["hits"][0]["text"]

    r3 = n4_query(case, "provider:*Security* channel:Security", backend="csv")
    assert r3["count"] == 2

    r4 = n4_query(case, "nope:1", backend="csv")
    assert r4.get("error") and "unknown field" in r4["error"]
