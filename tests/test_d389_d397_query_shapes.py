"""D389-D397: the rest of the model-written ES shapes that were refused in R1z3 (T01, T04, T05, T10).

Each input below is a refused call verbatim from the case audit logs (audit id in the comment). Each is now either run
after a reported rewrite or refused before Elasticsearch with a message that says what to send instead; none reaches
ES as a raw 400. The audit ids are those of CASE-D297ECAA (T01) unless named otherwise.
"""
from __future__ import annotations

import pytest

from nexus.langgraph import es_native
from nexus.langgraph.es_native import ESQueryError, validate_aggs, validate_query
from nexus.langgraph.query_normalize import normalize_aggs, normalize_query, normalize_sort
from tests.test_es_native import _FakeClient, _Resp

TYPES = {
    "ts": "date", "family": "keyword", "host": "keyword", "line": "integer", "text": "text", "text.wc": "wildcard",
    "fields.Executed": "text", "fields.Executed.kw": "keyword", "fields.ValueData": "text",
    "fields.ValueData.kw": "keyword", "fields.Notes": "text", "fields.SessionId": "long",
}


def _aggs(aggs):
    out, notes = normalize_aggs(aggs, TYPES)
    validate_aggs(out)
    return out, notes


def test_d389_filter_and_date_range_aggregations_run():
    # -199: count a condition with `filter`
    out, _ = _aggs({"executed_yes_count": {"filter": {"term": {"fields.Executed": "Yes"}}},
                    "executed_no_count": {"filter": {"term": {"fields.Executed": "No"}}}})
    assert set(out) == {"executed_yes_count", "executed_no_count"}
    # -227: buckets of time with `date_range`
    _aggs({"time_range": {"date_range": {"field": "ts", "ranges": [{"from": "2020-01-01", "to": "2020-06-30"}]}}})


def test_d389_a_query_clause_used_as_an_aggregation_is_a_filter():
    # -696 (T01 Mode 3)
    out, notes = _aggs({"by_run_match": {"bool": {"filter": [{"wildcard": {"text": "*Run*"}}]}}})
    assert "filter" in out["by_run_match"]
    assert any("filter" in n for n in notes)


def test_d390_date_histogram_shapes():
    # -094: `interval` (ES 8 removed it) and an invented `target`
    out, _ = _aggs({"by_ts_bucket": {"date_histogram": {"field": "ts", "interval": "1d", "target": "00:00:00"}}})
    assert out["by_ts_bucket"]["date_histogram"] == {"field": "ts", "calendar_interval": "1d"}
    # -086: an ISO-8601 duration
    out, _ = _aggs({"t": {"date_histogram": {"field": "ts", "fixed_interval": "P1D", "time_zone": "UTC"}}})
    assert out["t"]["date_histogram"]["fixed_interval"] == "1d"
    # T04 -097: extended_bounds is a real option
    _aggs({"by_year": {"date_histogram": {"field": "ts", "calendar_interval": "year", "min_doc_count": 0,
                                          "extended_bounds": {"min": "2020-01-01", "max": "2026-12-31"}}}})
    # T04 -723: target_bounds means extended_bounds
    out, _ = _aggs({"r": {"date_histogram": {"field": "ts", "calendar_interval": "day", "min_doc_count": 0,
                                             "target_bounds": {"gte": "2020-10-20", "lte": "2020-11-15"}}}})
    assert out["r"]["date_histogram"]["extended_bounds"] == {"min": "2020-10-20", "max": "2020-11-15"}
    # -244: `size` and `order: {by: ...}` are not date_histogram options
    out, _ = _aggs({"h": {"date_histogram": {"field": "ts", "fixed_interval": "1h", "order": {"by": "_count"},
                                             "size": 50}}})
    assert out["h"]["date_histogram"] == {"field": "ts", "fixed_interval": "1h"}
    # -726: min_doc_count as a boolean
    out, _ = _aggs({"b": {"date_histogram": {"field": "ts", "fixed_interval": "1d", "min_doc_count": True}}})
    assert out["b"]["date_histogram"]["min_doc_count"] == 1


def test_d391_text_fields_in_aggregations_and_sorts():
    # -185: cardinality on a text field uses its keyword sub-field
    out, _ = _aggs({"executed_count": {"cardinality": {"field": "fields.Executed"}}})
    assert out["executed_count"]["cardinality"]["field"] == "fields.Executed.kw"
    # -187 / -529 / T10 -038: sorting on analysed `text` falls back to ts, said
    sort, notes = normalize_sort([{"text": "asc"}], TYPES)
    assert sort == [{"ts": {"order": "asc"}}]
    assert any("cannot be sorted" in n for n in notes)


def test_d392_exists_naming_the_field_as_its_key():
    # T04 -179
    out, _ = normalize_query({"bool": {"must": [{"exists": {"fields.ValueData": {}}}]}}, field_types=TYPES)
    validate_query(out)
    assert out["bool"]["must"][0] == {"exists": {"field": "fields.ValueData"}}


def test_d393_one_list_item_holding_two_clauses():
    # -847 (T01 Mode 3)
    q = {"bool": {"must": [{"wildcard": {"fields.ValueData": "*AUDIODG.EXE*"}, "term": {"fields.Notes": "Run"}},
                           {"match": {"fields.Notes": "User"}}]}}
    out, _ = normalize_query(q, field_types=TYPES)
    validate_query(out)
    assert len(out["bool"]["must"]) == 3


def test_d394_a_mapped_field_used_as_a_clause_is_a_term():
    # T05 -254: {"bool": {...}, "family": "evtxecmd"}
    out, notes = normalize_query({"bool": {"must": [{"term": {"host": "SRL-FORGE"}}]}, "family": "evtxecmd"},
                                 field_types=TYPES)
    validate_query(out)
    assert {"term": {"family": "evtxecmd"}} in out["bool"]["must"]
    # an unmapped name is not guessed
    out, _ = normalize_query({"nosuchfield": "x"}, field_types=TYPES)
    with pytest.raises(ESQueryError):
        validate_query(out)


def test_d395_a_metric_without_a_field_points_to_total():
    # T10 -312
    with pytest.raises(ESQueryError, match="needs a `field`.*`total`"):
        validate_aggs({"__count": {"value_count": {}}})
    # -235: date_range with no ranges, for the time span
    with pytest.raises(ESQueryError, match="ranges.*min.*max"):
        validate_aggs({"time_range": {"date_range": {"field": "ts", "format": "yyyy-MM-dd"}}})


def test_d397_star_bounds_in_a_range_are_left_out():
    # -218
    out, _ = _aggs({"ts_range": {"range": {"field": "ts", "ranges": [{"from": "*", "to": "*"}]}}})
    assert out["ts_range"]["range"]["ranges"] == [{}]


class _BucketsES(_FakeClient):
    def post(self, path, json=None):
        self.last_search_body = json
        return _Resp(400, {"error": {"caused_by": {"type": "too_many_buckets_exception"}}})


def test_too_many_buckets_says_what_to_change(monkeypatch):
    from nexus.langgraph import case_index

    client = _BucketsES()
    monkeypatch.setattr(case_index, "_client", lambda: client)
    monkeypatch.setattr(case_index, "es_available", lambda: True)
    with pytest.raises(ESQueryError, match="coarser interval"):
        es_native.es_aggregate("CASE-X", {"h": {"date_histogram": {"field": "ts", "fixed_interval": "1h"}}})


def test_d396_a_terms_value_the_field_cannot_hold_is_reported(monkeypatch):
    # T10 -223: terms ["any"] on a long field reached ES as a raw 400
    monkeypatch.setattr(es_native, "_mapping_field_types", lambda _c: TYPES)
    fatal, _ = es_native.failed_field_refs_detail("CASE-X", {"bool": {"must": [{"terms": {"fields.SessionId": ["any"]}}]}})
    assert fatal and "cannot be a long" in fatal[0]["reason"]
