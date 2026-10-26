"""D405: query shapes the R1z3b mode runs still lost, found reviewing every run from the case audits (rule 18).

Each input is a refused or raw-400 call verbatim from the audit (case and audit id in the comment). Each now runs after a
reported rewrite, or is refused before Elasticsearch with what to send instead.
"""
from __future__ import annotations

import pytest

from nexus.langgraph import es_native
from nexus.langgraph.es_native import ESQueryError, validate_aggs, validate_query
from nexus.langgraph.query_normalize import lift_aggs_query, normalize_aggs, normalize_query

TYPES = {
    "ts": "date", "family": "keyword", "file": "keyword", "text": "text", "text.wc": "wildcard",
    "fields.data_type": "text", "fields.data_type.kw": "keyword", "fields.url": "text", "fields.url.kw": "keyword",
    "fields.source_ip": "text", "fields.source_ip.kw": "keyword", "fields.dest_ip": "text",
    "fields.dest_ip.kw": "keyword", "fields.source_port": "long", "fields.bytes": "text", "fields.bytes.kw": "keyword",
    "fields.sa": "text", "fields.sa.kw": "keyword", "ecs.host.name": "keyword",
}


def _aggs(aggs):
    out, notes = normalize_aggs(aggs, TYPES)
    out, _, lifted = lift_aggs_query(out)
    validate_aggs(out)
    return out, notes + lifted


def test_stats_filters_and_top_hits_aggregations_run():
    # T21 -378 / -1674: a time span as `stats`
    _aggs({"ts_span": {"stats": {"field": "ts"}}})
    # T21 -699: named conditions as `filters`, each a query the surface normalizes
    out, _ = _aggs({"classes": {"filters": {"filters": {
        "drive": {"wildcard": {"text": {"value": "*Google Drive*", "case_insensitive": True}}},
        "fn": {"wildcard": {"text": "*function*", "case_insensitive": True}}}}}})
    assert out["classes"]["filters"]["filters"]["fn"] == {
        "wildcard": {"text": {"value": "*function*", "case_insensitive": True}}}
    # T21 -1474: example rows per bucket
    _aggs({"by_guid": {"terms": {"field": "fields.data_type"}, "aggs": {"sample": {"top_hits": {"size": 2}}}}})
    with pytest.raises(ESQueryError, match="top_hits size"):
        validate_aggs({"s": {"top_hits": {"size": 500}}})


def test_sub_aggregations_written_inside_or_beside_the_body_move_to_aggs():
    # T21 -518: beside `terms`
    out, notes = _aggs({"by_profile": {"terms": {"field": "fields.data_type", "size": 20},
                                       "aggs": {"dl": {"filter": {"term": {"fields.data_type": "x"}}}},
                                       "first_ts": {"min": {"field": "ts"}}, "last_ts": {"max": {"field": "ts"}}}})
    assert set(out["by_profile"]["aggs"]) == {"dl", "first_ts", "last_ts"}
    assert "first_ts" not in out["by_profile"]["terms"]
    # inside the body
    out, _ = _aggs({"by_file": {"terms": {"field": "file", "first": {"min": {"field": "ts"}}}}})
    assert out["by_file"]["aggs"] == {"first": {"min": {"field": "ts"}}}


def test_a_calendar_interval_multiple_is_a_fixed_interval():
    # T21 -581
    out, notes = _aggs({"by_time": {"date_histogram": {"field": "ts", "calendar_interval": "10m"}}})
    assert out["by_time"]["date_histogram"] == {"field": "ts", "fixed_interval": "10m"}
    out, _ = _aggs({"w": {"date_histogram": {"field": "ts", "calendar_interval": "2w"}}})
    assert out["w"]["date_histogram"]["fixed_interval"] == "14d"
    out, _ = _aggs({"d": {"date_histogram": {"field": "ts", "calendar_interval": "1d"}}})
    assert out["d"]["date_histogram"]["calendar_interval"] == "1d"


def test_terms_with_boost_is_one_field_and_lists_stay_terms():
    # T13 -303
    q = {"bool": {"must": [{"term": {"family": "wireshark"}},
                           {"terms": {"fields.source_ip": ["10.10.10.42"], "boost": "2"}},
                           {"terms": {"fields.dest_ip": ["10.10.10.42"], "boost": "1"}}]}}
    out, _ = normalize_query(q, field_types=TYPES)
    validate_query(out)
    assert all("term" not in c or not isinstance(next(iter(c["term"].values())), list) for c in out["bool"]["must"])
    # two real fields still split, each list staying `terms`
    out, _ = normalize_query({"terms": {"fields.source_ip.kw": ["a"], "fields.dest_ip.kw": ["b"]}}, field_types=TYPES)
    validate_query(out)
    assert all("terms" in c for c in out["bool"]["should"])


def test_a_pattern_on_a_number():
    # T13 -607: no wildcard character means equals
    out, notes = normalize_query({"wildcard": {"fields.source_port.kw": "49208"}}, field_types=TYPES)
    assert out == {"term": {"fields.source_port": "49208"}} and notes
    # a real pattern is refused with a pointer, before ES
    assert es_native._patterns_on_non_strings({"wildcard": {"fields.source_port": "49*"}}, TYPES)


def test_numeric_aggregations_need_a_number():
    # T13 -323
    problems = es_native._aggregation_field_problems({"bytes_total": {"sum": {"field": "fields.bytes"}}}, TYPES)
    assert problems and "needs a number or a date" in problems[0]


def test_an_impossible_date_is_not_a_date():
    # T12 -673
    assert es_native._coercible("date", "2021-12-01") and not es_native._coercible("date", "2021-13-01")
    assert es_native._coercible("date", "2020-11-01 22:15:47.5539615")


def test_size_inside_aggs_and_an_aggregation_inside_a_query_item():
    # T13 -435
    out, notes = _aggs({"by_src_ip": {"terms": {"field": "fields.source_ip", "size": 20}},
                        "query": {"term": {"family": "syslog"}}, "size": 20})
    assert set(out) == {"by_src_ip"} and any("size" in n for n in notes)
    # T12 -258
    out, notes = normalize_query({"bool": {"must": [{"wildcard": {"ecs.host.name": "*PSEXESVC*"},
                                                      "cardinality": {"field": "ecs.host.name", "size": 10}}]}},
                                 field_types=TYPES)
    validate_query(out)
    assert any("cardinality" in n for n in notes)


def test_a_bare_column_resolves_to_its_fields_name():
    # T18 Mode 2: `sa` answered "this index has fields.sa"
    out, notes = normalize_query({"term": {"sa": "172.16.62.42"}}, field_types=TYPES)
    assert "fields.sa" in str(out)
