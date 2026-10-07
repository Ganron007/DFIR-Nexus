"""WO-R1F item 2 — the LLM-proof query surface.

Measured at R1: 27% of the model's ES calls were rejected in SC1. These tests pin
the shapes the model actually sent (taken from the case audit), so the surface
stays forgiving. Every rewrite must be REPORTED — "accept and normalize; never
fail silently".
"""

from __future__ import annotations

from nexus.langgraph.query_normalize import (
    normalize_aggs,
    normalize_query,
    normalize_sort,
)

TYPES = {
    "ts": "date",
    "family": "keyword",
    "host": "keyword",
    "user": "keyword",
    "text": "text",
    "text.kw": "keyword",
    "fields.command_line": "text",
    "fields.command_line.kw": "keyword",
    "ecs.host.name": "keyword",
    "ecs.winlog.event_data.EventId": "keyword",
    "ecs.host": "object",
}


def test_query_as_a_json_string_is_parsed():
    out, notes = normalize_query('{"bool":{"must":[{"term":{"family":"hayabusa"}}]}}',
                                 field_types=TYPES)
    assert out == {"bool": {"must": [{"term": {"family": "hayabusa"}}]}}
    assert any("JSON string" in n for n in notes)


def test_empty_query_becomes_match_all():
    for empty in ({}, None, [], ""):
        out, notes = normalize_query(empty, field_types=TYPES)
        assert out == {"match_all": {}}
        assert notes


def test_several_top_level_clauses_become_bool_must():
    out, notes = normalize_query(
        {"term": {"family": "hayabusa"}, "range": {"ts": {"gte": "2023-01-01"}}},
        field_types=TYPES,
    )
    assert set(out) == {"bool"}
    assert len(out["bool"]["must"]) == 2
    assert any("bool.must" in n for n in notes)


def test_size_and_sort_inside_the_query_are_lifted_out():
    out, notes = normalize_query(
        {"bool": {"must": [{"term": {"family": "x"}}]},
         "size": 50, "sort": [{"ts": "asc"}]},
        field_types=TYPES,
    )
    assert "size" not in out and "sort" not in out
    assert any("size" in n for n in notes)


def test_full_request_body_is_unwrapped():
    """`{"size":3,"query":{…},"sort":[…]}` is a body, not a query."""
    out, notes = normalize_query(
        {"size": 3, "query": {"match_all": {"_all": True}}, "sort": [{"ts": "asc"}]},
        field_types=TYPES,
    )
    assert out == {"match_all": {}}
    assert any("request body" in n for n in notes)


def test_sort_string_becomes_a_list():
    out, notes = normalize_sort("ts", TYPES)
    assert out == [{"ts": "asc"}]
    assert any("not a list" in n for n in notes)


def test_sort_object_becomes_a_list():
    out, _ = normalize_sort({"ts": "desc"}, TYPES)
    assert out == [{"ts": {"order": "desc"}}]


def test_sort_on_a_text_field_uses_the_keyword_subfield():
    out, notes = normalize_sort("text", TYPES)
    assert out == [{"text.kw": "asc"}]
    assert any("keyword sub-field" in n for n in notes)


def test_sort_on_id_uses_ts():
    out, notes = normalize_sort(["_id"], TYPES)
    assert out == [{"ts": "asc"}]
    assert any("_id" in n for n in notes)


def test_sort_on_an_unmapped_field_falls_back_to_ts():
    out, notes = normalize_sort([{"nope": "asc"}], TYPES)
    assert out == [{"ts": {"order": "asc"}}]
    assert any("not mapped" in n for n in notes)


def test_alias_plain_ecs_names():
    out, notes = normalize_query(
        {"term": {"host.name": "WS01"}}, field_types=TYPES
    )
    assert out == {"term": {"ecs.host.name": "WS01"}}
    assert any("host.name" in n for n in notes)


def test_alias_event_data_paths():
    out, _ = normalize_query(
        {"term": {"fields.event_data.TargetUserName": "admin"}},
        field_types={**TYPES, "ecs.winlog.event_data.TargetUserName": "keyword"},
    )
    assert out == {"term": {"ecs.winlog.event_data.TargetUserName": "admin"}}


def test_at_timestamp_maps_to_ts():
    out, notes = normalize_query(
        {"range": {"@timestamp": {"gte": "2023-01-01"}}}, field_types=TYPES
    )
    assert out == {"range": {"ts": {"gte": "2023-01-01"}}}
    assert any("@timestamp" in n for n in notes)


def test_term_on_a_text_field_uses_its_keyword():
    out, notes = normalize_query(
        {"term": {"text": "set-mppreference"}}, field_types=TYPES
    )
    assert out == {"term": {"text.kw": "set-mppreference"}}
    assert any("keyword sub-field" in n for n in notes)


def test_min_should_match_is_renamed():
    out, notes = normalize_query(
        {"bool": {"should": [{"term": {"family": "a"}}], "min_should_match": 1}},
        field_types=TYPES,
    )
    assert out["bool"]["minimum_should_match"] == 1
    assert "min_should_match" not in out["bool"]
    assert any("minimum_should_match" in n for n in notes)


def test_wildcard_case_sensitive_is_dropped():
    out, notes = normalize_query(
        {"wildcard": {"family": {"value": "*x*", "case_sensitive": False}}},
        field_types=TYPES,
    )
    assert "case_sensitive" not in out["wildcard"]["family"]
    assert any("case_sensitive" in n for n in notes)


def test_wildcard_value_object_is_flattened():
    """`{field: {wildcard: "*x*", case_sensitive: false}}` — a real SC1 shape."""
    out, notes = normalize_query(
        {"wildcard": {"text": {"wildcard": "*LSASS*", "case_sensitive": False}}},
        field_types=TYPES,
    )
    assert out == {"wildcard": {"text.kw": {"value": "*LSASS*"}}}
    assert notes


def test_multi_field_terms_becomes_bool_should():
    out, notes = normalize_query(
        {"terms": {"family": "a", "host": "b"}}, field_types=TYPES
    )
    assert set(out) == {"bool"}
    assert len(out["bool"]["should"]) == 2
    assert any("terms" in n for n in notes)


def test_multi_field_term_becomes_bool_should():
    out, _ = normalize_query({"term": {"family": "a", "host": "b"}},
                             field_types=TYPES)
    assert len(out["bool"]["should"]) == 2


def test_query_string_becomes_multi_match():
    out, notes = normalize_query(
        {"query_string": {"query": "rundll32", "fields": ["*"]}}, field_types=TYPES
    )
    assert out == {"multi_match": {"query": "rundll32"}}
    assert any("query_string" in n for n in notes)


def test_stray_clause_beside_bool_is_moved_inside():
    """`{"bool": {…}, "enable": false}` and `{"bool": {…}, "must_not": […]}`."""
    out, notes = normalize_query(
        {"bool": {"must": [{"term": {"family": "a"}}]},
         "must_not": [{"term": {"family": "b"}}],
         "enable": False},
        field_types=TYPES,
    )
    assert set(out) == {"bool"}
    assert len(out["bool"]["must"]) == 1
    assert out["bool"]["must_not"] == [{"term": {"family": "b"}}]
    assert any("enable" in n for n in notes)


def test_stray_clause_inside_bool_keeps_its_key():
    """`{"bool":{"must":[…],"range":{…}}}` — the range must stay a range."""
    out, notes = normalize_query(
        {"bool": {"must": [{"term": {"family": "a"}}],
                  "range": {"ts": {"gte": "2023-01-17"}}}},
        field_types=TYPES,
    )
    must = out["bool"]["must"]
    assert any("range" in clause for clause in must), must
    assert any("range" in n for n in notes)


def test_exists_missing_option_is_dropped():
    out, notes = normalize_query(
        {"exists": {"field": "fields.InUse", "missing": False}}, field_types=TYPES
    )
    assert out == {"exists": {"field": "fields.InUse"}}
    assert notes


def test_match_all_options_are_dropped():
    out, notes = normalize_query({"match_all": {"_all": True}}, field_types=TYPES)
    assert out == {"match_all": {}}
    assert notes


def test_aggs_as_a_json_string_is_parsed_and_aliased():
    out, notes = normalize_aggs(
        '{"by_family":{"terms":{"field":"family"}}}',
        TYPES,
    )
    assert out["by_family"]["terms"]["field"] == "family"
    assert any("JSON string" in n for n in notes)


def test_agg_shard_size_beside_the_type_is_moved_inside():
    out, notes = normalize_aggs(
        {"distinct": {"terms": {"field": "family", "size": 50}, "shard_size": 200}},
        TYPES,
    )
    assert out["distinct"]["terms"]["shard_size"] == 200
    assert any("shard_size" in n for n in notes)


def test_agg_on_a_text_field_uses_its_keyword():
    out, notes = normalize_aggs(
        {"by_cmd": {"terms": {"field": "fields.command_line"}}}, TYPES
    )
    assert out["by_cmd"]["terms"]["field"] == "fields.command_line.kw"
    assert any("keyword sub-field" in n for n in notes)


def test_unnamed_agg_is_wrapped_under_a_name():
    out, notes = normalize_aggs({"terms": {"field": "family"}}, TYPES)
    assert "agg" in out
    assert any("unnamed" in n for n in notes)


def test_agg_field_alias():
    out, _ = normalize_aggs({"by_host": {"terms": {"field": "host.hostname"}}}, TYPES)
    assert out["by_host"]["terms"]["field"] == "ecs.host.name"


def test_normalize_never_mutates_the_callers_body():
    """The tool audit-logs the body it sent; a retry re-sends it."""
    body = {"bool": {"must": [{"term": {"family": "a"}}]},
            "size": 50, "min_should_match": 1}
    snapshot = repr(body)
    normalize_query(body, field_types=TYPES)
    assert repr(body) == snapshot, "normalize_query mutated its input"

    aggs = {"a": {"terms": {"field": "family"}, "shard_size": 10}}
    snapshot = repr(aggs)
    normalize_aggs(aggs, TYPES)
    assert repr(aggs) == snapshot, "normalize_aggs mutated its input"
