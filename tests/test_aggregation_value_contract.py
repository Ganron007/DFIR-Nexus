"""Verbatim T19 refusals must fail the producer and strict native contract."""
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from nexus.langgraph import context_loop, es_native
from nexus.langgraph.tool_generation import response_schema

REQUESTS = json.loads((Path(__file__).parent / "fixtures/t19_mode3_recovery1_requests.json").read_text())


@pytest.mark.parametrize("suffix", ["920", "1410"])
def test_exact_aggregation_value_refusals_are_excluded_by_generation(monkeypatch, suffix):
    monkeypatch.setattr(es_native, "_field_types", lambda _: {
        "user": "keyword", "ts": "date", "ecs": "object",
    })
    entry = next(e for e in REQUESTS if e["audit_id"].endswith("-" + suffix))
    params = {k: copy.deepcopy(v) for k, v in entry["params"].items() if k != "case_id"}
    schema = response_schema(entry["params"]["case_id"], context_loop._TOOL_ARGS,
                             context_loop._REQUIRED_ARGS, context_loop._STRING_FIELDS_BY_TOOL)
    assert list(Draft202012Validator(schema).iter_errors({"tool_calls": [{
        "tool": entry["tool"], "args": params,
    }]})), "The generation contract still admits the exact raw ES failure"


@pytest.mark.parametrize("suffix", ["920", "1410"])
def test_exact_aggregation_value_refusals_fail_the_strict_consumer(suffix):
    entry = next(e for e in REQUESTS if e["audit_id"].endswith("-" + suffix))
    with pytest.raises(es_native.ESQueryError, match="terms size"):
        es_native.validate_aggs(copy.deepcopy(entry["params"]["aggs"]))


@pytest.mark.parametrize("bad", [[], [["value"]], {}, True, 0, -1, 1.5])
def test_terms_size_is_a_positive_integer(bad):
    with pytest.raises(es_native.ESQueryError, match="terms size"):
        es_native.validate_aggs({"arbitrary": {"terms": {"field": "family", "size": bad}}})


def test_scalar_normalization_preserves_named_filter_query_normalization():
    from nexus.langgraph.query_normalize import normalize_aggs

    source = {"classes": {"filters": {"other_bucket": "false", "filters": {
        "fn": {"wildcard": {"text": "*function*", "case_insensitive": True}},
    }}}}
    unchanged = copy.deepcopy(source)
    normalized, notes = normalize_aggs(source, {"text": "text", "text.wc": "wildcard"})
    es_native.validate_aggs(normalized)
    assert source == unchanged
    assert normalized["classes"]["filters"]["other_bucket"] is False
    assert normalized["classes"]["filters"]["filters"]["fn"] == {
        "wildcard": {"text": {"value": "*function*", "case_insensitive": True}},
    }
    assert any("other_bucket" in note for note in notes)


@pytest.mark.parametrize("body", [
    {"terms": {"field": "family", "size": 100001, "order": [{"_count": "desc"}, {"_key": "asc"}]}},
    {"top_hits": {"size": 2, "_source": {"includes": ["family", "ts"]}, "sort": ["ts"] * 5}},
    {"date_range": {"field": "ts", "ranges": [{"from": None, "to": "2021-01-01"}], "keyed": True}},
    {"terms": {"field": "family", "include": {"partition": 0, "num_partitions": 2}}},
])
def test_supported_option_forms_keep_their_existing_limits(body, monkeypatch):
    es_native.validate_aggs({"arbitrary investigator name": body})
    monkeypatch.setattr(es_native, "_field_types", lambda _: {"family": "keyword", "ts": "date"})
    schema = response_schema("CASE-CONTRACT", context_loop._TOOL_ARGS,
                             context_loop._REQUIRED_ARGS, context_loop._STRING_FIELDS_BY_TOOL)
    Draft202012Validator(schema).validate({"tool_calls": [{
        "tool": "es_aggregate", "args": {"aggs": {"arbitrary investigator name": body}},
    }]})


@pytest.mark.parametrize("source", [False, "family", ["family", "ts"], {"excludes": "text"}])
def test_top_hits_source_projection_forms_are_preserved(source):
    es_native.validate_aggs({"examples": {"top_hits": {"_source": source}}})


@pytest.mark.parametrize("body", [
    {"histogram": {"field": "line"}},
    {"date_histogram": {"field": "ts"}},
    {"date_histogram": {"field": "ts", "fixed_interval": "1h", "calendar_interval": "day"}},
    {"composite": {"sources": [{"time": {"date_histogram": {"fixed_interval": "1h"}}}]}},
])
def test_incomplete_or_conflicting_aggregation_bodies_are_refused(body, monkeypatch):
    with pytest.raises(es_native.ESQueryError):
        es_native.validate_aggs({"arbitrary": body})
    monkeypatch.setattr(es_native, "_field_types", lambda _: {"line": "integer", "ts": "date"})
    schema = response_schema("CASE-CONTRACT", context_loop._TOOL_ARGS,
                             context_loop._REQUIRED_ARGS, context_loop._STRING_FIELDS_BY_TOOL)
    assert list(Draft202012Validator(schema).iter_errors({"tool_calls": [{
        "tool": "es_aggregate", "args": {"aggs": {"arbitrary": body}},
    }]}))


def test_promoted_composite_size_uses_the_same_scalar_contract():
    from nexus.langgraph.query_normalize import normalize_aggs

    source = {"groups": {"composite": {"sources": [
        {"arbitrary": {"terms": {"field": "family", "size": "100"}}},
    ]}}}
    normalized, notes = normalize_aggs(source, {"family": "keyword"})
    es_native.validate_aggs(normalized)
    assert normalized["groups"]["composite"]["size"] == 100
    assert "size" not in normalized["groups"]["composite"]["sources"][0]["arbitrary"]["terms"]
    assert any("size" in note and "scalar" in note for note in notes)
