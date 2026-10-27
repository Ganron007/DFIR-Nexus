"""Real refused requests and canonical query shapes share one producer/consumer grammar."""
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from nexus.langgraph import context_loop, es_native
from nexus.langgraph.query_normalize import normalize_query
from nexus.langgraph.tool_generation import response_schema

REQUESTS = json.loads((Path(__file__).parent / "fixtures/t19_mode3_recovery1_requests.json").read_text())
TYPES = {"family": "keyword", "ts": "date", "line": "integer", "ecs": "object", "file": "keyword",
         "text": "text", "text.wc": "wildcard", "user": "text", "user.kw": "keyword",
         "fields.user": "text", "fields.user.kw": "keyword", "fields.artifact_type.kw": "keyword",
         "fields.ts_synthesized": "boolean"}


@pytest.fixture
def schema(monkeypatch):
    monkeypatch.setattr(es_native, "_field_types", lambda _: TYPES)
    return response_schema("CASE-CONTRACT", context_loop._TOOL_ARGS,
                           context_loop._REQUIRED_ARGS, context_loop._STRING_FIELDS_BY_TOOL)


@pytest.mark.parametrize("entry", REQUESTS, ids=lambda e: e["audit_id"].rsplit("-", 1)[1])
def test_every_exact_t19_refusal_is_excluded_at_generation(schema, entry):
    args = {k: copy.deepcopy(v) for k, v in entry["params"].items() if k != "case_id"}
    assert list(Draft202012Validator(schema).iter_errors({"tool_calls": [{
        "tool": entry["tool"], "args": args,
    }]})), entry["audit_id"]


QUERIES = [
    {"bool": {"must": [{"term": {"family": "cloudtrail"}}],
              "should": [{"exists": {"field": "text"}}], "minimum_should_match": 1}},
    {"term": {"family": {"value": "cloudtrail", "boost": 2, "case_insensitive": True}}},
    {"terms": {"family": ["cloudtrail", "aws_vpc_flow"], "boost": 2}},
    {"range": {"ts": {"gte": "2021-01-01", "lt": "2030-01-01"}}},
    {"match": {"text": {"query": "probe words", "boost": 2}}},
    {"match_phrase": {"text": {"query": "probe words", "boost": 2}}},
    {"multi_match": {"query": "words", "fields": ["text", "family"], "type": "best_fields"}},
    {"wildcard": {"text.wc": {"value": "*probe*", "case_insensitive": True}}},
    {"prefix": {"family": {"value": "cloud", "boost": 2}}},
    {"exists": {"field": "fields.ts_synthesized"}},
    {"match_all": {}}, {"match_none": {}}, {"ids": {"values": ["id"]}},
    {"regexp": {"family": {"value": "cloud.*", "flags": "ALL", "case_insensitive": False}}},
]


@pytest.mark.parametrize("query", QUERIES, ids=lambda q: next(iter(q)))
def test_all_existing_query_types_and_valid_object_forms_pass_both_ends(schema, query):
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate({"tool_calls": [{
        "tool": "es_search", "args": {"query": query},
    }]})
    es_native.validate_query(query)
    es_native.validate_canonical_query(query)


@pytest.mark.parametrize("kind", ["match", "match_phrase"])
def test_canonical_match_objects_and_boosts_survive_normalization(kind):
    query = {kind: {"family": {"query": "cloudtrail", "boost": 2}}}
    original = copy.deepcopy(query)
    normalized, _ = normalize_query(query, field_types=TYPES)
    assert normalized == original and query == original
    es_native.validate_query(normalized)
    es_native.validate_canonical_query(normalized)


@pytest.mark.parametrize("value", [True, False, "true", "false"])
def test_supported_boolean_query_values_pass_both_ends(schema, value):
    query = {"term": {"fields.ts_synthesized": value}}
    Draft202012Validator(schema).validate({"tool_calls": [{"tool": "es_search", "args": {"query": query}}]})
    assert es_native._coercible("boolean", value)


@pytest.mark.parametrize("value", [0, 1, "0", "1", "True", "False", "2021-07-29T13:00:00"])
def test_es_refused_boolean_values_fail_both_ends(schema, value):
    query = {"term": {"fields.ts_synthesized": value}}
    assert list(Draft202012Validator(schema).iter_errors({"tool_calls": [{
        "tool": "es_search", "args": {"query": query},
    }]}))
    assert not es_native._coercible("boolean", value)


def test_unknown_field_remains_a_structurally_valid_neutral_hint(schema):
    query = {"term": {"fields.not_in_this_mapping": "value"}}
    Draft202012Validator(schema).validate({"tool_calls": [{"tool": "es_search", "args": {"query": query}}]})
    es_native.validate_canonical_query(query)


def test_filter_aggregations_use_the_same_recursive_query_contract(schema):
    bad = {"bool": {"must": ["range({", "ts"]}}
    args = {"aggs": {"condition": {"filter": bad}}}
    assert list(Draft202012Validator(schema).iter_errors({"tool_calls": [{"tool": "es_aggregate", "args": args}]}))


@pytest.mark.parametrize("kind,spec", [
    ("term", {"value": "cloudtrail", "boost": "2"}),
    ("match", {"query": "cloudtrail", "boost": "2"}),
    ("match_phrase", {"query": "cloudtrail", "boost": "2"}),
    ("terms", None),
])
def test_valid_numeric_option_spellings_are_reported_and_preserve_weights(kind, spec):
    query = ({"terms": {"family": ["cloudtrail"], "boost": "2"}} if kind == "terms" else
             {kind: {"family": spec}})
    original = copy.deepcopy(query)
    normalized, notes = normalize_query(query, field_types=TYPES)
    assert query == original
    body = normalized[kind] if kind == "terms" else normalized[kind]["family"]
    assert body["boost"] == 2 and not isinstance(body["boost"], str)
    assert any("boost" in note for note in notes)
    es_native.validate_query(normalized)
    es_native.validate_canonical_query(normalized)


@pytest.mark.parametrize("field", ["script", "_script", "script.source", "fields.Script", "fields._SCRIPT"])
def test_unknown_name_branch_cannot_bypass_existing_script_field_guard(schema, field):
    query = {"term": {field: "value"}}
    assert list(Draft202012Validator(schema).iter_errors({"tool_calls": [{
        "tool": "es_search", "args": {"query": query},
    }]}))
    with pytest.raises(es_native.ESQueryError, match="field names cannot contain scripts"):
        es_native.validate_query(query)


def test_field_catalog_and_native_queries_share_type_classification():
    from nexus.langgraph import field_catalog, query_contract

    assert field_catalog.NUMERIC_TYPES is es_native._NUMERIC_ES is query_contract.NUMERIC_TYPES
    assert field_catalog.DATE_TYPES is es_native._DATE_ES is query_contract.DATE_TYPES
