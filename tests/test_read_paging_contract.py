"""Paging must preserve the requested sort/cursor and refuse ambiguous envelopes."""
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from nexus.langgraph import context_loop, es_native
from nexus.langgraph.tool_generation import response_schema
from tests.test_es_native import fake_es  # noqa: F401

REQUESTS = json.loads((Path(__file__).parent / "fixtures/t19_mode3_recovery1_requests.json").read_text())
TYPES = {"ts": "date", "family": "keyword", "line": "long", "file": "keyword",
         "fields.dest_ip": "keyword", "fields.source_ip": "keyword", "fields.user": "keyword"}


@pytest.fixture
def index(request, monkeypatch):
    client = request.getfixturevalue("fake_es")
    monkeypatch.setattr(es_native, "_field_types", lambda _: TYPES)
    monkeypatch.setattr(es_native, "_mapping_field_types", lambda _: TYPES)
    return client


@pytest.fixture
def schema(monkeypatch):
    monkeypatch.setattr(es_native, "_field_types", lambda _: TYPES)
    return response_schema("CASE-X", context_loop._TOOL_ARGS,
                           context_loop._REQUIRED_ARGS, context_loop._STRING_FIELDS_BY_TOOL)


@pytest.mark.parametrize("suffix", ["1379", "1380", "1381"])
def test_exact_conflicting_nested_options_are_refused_before_es(index, suffix):
    params = copy.deepcopy(next(e["params"] for e in REQUESTS if e["audit_id"].endswith("-" + suffix)))
    original = copy.deepcopy(params)
    with pytest.raises(es_native.ESQueryError, match="request option"):
        es_native.es_search(**params)
    assert params == original and index.last_search_body is None


@pytest.mark.parametrize("sort,cursor", [(None, [1, 2]), ([], [1, 2]),
    ([{"ts": "asc"}], [1, 2]), ([{"ts": "asc"}, {"line": "desc"}], [1])])
def test_valid_query_cannot_bypass_cursor_sort_arity(index, schema, sort, cursor):
    args = {"query": {"match_all": {}}, "sort": sort, "search_after": cursor}
    assert list(Draft202012Validator(schema).iter_errors({"tool_calls": [{"tool": "es_search", "args": args}]}))
    with pytest.raises(es_native.ESQueryError, match="search_after.*sort"):
        es_native.es_search("CASE-X", **args)
    assert index.last_search_body is None


@pytest.mark.parametrize("sort", [[{"ts": "asc"}] * 5, [False], [{"ts": 42}], [{"ts": "up"}],
                                  [{"ts": {"order": False}}]])
def test_invalid_sorts_are_never_dropped_or_truncated(index, schema, sort):
    args = {"query": {"match_all": {}}, "sort": sort}
    assert list(Draft202012Validator(schema).iter_errors({"tool_calls": [{"tool": "es_search", "args": args}]}))
    with pytest.raises(es_native.ESQueryError, match="sort"):
        es_native.es_search("CASE-X", **args)
    assert index.last_search_body is None


@pytest.mark.parametrize("cursor", [[{}], [[1]], "1", [float("inf")]])
def test_cursor_is_a_finite_scalar_array(index, cursor):
    with pytest.raises(es_native.ESQueryError, match="search_after"):
        es_native.es_search("CASE-X", {"match_all": {}}, search_after=cursor)
    assert index.last_search_body is None


@pytest.mark.parametrize("sort,cursor", [(None, None), (None, []), (None, [7]),
    ([], [7]), (["_doc"], [7]), ([{"ts": "desc"}, {"line": "asc"}], [123, 7])])
def test_valid_paging_exposes_effective_sort_through_seat_summary(index, schema, sort, cursor):
    args = {"query": {"match_all": {}}, "size": 1, "sort": sort, "search_after": cursor}
    Draft202012Validator(schema).validate({"tool_calls": [{"tool": "es_search", "args": args}]})
    effective = sort or ["_doc"]
    next_cursor = list(range(len(effective)))
    index.search_payload = {"hits": {"total": {"value": 100}, "hits": [
        {"_source": {"family": "cloudtrail", "line": 1}, "sort": next_cursor}]}}
    result = es_native.es_search("CASE-X", **args)
    assert result["sort"] == index.last_search_body["sort"]
    assert len(result["sort"]) == len(result["next_search_after"])
    assert context_loop._result_summary("es_search", result)["sort"] == result["sort"]
    if cursor:
        assert index.last_search_body["search_after"] == cursor
    if effective == ["_doc"]:
        assert result["sort"] == ["_doc"]


@pytest.mark.parametrize("query", [
    {"query": {"match_all": {}}, "size": 3},
    {"bool": {"must": [{"match_all": {}}], "sort": [{"ts": "asc"}]}},
    {"bool": {"must": [{"match_all": {}, "search_after": [3]}]}},
    {"match_all": {}, "_source": ["line"]},
    {"query": {"match_all": {}}, "family": "cloudtrail"},
    '{"query":{"match_all":{}},"size":3}',
])
def test_request_options_in_query_slots_are_not_silently_discarded(index, query):
    with pytest.raises(es_native.ESQueryError, match="request option"):
        es_native.es_search("CASE-X", query)
    assert index.last_search_body is None


def test_envelope_detection_does_not_treat_data_field_names_as_options(index):
    result = es_native.es_search("CASE-X", {"term": {"fields.user": "sort"}})
    assert "error" not in result


def test_real_data_field_named_size_remains_a_query_field(index, monkeypatch):
    mapped = {**TYPES, "size": "long"}
    monkeypatch.setattr(es_native, "_field_types", lambda _: mapped)
    monkeypatch.setattr(es_native, "_mapping_field_types", lambda _: mapped)
    result = es_native.es_search("CASE-X", {"term": {"size": 5}})
    assert "error" not in result
    assert index.last_search_body["query"] == {"term": {"size": 5}}


@pytest.mark.parametrize("aggs", [
    {"selection": {"filter": {"match_all": {}, "size": 2}}},
    {"selections": {"filters": {"filters": {"named": {"bool": {"size": 2}}}}}},
    '{"selection":{"filter":{"match_all":{},"size":2}}}',
])
def test_aggregation_query_slots_do_not_drop_request_options(index, aggs):
    with pytest.raises(es_native.ESQueryError, match="request option"):
        es_native.es_aggregate("CASE-X", aggs)
    assert index.last_search_body is None


@pytest.mark.parametrize("sort", [[{"no_such_field": "asc"}], ["_id"]])
def test_existing_cursor_cannot_be_reused_after_sort_field_substitution(index, sort):
    with pytest.raises(es_native.ESQueryError, match="search_after.*substituted sort"):
        es_native.es_search("CASE-X", {"match_all": {}}, sort=sort, search_after=[7])
    assert index.last_search_body is None
