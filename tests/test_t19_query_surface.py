"""Exact audited requests from both T19 Mode 2 runs; no reconstructed lost args.

Backend doubles test contracts. Real-index replay evidence is kept in the runbook
logs separately; mock responses are never represented as forensic evidence.
"""
from __future__ import annotations

import copy
import inspect
import json
from pathlib import Path

import pytest

from nexus.langgraph import backbone, context_loop, es_native
from tests.test_d387_d388_aggregations import counting_es  # noqa: F401

REQUESTS = json.loads((Path(__file__).parent / "fixtures/t19_mode2_requests.json").read_text())
TYPES = {
    "ts": "date", "family": "keyword", "user": "text", "user.kw": "keyword",
    **{f"fields.{field}": "keyword" for field in (
        "action", "severity", "protocol", "source_ip", "dest_ip", "dest_port", "source", "description",
    )},
    "fields.user": "keyword", "ecs.file.path": "keyword",
}


def request(suffix):
    entry = copy.deepcopy(next(a for a in REQUESTS if a["audit_id"].endswith(f"-{suffix}")))
    return entry, entry["params"]


@pytest.fixture
def index(request, monkeypatch):
    client = request.getfixturevalue("counting_es")
    monkeypatch.setattr(es_native, "_field_types", lambda _case: TYPES)
    monkeypatch.setattr(es_native, "_mapping_field_types", lambda _case: TYPES)
    return client


@pytest.mark.parametrize("suffix", ["404", "422", "429"])
def test_d408_exact_captured_requests_pass_the_runtime_argument_contract(suffix):
    _, params = request(suffix)
    clean, error, _ = context_loop._validate_call_args("es_aggregate", params)
    assert not error
    assert clean == {key: value for key, value in params.items() if key != "case_id"}


@pytest.mark.parametrize("tool", ["es_search", "es_aggregate"])
def test_d408_prompt_loop_and_native_signature_share_the_argument_contract(tool):
    names = [name for name in inspect.signature(getattr(es_native, tool)).parameters if name != "case_id"]
    assert context_loop._TOOL_ARGS[tool] == set(names)
    assert f"{tool}(case_id, {', '.join(names)})" in backbone.tool_contracts_block()


def test_d408_a_family_filter_is_conjoined_with_the_exact_request_query(index):
    _, params = request("404")
    result = es_native.es_aggregate(**params)
    assert not result.get("error")
    sent = index.last_search_body["query"]
    assert sent["bool"]["filter"] == [{"term": {"family": "aws_vpc_flow"}}]
    assert sent["bool"]["must"] == [{"term": {"fields.action": "accept"}}]


def test_d411_the_recorded_explicit_fixed_interval_becomes_a_time_histogram(index):
    _, params = request("344")
    result = es_native.es_aggregate(**params)
    assert not result.get("error")
    assert index.last_search_body["aggs"]["ts_range"] == {
        "date_histogram": {"field": "ts", "fixed_interval": "1d", "time_zone": "UTC"},
    }
    assert any("fixed_intervals" in note for note in result["normalized"])
    assert len(index.last_search_body["aggs"]) == 4


def test_d412_the_recorded_count_and_metric_group_keep_their_scopes(index):
    _, params = request("347")
    result = es_native.es_aggregate(**params)
    assert result["aggregations"]["total"] == {"value": result["total"]}
    assert result["total"] == 37
    sent = index.last_search_body["aggs"]
    assert set(sent) == {"by_dest_port", "by_dest_ip", "by_source_ip", "by_protocol", "total", "time_range"}
    assert sent["time_range"] == {
        "filter": {"match_all": {}}, "aggs": {
            "first": {"min": {"field": "ts"}}, "last": {"max": {"field": "ts"}},
        },
    }
    assert index.last_search_body["query"] == {"term": {"family": "aws_vpc_flow"}}


def test_d407_the_recorded_id_value_count_uses_the_exact_backend_total(index):
    _, params = request("313")
    result = es_native.es_aggregate(**params)
    assert result["aggregations"]["total_vpc"] == {"value": result["total"]}
    assert result["total"] == 37
    assert "_id" not in json.dumps(index.last_search_body)
    assert any("exact" in note and "total" in note for note in result["normalized"])


def test_d407_the_removed_type_field_gets_an_honest_schema_hint(index):
    _, params = request("059")
    result = es_native.es_aggregate(**params)
    assert es_native.is_unknown_field_hint(result["error"])
    assert result["aggregations"] == {}
    assert "total" not in result, "unexecutable aggregation must not claim a measured count"
    assert any(ref["field"] == "_type" for ref in result["failed_terms"])
    assert index.last_search_body is None


def test_d413_explicit_true_inclusion_keeps_both_requested_aggregations(index):
    _, params = request("457")
    result = es_native.es_aggregate(**params)
    assert not result.get("error")
    assert set(index.last_search_body["aggs"]) == {"by_dest_ip", "by_accept_dest_ip"}
    assert any("include_in_aggregation" in note for note in result["normalized"])
    assert "include_in_aggregation" not in json.dumps(index.last_search_body)


@pytest.mark.parametrize("value", [False, "true", 1, None])
def test_d413_an_ambiguous_or_negative_inclusion_is_still_refused(index, value):
    _, params = request("457")
    params["aggs"]["by_accept_dest_ip"]["terms"]["include_in_aggregation"] = value
    with pytest.raises(es_native.ESQueryError, match="unsupported terms options"):
        es_native.es_aggregate(**params)
    assert index.last_search_body is None


@pytest.mark.parametrize("suffix", ["059", "313", "344", "347", "457"])
def test_the_strict_raw_aggregation_validator_still_refuses_the_original_invalid_shapes(suffix):
    _, params = request(suffix)
    with pytest.raises(es_native.ESQueryError):
        es_native.validate_aggs(params["aggs"])


def test_d414_a_real_native_producer_result_keeps_counts_and_notes_for_the_seat(index):
    _, params = request("325")
    result = es_native.es_aggregate(**params)
    summary = context_loop._result_summary("es_aggregate", result)
    assert summary["total"] == result["total"] == 37
    assert summary["normalized"] == result["normalized"]


def test_unknown_field_hints_cannot_hide_a_later_unsafe_aggregation(index):
    _, params = request("059")
    params["aggs"]["unsafe"] = {"terms": {"field": "user", "script": "1"}}
    with pytest.raises(es_native.ESQueryError, match="script"):
        es_native.es_aggregate(**params)
    assert index.last_search_body is None


@pytest.mark.asyncio
async def test_d408_the_real_mcp_schema_uses_the_same_native_arguments(tmp_path):
    from mcp.server.fastmcp import FastMCP

    from nexus.audit import AuditWriter
    from nexus.tools.evidence_index import _register_native_read_tool

    server = FastMCP("native-contract")
    for name in ("es_search", "es_aggregate"):
        _register_native_read_tool(server, AuditWriter("nexus", audit_dir=tmp_path / "audit"), name)
    tools = {tool.name: tool for tool in await server.list_tools()}
    for name, tool in tools.items():
        assert set(tool.inputSchema["properties"]) == {"case_id", *es_native.READ_TOOL_PARAMETERS[name]}


def test_d408_dispatched_failure_keeps_the_same_full_replay_parameters(tmp_path, monkeypatch):
    from nexus.audit import AuditWriter
    from nexus.tools import evidence_index

    case = tmp_path / "CASE-CAPTURE"
    case.mkdir()
    monkeypatch.setattr(evidence_index, "_resolve_active_case", lambda *_: (case, ""))
    params = {"query": {"terms": {"family": ["x" * 700 + str(i) for i in range(25)]}}, "size": 5}

    def refuse(*_, **kwargs):
        assert kwargs == params
        raise es_native.ESQueryError("controlled backend refusal")

    monkeypatch.setattr(es_native, "es_search", refuse)
    audit = AuditWriter("nexus", audit_dir=case / "audit")
    result = backbone._es_call("es_search", audit=audit, case_id=case.name, case_dir=case, **params)
    assert result.get("error")
    row, = [json.loads(line) for line in (case / "audit/nexus.jsonl").read_text().splitlines()]
    assert row["params"] == {"case_id": case.name, **params}
    assert row["audit_id"] == result["provenance"]["audit_id"]


@pytest.mark.asyncio
async def test_d408_the_real_mcp_caller_delivers_the_captured_family_scope(index, tmp_path, monkeypatch):
    from mcp.server.fastmcp import FastMCP

    from nexus.audit import AuditWriter
    from nexus.tools import evidence_index

    _, params = request("404")
    case = tmp_path / params["case_id"]
    case.mkdir()
    monkeypatch.setattr(evidence_index, "_resolve_active_case", lambda *_: (case, ""))
    server = FastMCP("native-call")
    evidence_index._register_native_read_tool(server, AuditWriter("nexus", audit_dir=case / "audit"), "es_aggregate")
    await server.call_tool("es_aggregate", params)
    assert index.last_search_body["query"]["bool"]["filter"] == [{"term": {"family": "aws_vpc_flow"}}]
    row, = [json.loads(line) for line in (case / "audit/nexus.jsonl").read_text().splitlines()]
    for key, value in params.items():
        assert row["params"][key] == value
    assert not row["result_summary"].get("error")


@pytest.mark.parametrize("relation,total", [("gte", 37), ("eq", None)])
def test_row_counts_require_an_exact_measured_backend_total(index, monkeypatch, relation, total):
    from tests.test_es_native import _Resp

    monkeypatch.setattr(index, "post", lambda *_a, **_k: _Resp(200, {
        "hits": {"total": {"value": total, "relation": relation}}, "aggregations": {},
    }))
    _, params = request("313")
    with pytest.raises(es_native.ESQueryError, match="exact hits.total"):
        es_native.es_aggregate(**params)


def test_row_count_compilation_does_not_bypass_the_aggregation_count_limit(index):
    aggs = {f"count_{i}": {"value": "_count"} for i in range(es_native.MAX_AGGS + 1)}
    with pytest.raises(es_native.ESQueryError, match="too many aggregations"):
        es_native.es_aggregate("CASE-X", aggs)
    assert index.last_search_body is None


def test_a_nested_count_is_never_substituted_with_the_global_total(index):
    aggs = {"scoped": {"filter": {"term": {"user": "a"}},
                       "aggs": {"n": {"value_count": {"field": "_id"}}}}}
    with pytest.raises(es_native.ESQueryError, match="metadata field"):
        es_native.es_aggregate("CASE-X", aggs)
    assert index.last_search_body is None


def test_fixed_intervals_cannot_override_explicit_ranges(index):
    _, params = request("344")
    params["aggs"]["ts_range"]["date_range"]["ranges"] = [{"from": "2020-01-01", "to": "2021-01-01"}]
    with pytest.raises(es_native.ESQueryError, match="unsupported date_range options"):
        es_native.es_aggregate(**params)
    assert index.last_search_body is None


def test_sort_and_size_reach_the_aggregate_request(index):
    _, params = request("313")
    params.update(size=5, sort=[{"ts": "desc"}])
    es_native.es_aggregate(**params)
    assert index.last_search_body["size"] == 5
    assert index.last_search_body["sort"] == [{"ts": {"order": "desc"}}]


def test_unknown_metadata_cannot_mask_an_invalid_top_hits_child(index):
    _, params = request("059")
    params["aggs"]["bad"] = {"top_hits": {"size": 1}, "aggs": {"child": {"scripted_metric": {}}}}
    with pytest.raises(es_native.ESQueryError, match="top_hits cannot have sub-aggregations"):
        es_native.es_aggregate(**params)
    assert index.last_search_body is None


def test_d415_the_recorded_preview_request_reaches_the_response_and_real_consumer(index, monkeypatch):
    from tests.test_es_native import _Resp

    # Opaque transport markers exercise forwarding, not invented forensic rows.
    source = {"transport_ref": "opaque"}
    shaped = {"transport_ref": "shaped-opaque"}
    monkeypatch.setattr(es_native, "_shape_hit", lambda received: shaped if received == source else None)
    monkeypatch.setattr(index, "post", lambda *_a, **_k: _Resp(200, {
        "hits": {"total": {"value": 37, "relation": "eq"}, "hits": [{"_source": source}]},
        "aggregations": {"total_vpc": {"doc_count": 37}},
    }))
    _, params = request("461")
    result = es_native.es_aggregate(**params)
    assert result["hits"] == [shaped]
    assert result["returned"] == 1
    assert result["aggregations"]["total_vpc"] == {"value": 37}
    hits = []
    calls = []
    observed = context_loop._append_tool_observation(
        tool_calls=calls, all_hits=hits, aggregations=[], name="es_aggregate",
        args=params, why="verify preview forwarding", result=result, elapsed_ms=1,
    )
    assert observed["summary"]["hits"] == [shaped]
    assert observed["summary"]["returned"] == 1
    assert hits == [shaped]
