"""Exact T19 temporal refusals and producer/consumer field agreement."""
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from nexus.langgraph import context_loop, es_native
from nexus.langgraph.tool_generation import response_schema

REQUESTS = json.loads((Path(__file__).parent / "fixtures/t19_mode3_recovery1_requests.json").read_text())
TYPES = {"fields.user": "text", "fields.user.kw": "keyword", "fields.artifact_type.kw": "keyword",
         "ts": "date", "line": "integer", "flag": "boolean"}


@pytest.mark.parametrize("suffix", ["1302", "1303"])
def test_exact_temporal_refusals_are_excluded_before_es_and_at_generation(monkeypatch, suffix):
    monkeypatch.setattr(es_native, "_field_types", lambda _: TYPES)
    entry = next(e for e in REQUESTS if e["audit_id"].endswith("-" + suffix))
    params = copy.deepcopy(entry["params"])
    schema = response_schema(params["case_id"], context_loop._TOOL_ARGS,
                             context_loop._REQUIRED_ARGS, context_loop._STRING_FIELDS_BY_TOOL)
    args = {k: v for k, v in params.items() if k != "case_id"}
    assert list(Draft202012Validator(schema).iter_errors({"tool_calls": [{
        "tool": entry["tool"], "args": args,
    }]})), "The producer must exclude the exact request its consumer cannot execute"

    def no_dispatch(*args, **kwargs):
        raise AssertionError("An incompatible mapped field must not reach ES")

    monkeypatch.setattr(es_native, "_client_and_index", no_dispatch)
    with pytest.raises(es_native.ESQueryError, match="needs a number or a date"):
        es_native.es_aggregate(**params)


@pytest.mark.parametrize("agg_type", ["date_histogram", "date_range"])
@pytest.mark.parametrize("field", ["fields.user", "fields.user.kw"])
def test_temporal_aggregations_and_composite_sources_share_eligibility(agg_type, field):
    body = {"field": field}
    if agg_type == "date_histogram":
        body["fixed_interval"] = "1h"
    else:
        body["ranges"] = [{"from": 0, "to": 2}]
    problems = es_native._aggregation_field_problems({"arbitrary": {agg_type: body}}, TYPES)
    assert problems and field in problems[0]
    if agg_type in es_native._COMPOSITE_SOURCES:
        problems = es_native._aggregation_field_problems({"arbitrary": {"composite": {
            "sources": [{"source": {agg_type: body}}],
        }}}, TYPES)
        assert problems and "composite source" in problems[0]


@pytest.mark.parametrize("kind", ["date", "date_nanos", "long", "integer", "double", "boolean"])
@pytest.mark.parametrize("agg_type", ["date_histogram", "date_range"])
def test_native_numeric_date_and_boolean_value_sources_remain_eligible(kind, agg_type):
    # ES 8.17.4 controls confirm numeric and boolean doc values work too;
    # restricting these aggregations to mapped dates would remove supported calls.
    assert not es_native.aggregation_field_problem(agg_type, "field", {"field": kind})
