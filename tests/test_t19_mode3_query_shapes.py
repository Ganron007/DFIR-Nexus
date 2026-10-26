"""Verbatim interrupted T19 Mode 3 requests; strict raw guards stay intact."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from nexus.langgraph import context_loop, es_native, query_normalize
from tests.test_d387_d388_aggregations import counting_es  # noqa: F401
from tests.test_t19_query_surface import TYPES

REQUESTS = json.loads((Path(__file__).parent / "fixtures/t19_mode3_requests.json").read_text())


@pytest.fixture
def index(request, monkeypatch):
    client = request.getfixturevalue("counting_es")
    types = {**TYPES, "text": "text"}
    monkeypatch.setattr(es_native, "_field_types", lambda _case: types)
    monkeypatch.setattr(es_native, "_mapping_field_types", lambda _case: types)
    return client


def request(suffix):
    return copy.deepcopy(next(entry["params"] for entry in REQUESTS if entry["audit_id"].endswith("-" + suffix)))


def test_exact_476_fixed_hour_is_compiled_to_a_duration(index):
    result = es_native.es_aggregate(**request("476"))
    assert index.last_search_body["aggs"]["by_hour"]["date_histogram"]["fixed_interval"] == "1h"
    assert any("hour" in note and "1h" in note for note in result["normalized"])


def test_exact_715_inclusive_lower_and_exclusive_upper_bounds_keep_their_semantics(index):
    params = request("715")
    result = es_native.es_aggregate(**params)
    expected = [{"from": row["gte"], "to": row["lt"]} for row in params["aggs"]["time_range"]["date_range"]["ranges"]]
    assert index.last_search_body["aggs"]["time_range"]["date_range"]["ranges"] == expected
    assert any("gte" in note and "from" in note for note in result["normalized"])


@pytest.mark.parametrize("bounds", [
    {"gte": "2021-01-01", "from": "2020-01-01"},
    {"lt": "2021-02-01", "to": "2021-03-01"},
    {"gt": "2021-01-01"}, {"lte": "2021-02-01"}, {"script": "unsafe"},
])
def test_range_bounds_with_conflicts_or_different_inclusivity_remain_refused(bounds):
    aggs, _ = query_normalize.normalize_aggs({"r": {"date_range": {"field": "ts", "ranges": [bounds]}}})
    with pytest.raises(es_native.ESQueryError, match="range bound"):
        es_native.validate_aggs(aggs)


def test_the_other_three_exact_requests_still_require_a_producer_fix(index):
    # These refusals must not be made to pass by guessing the model's intent.
    _, error, _ = context_loop._validate_call_args("es_search", request("538"))
    assert "at least 1" in error
    with pytest.raises(es_native.ESQueryError, match="analysed text"):
        es_native.es_aggregate(**request("637"))
    with pytest.raises(es_native.ESQueryError, match="ranges.*min.*max"):
        es_native.es_aggregate(**request("748"))
