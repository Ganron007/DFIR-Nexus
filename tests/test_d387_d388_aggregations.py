"""D387 and D388: two model-written aggregation shapes that cost T21 Mode 2 its calls (R1z3, 2026-10-25).

D387 (audit nexus-claudebot-20261025-156): the request's `query` written inside `aggs`. The aggregation normalizer moved
stray options beside an agg type, but a request key among the named aggs reached the validator as an aggregation
called "query" and the call was refused.

D388 (audit nexus-claudebot-20261025-245): `cardinality` on `_id` to count the rows matching a query. `es_aggregate`
asked ES for the exact hit count (`track_total_hits`) and dropped it, so the model had no row count and improvised one
ES forbids (fielddata on `_id`), which came back as a raw 400. The result now carries `total`, and an aggregation on a
metadata field is refused before ES with that pointer.
"""
from __future__ import annotations

import pytest

from nexus.langgraph import es_native, query_normalize
from tests.test_es_native import _FakeClient, _Resp, fake_es  # noqa: F401 - the fixture

_D387 = {
    "by_hash": {"terms": {"field": "file_hash_sha256", "size": 20, "missing": "__empty__"}},
    "by_process": {"terms": {"field": "process_name", "size": 20, "missing": "__empty__"}},
    "query": {"match_all": {}},
}
_D388_AGGS = {"closed_tab_count": {"cardinality": {"field": "_id", "precision_threshold": 40}}}
_D388_QUERY = {"bool": {"must": [{"term": {"fields.data_type": "chrome:session:closed_tab"}}]}}


class _CountingES(_FakeClient):
    """Answers an aggregation search with an exact total, as ES does under `track_total_hits`."""

    def post(self, path, json=None):
        self.last_search_body = json
        return _Resp(200, {"took": 2, "hits": {"total": {"value": 37, "relation": "eq"}, "hits": []},
                           "aggregations": {name: {"value": 1} for name in (json or {}).get("aggs", {})}})


@pytest.fixture
def counting_es(monkeypatch):
    from nexus.langgraph import case_index

    client = _CountingES()
    monkeypatch.setattr(case_index, "_client", lambda: client)
    monkeypatch.setattr(case_index, "es_available", lambda: True)
    monkeypatch.setattr(case_index, "fields_property_names", lambda _c: [])
    return client


def test_d387_the_recorded_call_was_refused_as_an_aggregation_called_query():
    with pytest.raises(es_native.ESQueryError, match="agg 'query' must have exactly one type"):
        es_native.validate_aggs(_D387)


def test_d387_a_query_inside_aggs_becomes_the_request_query(counting_es):
    out = es_native.es_aggregate("CASE-X", _D387)
    sent = counting_es.last_search_body
    assert set(sent["aggs"]) == {"by_hash", "by_process"}
    assert sent["query"] == {"match_all": {}}
    assert any("query" in note and "aggs" in note for note in out["normalized"])


def test_d387_a_lifted_query_and_the_call_query_both_apply(counting_es):
    aggs = {"by_process": {"terms": {"field": "process_name"}}, "query": {"term": {"family": "hindsight"}}}
    es_native.es_aggregate("CASE-X", aggs, query={"range": {"ts": {"gte": "2020-11-14"}}})
    sent = str(counting_es.last_search_body["query"])
    assert "2020-11-14" in sent and "hindsight" in sent


def test_d388_the_result_carries_the_exact_row_count(counting_es):
    out = es_native.es_aggregate("CASE-X", {"by_process": {"terms": {"field": "process_name"}}})
    assert out["total"] == 37


def test_d388_an_aggregation_on_a_metadata_field_is_refused_with_the_pointer(counting_es):
    with pytest.raises(es_native.ESQueryError, match=r"metadata field `_id`.*`total`"):
        es_native.es_aggregate("CASE-X", _D388_AGGS, query=_D388_QUERY)
    assert counting_es.last_search_body is None, "refused before ES"


def test_the_normalizer_reads_the_validators_aggregation_types():
    assert query_normalize._AGG_TYPES is es_native._AGG_TYPES
