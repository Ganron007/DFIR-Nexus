"""Phase 4k.5 — ES-native surface: allowlist validation, paging, hit shape."""
from __future__ import annotations

import json

import pytest

from nexus.langgraph import es_native

# ── validation (safety surface) ────────────────────────────────────────

def test_query_allowlist_rejects_dangerous_shapes():
    with pytest.raises(es_native.ESQueryError):
        es_native.validate_query({"script": {"source": "doc['a'].value > 1"}})
    with pytest.raises(es_native.ESQueryError):
        es_native.validate_query({"term": {"host": "x"}, "range": {"ts": {}}})
    with pytest.raises(es_native.ESQueryError):
        es_native.validate_query({"range": {"ts": {"gte": "2024-01-01", "script": "x"}}})
    with pytest.raises(es_native.ESQueryError):
        es_native.validate_query({"terms": {"host": {"index": "other"}}})
    deep: dict = {"match_all": {}}
    for _ in range(8):
        deep = {"bool": {"must": [deep]}}
    with pytest.raises(es_native.ESQueryError):
        es_native.validate_query(deep)


def test_query_allowlist_accepts_legit_shapes():
    es_native.validate_query({
        "bool": {
            "must": [
                {"term": {"family": "hayabusa"}},
                {"range": {"ts": {"gte": "2024-01-01T00:00:00Z", "lte": "2024-02-01T00:00:00Z"}}},
            ],
            "must_not": [{"match_phrase": {"text": "benign"}}],
            "filter": [{"exists": {"field": "host"}}],
        }
    })
    es_native.validate_query({"wildcard": {"text.wc": {"value": "*sdelete*", "case_insensitive": True}}})


def test_agg_allowlist_composite_and_scripts():
    es_native.validate_aggs({
        "by_host": {"terms": {"field": "host", "size": 10}},
        "pairs": {
            "composite": {
                "size": 500,
                "sources": [
                    {"u": {"terms": {"field": "user"}}},
                    {"h": {"terms": {"field": "host"}}},
                ],
            }
        },
    })
    with pytest.raises(es_native.ESQueryError):
        es_native.validate_aggs({"x": {"scripted_metric": {}}})
    with pytest.raises(es_native.ESQueryError):
        es_native.validate_aggs({"x": {"composite": {"sources": [{"a": {"script": {}}}]}}})


# ── fake ES client ─────────────────────────────────────────────────────

class _Resp:
    def __init__(self, code: int, payload: dict):
        self.status_code = code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class _FakeClient:
    def __init__(self, search_payload: dict | None = None, status: int = 200):
        self.search_payload = search_payload or {"hits": {"total": {"value": 0}, "hits": []}}
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def head(self, path):
        return _Resp(200 if self.status == 200 else 404, {})

    def get(self, path):
        name = path.strip("/").split("/")[0]
        return _Resp(200, {name: {"mappings": {"properties": {
            "family": {"type": "keyword"}, "ts": {"type": "date"},
            "fields": {"properties": {"Channel": {"type": "text", "fields": {"kw": {"type": "keyword"}}}}},
        }}}})

    def post(self, path, json=None):
        if "_search" in path and (json or {}).get("aggs"):
            return _Resp(200, {
                "took": 3,
                "aggregations": {
                    "pairs": {"after_key": {"u": "bob", "h": "WS01"}, "buckets": []},
                },
            })
        return _Resp(200, self.search_payload)


@pytest.fixture
def fake_es(monkeypatch, tmp_path):
    from nexus.langgraph import case_index

    client = _FakeClient()
    monkeypatch.setattr(case_index, "_client", lambda: client)
    monkeypatch.setattr(case_index, "es_available", lambda: True)
    monkeypatch.setattr(case_index, "fields_property_names", lambda _c: ["Channel"])
    return client


def test_es_search_shapes_hits_and_reports_exact_total(fake_es):
    fake_es.search_payload = {
        "took": 5,
        "hits": {"total": {"value": 5000}, "hits": [
            {"_source": {
                "family": "hayabusa", "file": "a.csv", "line": 7,
                "text": "sdelete used", "host": "WS01", "ts": "2020-11-14T04:49:43Z",
                "ts_src": "event", "ts_precision": "ms", "ts_tz_assumed": True,
                "fields": {"Channel": "Security"},
            }, "sort": [17]},
        ]},
    }
    out = es_native.es_search("CASE-X", {"match_all": {}}, size=200)
    assert out["total"] == 5000
    assert out["returned"] == 1
    assert out["has_more"] is True
    assert out["next_search_after"] == [17]
    hit = out["hits"][0]
    assert hit["family"] == "hayabusa"
    assert hit["fields"]["Channel"] == "Security"
    assert hit["ts_tz_assumed"] is True and hit["terms_list"] == []


def test_es_search_size_cap_and_index_missing(fake_es):
    with pytest.raises(es_native.ESQueryError):
        es_native.es_search("CASE-X", {"match_all": {}}, size=5000)
    fake_es.status = 404
    with pytest.raises(es_native.ESQueryError) as exc:
        es_native.es_search("CASE-X", {"match_all": {}})
    assert "index missing" in str(exc.value)


def test_es_unavailable_is_hard_error(monkeypatch):
    from nexus.langgraph import case_index

    monkeypatch.setattr(case_index, "es_available", lambda: False)
    with pytest.raises(es_native.ESQueryError) as exc:
        es_native.es_fields("CASE-X")
    assert "Elasticsearch unavailable" in str(exc.value)


def test_es_fields_lists_all_columns(fake_es):
    out = es_native.es_fields("CASE-X")
    core = {row["field"]: row["type"] for row in out["core_fields"]}
    assert core["family"] == "keyword" and core["ts"] == "date"
    parsed = {row["field"]: row["type"] for row in out["parsed_columns"]}
    assert parsed["Channel"] == "text(kw)"


def test_es_aggregate_returns_next_after_key(fake_es):
    out = es_native.es_aggregate(
        "CASE-X",
        {"pairs": {"composite": {"size": 500, "sources": [{"u": {"terms": {"field": "user"}}}]}}},
    )
    assert out["next_after_key"] == {"u": "bob", "h": "WS01"}


def test_es_sample_filters_family_and_spreads(fake_es):
    fake_es.search_payload = {
        "took": 2,
        "hits": {"total": {"value": 100}, "hits": [
            {"_source": {"family": "hayabusa", "file": "a.csv", "line": i,
                         "text": f"row {i}", "ts": f"2020-11-14T0{i}:00:00Z"},
             "sort": [i]}
            for i in range(1, 7)
        ]},
    }
    out = es_native.es_sample("CASE-X", family="hayabusa", field="Channel",
                              value="Security", n=3)
    assert out["backend"] == "elasticsearch"
    assert out["matched"] == 100
    assert 0 < out["sampled"] <= 3
    assert out["hits"]
