"""Current index metadata, using published native counters and no event records."""
import copy
import json
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest

from nexus.langgraph import case_digest, case_index


def _coverage():
    path = Path(__file__).parent / "fixtures" / "t22_case_digest.json"
    return json.loads(path.read_text(encoding="utf-8"))["digest"]["ts_coverage"]


class CoverageTransport:
    """Transport control replies contain counts, never reconstructed evidence."""

    def __init__(self, coverage):
        self.coverage = coverage
        self.requests = []
        self.failure = None

    def __call__(self, request):
        self.requests.append(request)
        if request.method == "HEAD":
            return httpx.Response(200)
        if request.url.path.endswith("/_count"):
            return httpx.Response(200, json={"count": sum(
                value["present"] + value["missing"] for value in self.coverage.values()
            )})
        if request.url.path.endswith("/_search"):
            body = json.loads(request.content)
            if "ignored" in body.get("aggs", {}):
                return httpx.Response(200, json={"aggregations": {"ignored": {"buckets": []}}})
            if self.failure is not None:
                return self.failure
            spec = body["aggs"]["families"]
            composite = spec["composite"]
            assert composite["sources"] == [{"family": {"terms": {"field": "family"}}}]
            filters = spec["aggs"]["clocks"]["filters"]["filters"]
            assert filters == {
                "present": {"exists": {"field": "ts"}},
                "missing": {"bool": {"must_not": [{"exists": {"field": "ts"}}]}},
                "synthesized": {"term": {"ts_src": "synthesized"}},
                "tz_assumed": {"term": {"ts_tz_assumed": True}},
                "year_assumed": {"term": {"ts_year_assumed": True}},
            }
            after = composite.get("after", {}).get("family", "")
            remaining = sorted(family for family in self.coverage if family > after)
            buckets = []
            result = {"buckets": buckets}
            if remaining:
                family = remaining[0]
                counts = self.coverage[family]
                buckets.append({"key": {"family": family},
                                "doc_count": counts["present"] + counts["missing"],
                                "clocks": {"buckets": {
                                    key: {"doc_count": value} for key, value in counts.items()
                                }}})
                result["after_key"] = {"family": family}
            return httpx.Response(200, json={"timed_out": False, "_shards": {"failed": 0},
                                            "hits": {"total": {"relation": "eq", "value": sum(
                                                value["present"] + value["missing"]
                                                for value in self.coverage.values()
                                            )}},
                                            "aggregations": {"families": result}})
        return httpx.Response(200, json={})


def _configure(monkeypatch, tmp_path, branch):
    current = _coverage()
    prior = {"memprocfs": copy.deepcopy(current["memprocfs"])}
    case = tmp_path / "CASE-COVERAGE"
    analysis = case / "analysis"
    analysis.mkdir(parents=True)
    (analysis / "es_index.json").write_text(json.dumps({"ts_coverage": prior}), encoding="utf-8")
    total = sum(item["present"] + item["missing"] for item in current.values())
    previous = {"docs": total, "file_mtimes": {"ingest/artifacts.jsonl": 1},
                "file_sha256s": {"ingest/artifacts.jsonl": "old"}}
    if branch != "full":
        (analysis / "index_state.json").write_text(json.dumps(previous), encoding="utf-8")
    mtimes = {} if branch == "purge_refused" else {"ingest/artifacts.jsonl": 2}
    if branch == "unchanged":
        mtimes = previous["file_mtimes"]
    monkeypatch.setattr(case_index, "ensure_index", lambda _: "nexus-case-coverage")
    monkeypatch.setattr(case_index, "_index_file_mtimes", lambda *_: mtimes)
    monkeypatch.setattr(case_index, "_index_file_digests", lambda *_: {
        "ingest/artifacts.jsonl": "old" if branch == "unchanged" else "new"
    })
    monkeypatch.setattr(case_index, "_source_extractions_text", lambda *_: "")

    def scan(*args, stats, **kwargs):
        # A changed-files scan is partial; it cannot replace current index totals.
        stats.update(ts_coverage=prior, file_counts={})
        return iter(())

    monkeypatch.setattr(case_index, "iter_index_doc_batches", scan)
    transport = CoverageTransport(current)

    @contextmanager
    def client():
        with httpx.Client(base_url="http://index.test", transport=httpx.MockTransport(transport)) as value:
            yield value

    monkeypatch.setattr(case_index, "_client", client)
    return case, current, transport


@pytest.mark.parametrize("branch", ["incremental", "unchanged", "full", "purge_refused"])
def test_index_report_and_existing_case_facts_use_current_complete_counts(monkeypatch, tmp_path, branch):
    case, expected, transport = _configure(monkeypatch, tmp_path, branch)
    meta = case_index.index_case(case, incremental=branch != "full")
    assert meta["ts_coverage"] == expected
    assert case_digest._ts_coverage(case) == expected
    assert case_digest._ts_coverage_lines({"ts_coverage": meta["ts_coverage"]}) == (
        case_digest._ts_coverage_lines({"ts_coverage": expected})
    )
    assert meta["purge_refused"] == (branch == "purge_refused")
    requests = [json.loads(request.content) for request in transport.requests
                if request.url.path.endswith("/_search") and "families" in json.loads(request.content).get("aggs", {})]
    assert len(requests) == len(expected) + 1


def test_current_coverage_can_be_empty_without_reusing_old_families():
    transport = CoverageTransport({})
    with httpx.Client(base_url="http://index.test", transport=httpx.MockTransport(transport)) as client:
        assert case_index.indexed_timestamp_coverage(client, "nexus-case-coverage", "CASE-COVERAGE") == {}


@pytest.mark.parametrize("failure", [
    httpx.Response(503, json={}),
    httpx.Response(200, json={"timed_out": True}),
    httpx.Response(200, json={"_shards": {"failed": 1}}),
    httpx.Response(200, json={}),
    httpx.Response(200, json={"hits": {"total": {"relation": "gte", "value": 10000}}}),
    httpx.Response(200, json={"hits": {"total": {"relation": "eq", "value": 1}},
                            "aggregations": {"families": {"buckets": []}}}),
])
def test_failed_or_partial_census_is_not_reported_as_current(failure):
    transport = CoverageTransport(_coverage())
    transport.failure = failure
    with (
        httpx.Client(base_url="http://index.test", transport=httpx.MockTransport(transport)) as client,
        pytest.raises((RuntimeError, KeyError)),
    ):
        case_index.indexed_timestamp_coverage(client, "nexus-case-coverage", "CASE-COVERAGE")
