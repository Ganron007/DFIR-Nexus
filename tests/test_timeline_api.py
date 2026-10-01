"""A10: the timeline query API.

The properties under test are the ones an examiner would be misled by if they
broke: a page that skips rows, a cursor that pages the wrong case, a total read
as exact when it was capped, and - worst - an unreachable Elasticsearch
answering "no activity".
"""
from __future__ import annotations

import json

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.dashboard.timeline_api import (
    TimelineStore,
    TimelineUnavailable,
    _filters,
    decode_cursor,
    encode_cursor,
    timeline_api_routes,
)

# --------------------------------------------------------------------------
# a fake Elasticsearch that records what it was asked
# --------------------------------------------------------------------------

class _Resp:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self._payload = payload
        self.status_code = status

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")


def _hit(row: dict) -> dict:
    return {"_source": row}


def _page_response(rows: list[dict], total: int = 0, exact: bool = True) -> dict:
    return {
        "hits": {
            "total": {"value": total, "relation": "eq" if exact else "gte"},
            "hits": [_hit(r) for r in rows],
        }
    }


def _event(event_id: str, ts: str, **over) -> dict:
    row = {
        "event_id": event_id,
        "ts": ts,
        "ts_desc": "Created0x10",
        "ts_src": "column",
        "family": "mftecmd",
        "host": "WS01",
        "user": "bob",
        "artifact": "mftecmd.csv",
        "source_file": "mft/mftecmd.csv",
        "source_line": 42,
        "audit_id": "nx-1",
        "finding_ids": ["F-abc"],
    }
    row.update(over)
    return row


class FakeES:
    """Answers the aggregations the store asks for and records every body."""

    def __init__(self, rows: list[dict] | None = None, total: int | None = None,
                 exact: bool = True) -> None:
        self.rows = rows if rows is not None else []
        self.total = len(self.rows) if total is None else total
        self.exact = exact
        self.requests: list[dict] = []
        self.paths: list[str] = []

    def post(self, path: str, json: dict | None = None) -> _Resp:  # noqa: A002 - httpx API
        body = json or {}
        self.paths.append(path)
        self.requests.append(body)

        aggs = body.get("aggs")
        if aggs:
            names = set(aggs)
            if names == {"timeline"}:
                return _Resp({
                    "aggregations": {
                        "timeline": {
                            "buckets": [
                                {"key_as_string": "2026-09-29T13:00:00Z", "doc_count": 4},
                                {"key_as_string": "2026-09-29T14:00:00Z", "doc_count": 9},
                            ]
                        }
                    }
                })
            return _Resp({
                "aggregations": {
                    field: {"buckets": [{"key": "mftecmd", "doc_count": 4}]}
                    for field in names
                }
            })

        # a term lookup (anchor / findings)
        if "term" in str(body.get("query")):
            match = next(
                (r for r in self.rows if r.get("event_id") == body["query"]["term"]["event_id"]),
                None,
            )
            return _Resp({"hits": {"hits": [_hit(match)] if match else []}})

        search_after = body.get("search_after")
        rows = self.rows
        # an honest fake applies the filters it is handed, so a range window
        # actually narrows the result the way Elasticsearch would
        for clause in (body.get("query", {}).get("bool", {}).get("filter") or []):
            if "range" in clause:
                field, bounds = next(iter(clause["range"].items()))
                lo = str(bounds.get("gte") or "")
                hi = str(bounds.get("lte") or "")
                rows = [
                    r for r in rows
                    if (not lo or str(r.get(field, "")) >= lo)
                    and (not hi or str(r.get(field, "")) <= hi)
                ]
        if search_after:
            after_id = search_after[1] if len(search_after) > 1 else search_after[0]
            ids = [r.get("event_id") for r in rows]
            if after_id in ids:
                rows = rows[ids.index(after_id) + 1:]
        size = int(body.get("size") or 10)
        return _Resp(_page_response(rows[:size], self.total, self.exact))

    def __enter__(self) -> FakeES:
        return self

    def __exit__(self, *_exc) -> None:
        return None


class DeadES:
    """ES is not there at all."""

    def post(self, *_a, **_kw):
        raise ConnectionError("connection refused")

    def __enter__(self) -> DeadES:
        return self

    def __exit__(self, *_exc) -> None:
        return None


@pytest.fixture
def es(monkeypatch):
    """Install a fake ES and hand back its factory + what it recorded."""
    import nexus.langgraph.case_index as ci

    def install(fake: FakeES | DeadES) -> FakeES | DeadES:
        monkeypatch.setattr(ci, "_client", lambda: fake)
        return fake

    return install


@pytest.fixture
def client():
    app = Starlette(routes=list(timeline_api_routes()))
    return TestClient(app)


# --------------------------------------------------------------------------
# cursors
# --------------------------------------------------------------------------

def test_cursor_round_trips_and_is_case_bound():
    values = ["2026-09-29T13:04:07.123Z", "abc123"]
    cursor = encode_cursor("CASE-A", values)
    assert decode_cursor("CASE-A", cursor) == values
    # a cursor from one case is REFUSED by another, not honoured
    with pytest.raises(ValueError, match="different case"):
        decode_cursor("CASE-B", cursor)


def test_a_corrupt_cursor_is_a_400_not_a_500():
    with pytest.raises(ValueError, match="not readable"):
        decode_cursor("CASE-A", "!!!not-base64!!!")


# --------------------------------------------------------------------------
# paging
# --------------------------------------------------------------------------

def test_paging_uses_search_after_not_from(es):
    rows = [_event("e1", "2026-09-29T13:00:00Z"), _event("e2", "2026-09-29T14:00:00Z")]
    fake = es(FakeES(rows))
    store = TimelineStore("CASE-A")

    first = store.paged(size=1)
    assert first["rows"][0]["event_id"] == "e1"
    assert first["next_cursor"], "a full page must offer a cursor"
    assert first["exact"] is True

    second = store.paged(size=1, cursor=first["next_cursor"])
    assert second["rows"][0]["event_id"] == "e2", "the cursor must not skip e2"

    # the tie-breaker sort is what makes it stable - assert the body
    sort_fields = [next(iter(s)) for s in fake.requests[-1]["sort"]]
    assert sort_fields == ["ts", "event_id"]
    assert fake.requests[-1]["search_after"][1] == "e1"
    assert "from" not in fake.requests[-1], "from/size paging skips while writing"


def test_a_partial_page_offers_no_cursor(es):
    es(FakeES([_event("e1", "2026-09-29T13:00:00Z")]))
    page = TimelineStore("CASE-A").paged(size=200)
    assert page["next_cursor"] is None


def test_a_capped_total_says_so(es):
    """An examiner must never read 10000 as the number of events."""
    es(FakeES([_event("e1", "2026-09-29T13:00:00Z")], total=10000, exact=False))
    page = TimelineStore("CASE-A").paged()
    assert page["capped"] is True
    assert page["exact"] is False
    assert page["total"] == 10000


def test_page_size_is_bounded(es):
    fake = es(FakeES([]))
    TimelineStore("CASE-A").paged(size=10**9)
    assert int(fake.requests[-1]["size"]) == 1000


def test_the_query_is_case_scoped_by_index(es):
    from nexus.langgraph.timeline_events import events_index_name

    fake = es(FakeES([]))
    TimelineStore("CASE-ZZZ").paged()
    # one index per case: another case's query can never read these events
    assert fake.paths[-1] == f"/{events_index_name('CASE-ZZZ')}/_search"
    assert "zzz" in fake.paths[-1]


# --------------------------------------------------------------------------
# facets / histogram
# --------------------------------------------------------------------------

def test_facets_report_bucket_counts(es):
    es(FakeES([]))
    out = TimelineStore("CASE-A").facets()
    assert out["facets"]["family"] == [{"value": "mftecmd", "count": 4}]
    assert out["backend"] == "es"


def test_histogram_returns_buckets_over_the_range(es):
    fake = es(FakeES([]))
    out = TimelineStore("CASE-A").histogram(start="2026-09-29T00:00:00Z", interval="1h")
    agg = fake.requests[-1]["aggs"]["timeline"]["date_histogram"]
    assert agg["fixed_interval"] == "1h"
    assert agg["extended_bounds"]["gte"] == "2026-09-29T00:00:00Z"
    assert [b["count"] for b in out["buckets"]] == [4, 9]


# --------------------------------------------------------------------------
# context
# --------------------------------------------------------------------------

def test_context_is_a_window_around_the_anchor_across_families(es):
    rows = [
        _event("anchor", "2026-09-29T13:00:00Z"),
        _event("near", "2026-09-29T13:02:00Z", family="evtx"),
        _event("far", "2026-09-29T18:00:00Z"),
    ]
    fake = es(FakeES(rows))
    out = TimelineStore("CASE-A").context("anchor", seconds=300)

    assert out["anchor"]["event_id"] == "anchor"
    window = fake.requests[-1]["query"]["bool"]["filter"][0]["range"]["ts"]
    assert window["lte"].startswith("2026-09-29T13:05")
    assert window["gte"].startswith("2026-09-29T12:55")
    assert [r["event_id"] for r in out["rows"]] == ["anchor", "near"]
    assert out["capped"] is False


def test_context_for_an_unknown_event_is_empty_not_an_error(es):
    es(FakeES([_event("other", "2026-09-29T13:00:00Z")]))
    out = TimelineStore("CASE-A").context("nope")
    assert out["anchor"] is None
    assert out["rows"] == []


# --------------------------------------------------------------------------
# honest degradation
# --------------------------------------------------------------------------

def test_a_down_backend_raises_rather_than_returning_nothing(es):
    es(DeadES())
    with pytest.raises(TimelineUnavailable):
        TimelineStore("CASE-A").paged()


def test_the_endpoint_says_unavailable_instead_of_empty(es, client):
    es(DeadES())
    resp = client.get("/portal/api/timeline/events", params={"case_id": "CASE-A"})
    assert resp.status_code == 503
    body = resp.json()
    assert body["backend"] == "unavailable"
    assert "requires Elasticsearch" in body["error"]
    assert "fallback_reason" in body
    assert "rows" not in body, "an empty list would read as 'no activity'"


def test_a_missing_events_index_is_unavailable_not_empty(es, client):
    class Gone(FakeES):
        def post(self, path, json=None):
            return _Resp({"error": "index_not_found_exception"}, status=404)

    es(Gone([]))
    resp = client.get("/portal/api/timeline/events", params={"case_id": "CASE-A"})
    assert resp.status_code == 503
    assert "missing" in resp.json()["fallback_reason"]


def test_case_id_is_required(client):
    assert client.get("/portal/api/timeline/events").status_code == 400
    assert client.get("/portal/api/timeline/events/facets").status_code == 400


def test_a_foreign_cursor_is_a_400_at_the_endpoint(es, client):
    es(FakeES([]))
    cursor = encode_cursor("CASE-OTHER", ["2026-01-01T00:00:00Z", "e1"])
    resp = client.get(
        "/portal/api/timeline/events",
        params={"case_id": "CASE-A", "cursor": cursor},
    )
    assert resp.status_code == 400
    assert "different case" in resp.json()["error"]


# --------------------------------------------------------------------------
# the served endpoints
# --------------------------------------------------------------------------

def test_events_endpoint_serves_paged_rows(es, client):
    es(FakeES([_event("e1", "2026-09-29T13:00:00Z")], total=1))
    resp = client.get("/portal/api/timeline/events", params={"case_id": "CASE-A"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["rows"][0]["event_id"] == "e1"
    assert body["total"] == 1 and body["exact"] is True


def test_events_endpoint_speaks_the_status_shape(es, client):
    es(FakeES([_event("e1", "2026-09-29T13:00:00Z")]))
    body = client.get(
        "/portal/api/timeline/events", params={"case_id": "CASE-A"}
    ).json()
    assert {"backend", "index", "rows", "next_cursor", "total", "exact", "capped"} <= set(body)


def test_facets_endpoint(es, client):
    es(FakeES([]))
    body = client.get(
        "/portal/api/timeline/events/facets", params={"case_id": "CASE-A"}
    ).json()
    assert body["facets"]["user"] == [{"value": "mftecmd", "count": 4}]


def test_histogram_endpoint(es, client):
    es(FakeES([]))
    body = client.get(
        "/portal/api/timeline/events/histogram",
        params={"case_id": "CASE-A", "interval": "1h"},
    ).json()
    assert body["buckets"][0]["ts"] == "2026-09-29T13:00:00Z"


def test_context_endpoint(es, client):
    es(FakeES([_event("e1", "2026-09-29T13:00:00Z")]))
    body = client.get(
        "/portal/api/timeline/events/e1/context",
        params={"case_id": "CASE-A", "seconds": 60},
    ).json()
    assert body["anchor"]["event_id"] == "e1"
    assert body["seconds"] == 60


def test_findings_endpoint_links_an_event_to_its_findings(es, client):
    es(FakeES([_event("e1", "2026-09-29T13:00:00Z")]))
    body = client.get(
        "/portal/api/timeline/events/e1/findings", params={"case_id": "CASE-A"}
    ).json()
    assert body["finding_ids"] == ["F-abc"]


def test_export_streams_the_same_rows_as_csv(es, client):
    rows = [_event("e1", "2026-09-29T13:00:00Z"), _event("e2", "2026-09-29T14:00:00Z")]
    es(FakeES(rows, total=2))
    resp = client.get(
        "/portal/api/timeline/events/export", params={"case_id": "CASE-A"}
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    lines = [line for line in resp.text.splitlines() if line.strip()]
    assert lines[0].startswith("event_id,ts,ts_desc")
    assert len(lines) == 3, "header + both events"
    assert "e1" in lines[1] and "e2" in lines[2]


# --------------------------------------------------------------------------
# the filter builder
# --------------------------------------------------------------------------

def test_filters_become_the_right_clauses():
    out = _filters({
        "family": "evtx",
        "host": ["WS01", "WS02"],
        "user": {"terms": ["bob", "alice"]},
        "ts": {"gte": "2026-01-01T00:00:00Z"},
    })
    kinds = [next(iter(c)) for c in out]
    assert kinds == ["term", "terms", "terms", "range"]
    assert out[3]["range"]["ts"]["gte"] == "2026-01-01T00:00:00Z"


def test_empty_filters_are_dropped_not_sent():
    assert _filters({"family": "", "host": [], "ts": {}}) == []
    assert _filters(None) == []


def test_filters_survive_the_json_query_parameter(es, client):
    fake = es(FakeES([]))
    client.get(
        "/portal/api/timeline/events",
        params={"case_id": "CASE-A", "filters": json.dumps({"family": "evtx"})},
    )
    assert fake.requests[-1]["query"]["bool"]["filter"] == [{"term": {"family": "evtx"}}]


def test_unreadable_filters_are_ignored_not_fatal(es, client):
    """A broken query parameter must not take the timeline down."""
    fake = es(FakeES([]))
    resp = client.get(
        "/portal/api/timeline/events",
        params={"case_id": "CASE-A", "filters": "{not json"},
    )
    assert resp.status_code == 200
    assert fake.requests[-1]["query"]["bool"]["filter"] == []

# --------------------------------------------------------------------------
# the build endpoint
# --------------------------------------------------------------------------

def test_build_route_refuses_a_traversing_case_id(client):
    resp = client.post(
        "/portal/api/timeline/events/build", params={"case_id": "../secrets"}
    )
    assert resp.status_code == 400
    assert "invalid case id" in resp.json()["error"]


def test_build_route_404s_an_unknown_case(client):
    resp = client.post(
        "/portal/api/timeline/events/build", params={"case_id": "CASE-NOPE00"}
    )
    assert resp.status_code == 404


def test_build_route_requires_a_case_id(client):
    assert client.post("/portal/api/timeline/events/build").status_code == 400


def test_build_route_reports_a_down_backend_instead_of_a_fake_build(
    client, monkeypatch
):
    import nexus.langgraph.timeline_events as te

    monkeypatch.setattr(
        te, "build_events",
        lambda case_dir, force=False: {
            "case_id": case_dir.name, "built": False,
            "reason": "elasticsearch unavailable: connection refused",
            "error": "elasticsearch unavailable: connection refused",
        },
    )
    # a real case dir so the 404 path is not what we are measuring
    from nexus.config import settings
    case_dir = settings.cases_root / "CASE-A"
    case_dir.mkdir(parents=True, exist_ok=True)
    try:
        body = client.post(
            "/portal/api/timeline/events/build", params={"case_id": "CASE-A"}
        ).json()
        assert body["built"] is False
        assert "unavailable" in body["reason"]
    finally:
        import shutil
        shutil.rmtree(case_dir, ignore_errors=True)
