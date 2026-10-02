"""Timeline query API (WO-A10 / T1-4, WPs 8.5 / 10.5 / 10.6).

One module behind every timeline read, so a paged grid, a histogram and a
context window can never disagree about what an event is or when it happened.

The contract, in the order the questions get asked:

``paged``   ``search_after`` on ``(ts, event_id)`` - never ``from``/``size``,
            which silently skips and duplicates while the index is being
            written to.
``facets``  ``terms`` aggregations for the filter panel.
``histogram`` ``date_histogram`` over the range, UTC-aligned buckets.
``context`` everything within +/-N seconds of one event, across families.
``export``  a stream of the same rows the grid shows.

Every response carries ``backend``, and where a count could be capped it says
so: an examiner must never read a capped number as a total.
"""
from __future__ import annotations

import base64
import binascii
import json
import logging
from datetime import datetime, timedelta
from typing import Any

from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

log = logging.getLogger(__name__)

DEFAULT_PAGE = 200
MAX_PAGE = 1000
FACET_FIELDS = ("family", "host", "user", "event_type", "ts_desc")


class TimelineUnavailable(RuntimeError):
    """ES is not reachable - the caller must SAY so, not return an empty list."""


# --------------------------------------------------------------------------
# cursors
# --------------------------------------------------------------------------

def encode_cursor(case_id: str, values: list[Any]) -> str:
    """An opaque, case-bound cursor.

    Case-bound on purpose: a cursor from one case replayed against another
    would page through the wrong investigation. It is refused, not honoured.
    """
    raw = json.dumps({"case": case_id, "v": values}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def decode_cursor(case_id: str, cursor: str) -> list[Any]:
    try:
        payload = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise ValueError(f"cursor is not readable: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("case") != case_id:
        raise ValueError("cursor belongs to a different case")
    values = payload.get("v")
    if not isinstance(values, list):
        raise ValueError("cursor carries no sort values")
    return values


# --------------------------------------------------------------------------
# the store
# --------------------------------------------------------------------------

class TimelineStore:
    """Every timeline read, one place. Read-only against the events index."""

    def __init__(self, case_id: str) -> None:
        self.case_id = case_id

    @property
    def index(self) -> str:
        from nexus.langgraph.timeline_events import events_index_name

        return events_index_name(self.case_id)

    def _client(self):
        from nexus.langgraph.case_index import _client

        return _client()

    def _search(self, body: dict[str, Any]) -> dict[str, Any]:
        try:
            with self._client() as client:
                response = client.post(f"/{self.index}/_search", json=body)
        except Exception as exc:  # noqa: BLE001 - the caller turns this into 503
            raise TimelineUnavailable(str(exc)[:200]) from exc
        if response.status_code == 404:
            raise TimelineUnavailable(f"events index missing for {self.case_id}")
        if response.status_code >= 400:
            raise TimelineUnavailable(
                f"elasticsearch refused the query: {response.status_code}"
            )
        try:
            return response.json()
        except Exception as exc:  # noqa: BLE001
            raise TimelineUnavailable(f"unreadable search response: {exc}") from exc

    # -- paged -----------------------------------------------------------
    def paged(
        self,
        *,
        cursor: str | None = None,
        size: int = DEFAULT_PAGE,
        filters: dict[str, Any] | None = None,
        sort_by: str = "ts",
        sort_dir: str = "asc",
    ) -> dict[str, Any]:
        size = max(1, min(MAX_PAGE, int(size or DEFAULT_PAGE)))
        query: dict[str, Any] = {"bool": {"filter": _filters(filters)}}
        body: dict[str, Any] = {
            "size": size,
            "query": query,
            "sort": [
                {sort_by: {"order": sort_dir, "unmapped_type": "keyword"}},
                # the tie-breaker is what makes search_after stable
                {"event_id": {"order": "asc"}},
            ],
        }
        if cursor:
            body["search_after"] = decode_cursor(self.case_id, cursor)
        payload = self._search(body)

        hits = (payload.get("hits") or {})
        rows = [h.get("_source") or {} for h in hits.get("hits") or []]
        total = hits.get("total")
        total_value = total.get("value") if isinstance(total, dict) else total
        # ES reports "gte" when the count stopped at 10000: the number is a
        # floor, and saying otherwise would read as an exact total.
        exact = not isinstance(total, dict) or total.get("relation") != "gte"
        next_cursor = None
        if rows and len(rows) == size:
            last = rows[-1]
            next_cursor = encode_cursor(
                self.case_id, [last.get(sort_by), last.get("event_id")]
            )
        return {
            "backend": "es",
            "index": self.index,
            "rows": rows,
            "next_cursor": next_cursor,
            "total": total_value if isinstance(total_value, int) else None,
            "exact": exact,
            "capped": bool(total_value == 10000),
        }

    # -- facets ----------------------------------------------------------
    def facets(self, filters: dict[str, Any] | None = None) -> dict[str, Any]:
        aggs = {
            field: {"terms": {"field": field, "size": 50}}
            for field in FACET_FIELDS
        }
        payload = self._search({
            "size": 0,
            "query": {"bool": {"filter": _filters(filters)}},
            "aggs": aggs,
        })
        out: dict[str, list[dict[str, Any]]] = {}
        for field, bucket in (payload.get("aggregations") or {}).items():
            out[field] = [
                {"value": b.get("key"), "count": b.get("doc_count")}
                for b in (bucket.get("buckets") or [])
            ]
        return {"backend": "es", "facets": out}

    # -- histogram -------------------------------------------------------
    def histogram(
        self,
        *,
        start: str | None = None,
        end: str | None = None,
        buckets: int = 500,
        interval: str | None = None,
        filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        rng: dict[str, Any] = {}
        if start:
            rng["gte"] = start
        if end:
            rng["lte"] = end
        agg: dict[str, Any] = {
            "date_histogram": {
                "field": "ts",
                "calendar_interval": interval or "auto",
                "min_doc_count": 0,
            }
        }
        if interval:
            agg["date_histogram"].pop("calendar_interval", None)
            agg["date_histogram"]["fixed_interval"] = interval
            # bucket_count is a hint that only exists alongside an explicit
            # interval; ES rejects "auto" + bucket_count, and the previous
            # draft sent both on every windowed call.
            agg["date_histogram"]["bucket_count"] = max(1, min(2000, int(buckets or 500)))
        if rng:
            agg["date_histogram"]["extended_bounds"] = rng
        payload = self._search({
            "size": 0,
            "query": {"bool": {"filter": _filters(filters)}},
            "aggs": {"timeline": agg},
        })
        result = (payload.get("aggregations") or {}).get("timeline") or {}
        return {
            "backend": "es",
            "buckets": [
                {"ts": b.get("key_as_string") or b.get("key"), "count": b.get("doc_count")}
                for b in (result.get("buckets") or [])
            ],
        }

    # -- context ---------------------------------------------------------
    def context(self, event_id: str, *, seconds: int = 300) -> dict[str, Any]:
        """Everything within +/-N seconds of an event, across every family."""
        anchor = self._search({
            "size": 1,
            "query": {"term": {"event_id": event_id}},
        })
        hits = (anchor.get("hits") or {}).get("hits") or []
        if not hits:
            return {"backend": "es", "anchor": None, "rows": [], "seconds": seconds}
        source = hits[0].get("_source") or {}
        ts = str(source.get("ts") or "")
        try:
            centre = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return {"backend": "es", "anchor": source, "rows": [], "seconds": seconds}
        window = max(1, min(86_400, int(seconds or 300)))
        page = self.paged(
            size=MAX_PAGE,
            filters={
                "ts": {
                    "gte": (centre - timedelta(seconds=window)).isoformat(),
                    "lte": (centre + timedelta(seconds=window)).isoformat(),
                }
            },
        )
        return {
            "backend": "es",
            "anchor": source,
            "seconds": window,
            "rows": page["rows"],
            # The window is read in ONE page. If more events fall inside it than
            # fit, say so - a context window that silently truncates reads as
            # "nothing else happened near this event".
            "capped": bool(page.get("capped")) or (
                isinstance(page.get("total"), int) and page["total"] > len(page["rows"])
            ),
            "truncated": bool(
                isinstance(page.get("total"), int) and page["total"] > len(page["rows"])
            ),
            "total": page["total"],
        }

    # -- findings link ---------------------------------------------------
    def findings_for(self, event_id: str) -> dict[str, Any]:
        payload = self._search({
            "size": 1,
            "query": {"term": {"event_id": event_id}},
        })
        hits = (payload.get("hits") or {}).get("hits") or []
        source = hits[0].get("_source") if hits else None
        return {
            "backend": "es",
            "event_id": event_id,
            "finding_ids": (source or {}).get("finding_ids") or [],
        }

    # -- export ----------------------------------------------------------
    def export(self, *, filters: dict[str, Any] | None = None, limit: int = 100_000):
        """Stream rows as CSV. The same rows the grid shows, not a re-query."""
        import csv
        import io

        columns = [
            "event_id", "ts", "ts_desc", "ts_src", "family", "host", "user",
            "artifact", "source_file", "source_line", "audit_id",
        ]

        def _rows():
            buffer = io.StringIO()
            writer = csv.writer(buffer, lineterminator="\n")
            writer.writerow(columns)
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate(0)
            cursor = None
            written = 0
            while written < limit:
                page = self.paged(
                    cursor=cursor,
                    size=min(MAX_PAGE, limit - written),
                    filters=filters,
                )
                for row in page["rows"]:
                    if written >= limit:
                        break
                    writer.writerow([row.get(c, "") for c in columns])
                    written += 1
                    if written % MAX_PAGE == 0:
                        yield buffer.getvalue()
                        buffer.seek(0)
                        buffer.truncate(0)
                cursor = page.get("next_cursor")
                if written >= limit or not cursor or not page["rows"]:
                    break
            if buffer.tell():
                yield buffer.getvalue()

        return _rows()


def _filters(filters: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Turn the grid's filter object into ES clauses (term + range)."""
    out: list[dict[str, Any]] = []
    for field, value in (filters or {}).items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, dict):
            if {"gte", "lte", "gt", "lt"} & set(value):
                out.append({"range": {field: {k: v for k, v in value.items() if v}}})
            elif "terms" in value:
                out.append({"terms": {field: list(value["terms"])}})
            continue
        if isinstance(value, list):
            out.append({"terms": {field: [str(v) for v in value]}})
        else:
            out.append({"term": {field: value}})
    return out


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------

def _store(request) -> TimelineStore | JSONResponse:
    case_id = (request.query_params.get("case_id") or "").strip()
    if not case_id:
        return JSONResponse({"error": "case_id is required"}, status_code=400)
    return TimelineStore(case_id)


def _unavailable(exc: Exception, case_id: str) -> JSONResponse:
    """503 with a reason - never an empty list that reads as 'no activity'."""
    return JSONResponse(
        {
            "error": "timeline requires Elasticsearch",
            "fallback_reason": str(exc)[:200],
            "case_id": case_id,
            "backend": "unavailable",
        },
        status_code=503,
    )


def _json_filters(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _timed(call):
    store = _store(call)
    if isinstance(store, JSONResponse):
        return store
    try:
        return JSONResponse(store.paged(
            cursor=call.query_params.get("cursor") or None,
            size=int(call.query_params.get("size") or DEFAULT_PAGE),
            filters=_json_filters(call.query_params.get("filters")),
            sort_by=call.query_params.get("sort_by") or "ts",
            sort_dir=call.query_params.get("sort_dir") or "asc",
        ))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except TimelineUnavailable as exc:
        return _unavailable(exc, store.case_id)


async def api_timeline_events(request):
    """GET /portal/api/timeline/events?case_id=&cursor=&filters={}"""
    from starlette.concurrency import run_in_threadpool

    return await run_in_threadpool(_timed, request)


def _facets(call):
    store = _store(call)
    if isinstance(store, JSONResponse):
        return store
    try:
        return JSONResponse(store.facets(_json_filters(call.query_params.get("filters"))))
    except TimelineUnavailable as exc:
        return _unavailable(exc, store.case_id)


async def api_timeline_events_facets(request):
    """GET /portal/api/timeline/events/facets?case_id=&filters={}"""
    from starlette.concurrency import run_in_threadpool

    return await run_in_threadpool(_facets, request)


def _histogram(call):
    store = _store(call)
    if isinstance(store, JSONResponse):
        return store
    try:
        return JSONResponse(store.histogram(
            start=call.query_params.get("start") or None,
            end=call.query_params.get("end") or None,
            buckets=int(call.query_params.get("buckets") or 500),
            interval=call.query_params.get("interval") or None,
            filters=_json_filters(call.query_params.get("filters")),
        ))
    except TimelineUnavailable as exc:
        return _unavailable(exc, store.case_id)


async def api_timeline_events_histogram(request):
    """GET /portal/api/timeline/events/histogram?case_id=&interval=&buckets="""
    from starlette.concurrency import run_in_threadpool

    return await run_in_threadpool(_histogram, request)


def _context(call):
    store = _store(call)
    if isinstance(store, JSONResponse):
        return store
    event_id = (call.path_params.get("event_id") or call.query_params.get("event_id") or "").strip()
    if not event_id:
        return JSONResponse({"error": "event_id is required"}, status_code=400)
    try:
        return JSONResponse(store.context(
            event_id, seconds=int(call.query_params.get("seconds") or 300)
        ))
    except TimelineUnavailable as exc:
        return _unavailable(exc, store.case_id)


async def api_timeline_event_context(request):
    """GET /portal/api/timeline/events/{event_id}/context?case_id=&seconds=300"""
    from starlette.concurrency import run_in_threadpool

    return await run_in_threadpool(_context, request)


def _findings(call):
    store = _store(call)
    if isinstance(store, JSONResponse):
        return store
    event_id = (call.path_params.get("event_id") or "").strip()
    try:
        return JSONResponse(store.findings_for(event_id))
    except TimelineUnavailable as exc:
        return _unavailable(exc, store.case_id)


async def api_timeline_event_findings(request):
    """GET /portal/api/timeline/events/{event_id}/findings?case_id="""
    from starlette.concurrency import run_in_threadpool

    return await run_in_threadpool(_findings, request)


def _export(call):
    store = _store(call)
    if isinstance(store, JSONResponse):
        return store
    try:
        rows = store.export(filters=_json_filters(call.query_params.get("filters")))
    except TimelineUnavailable as exc:
        return _unavailable(exc, store.case_id)
    return StreamingResponse(
        rows,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="timeline-events.csv"'},
    )


async def api_timeline_events_export(request):
    """GET /portal/api/timeline/events/export?case_id=&filters={} (streamed CSV)"""
    from starlette.concurrency import run_in_threadpool

    return await run_in_threadpool(_export, request)


def _build(call):
    """Build the events index from the document index (never from evidence)."""
    case_id = (call.query_params.get("case_id") or "").strip()
    if not case_id:
        return JSONResponse({"error": "case_id is required"}, status_code=400)
    from nexus.config import settings
    from nexus.discipline import validate_case_id

    if validate_case_id(case_id):
        return JSONResponse({"error": f"invalid case id: {case_id}"}, status_code=400)
    case_dir = settings.cases_root / case_id
    if not case_dir.is_dir():
        return JSONResponse({"error": f"unknown case: {case_id}"}, status_code=404)

    from nexus.langgraph.timeline_events import build_events

    force = (call.query_params.get("force") or "").lower() in ("1", "true", "yes")
    try:
        return JSONResponse(build_events(case_dir, force=force))
    except Exception as exc:  # noqa: BLE001 - reported, never silently empty
        return JSONResponse(
            {"error": "timeline build failed", "fallback_reason": str(exc)[:200]},
            status_code=500,
        )


async def api_timeline_events_build(request):
    """POST /portal/api/timeline/events/build?case_id=&force=1

    Reads the document index only - evidence is never re-parsed (A3 §2).
    """
    from starlette.concurrency import run_in_threadpool

    return await run_in_threadpool(_build, request)


def timeline_api_routes() -> list[Route]:
    base = "/portal/api/timeline/events"
    return [
        Route(base, api_timeline_events, methods=["GET"]),
        Route(f"{base}/facets", api_timeline_events_facets, methods=["GET"]),
        Route(f"{base}/histogram", api_timeline_events_histogram, methods=["GET"]),
        Route(f"{base}/export", api_timeline_events_export, methods=["GET"]),
        Route(f"{base}/build", api_timeline_events_build, methods=["POST"]),
        Route(f"{base}/{{event_id}}/context", api_timeline_event_context, methods=["GET"]),
        Route(f"{base}/{{event_id}}/findings", api_timeline_event_findings, methods=["GET"]),
    ]