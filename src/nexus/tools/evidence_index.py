"""MCP evidence/index tools — WP 9.10 (Mode 2/3 backbone, evidence plane).

The LLM (and any MCP client) reaches a case's evidence ONLY through these
tools: per-case N4 queries over the ES index (or the CSV pack), bounded
aggregations over the result set, and the index/vocabulary description.

**Case gating is absolute** (operator directive 2026-09-14): an empty
``case_id`` resolves to the active case; an explicit ``case_id`` must MATCH
the active case — any other id is refused, so an agent can never touch a
different case's evidence. ``validate_case_id`` blocks traversal.

Aggregation results are CONTEXT, never evidence (FD-001): a finding still
requires audit_id-backed hits. Every call is audit-logged; responses carry
the ``audit_id``.
"""
from __future__ import annotations

import contextlib
import logging
import re
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter
from nexus.discipline import validate_case_id

logger = logging.getLogger(__name__)

_MAX_TEXT = 600
_MAX_FIELDS = 24
_MAX_FIELD_VALUE = 300
_MAX_AGG_HITS = 2000
_MAX_TOP = 25

_TS_KEYS = ("TimeCreated", "Timestamp", "EventTime", "LastRun", "LastVisitTime", "ts")
_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ](\d{2})?")


def _resolve_active_case(case_id: str) -> tuple[Path | None, str]:
    """Active case only — the strictest reading of the operator's gating.

    Returns ``(case_dir, error)``; exactly one is falsy.
    """
    if case_id:
        problem = validate_case_id(case_id)
        if problem:
            return None, problem
    from nexus.case_manager import CaseManager

    manager = CaseManager()
    active = None
    try:
        active = manager.require_active_case()
    except Exception as exc:  # noqa: BLE001 — no active case is a clean error
        return None, f"no active case: {exc}"
    if case_id:
        active_id = Path(active).name
        if case_id != active_id:
            return None, (
                f"case_id {case_id!r} is not the active case ({active_id!r}) — "
                "agents are gated to the active case's evidence only"
            )
    return Path(active), ""


def _trim_hit(hit: dict[str, Any]) -> dict[str, Any]:
    fields = hit.get("fields")
    fields_out: dict[str, str] = {}
    if isinstance(fields, dict):
        for k in list(fields)[:_MAX_FIELDS]:
            fields_out[str(k)] = str(fields.get(k) or "")[:_MAX_FIELD_VALUE]
    return {
        "family": str(hit.get("family") or ""),
        "file": str(hit.get("file") or ""),
        "line": str(hit.get("line") or ""),
        "host": str(hit.get("host") or ""),
        "terms": str(hit.get("terms") or "")[:200],
        "text": str(hit.get("text") or "")[:_MAX_TEXT],
        "fields": fields_out,
    }


def _field_values(hits: list[dict[str, Any]], field: str) -> list[str]:
    """Values of `field` across hits — attached parsed columns first
    (case-insensitive), then the row-level host for the `host` alias."""
    low = field.strip().lower()
    out: list[str] = []
    for h in hits:
        fields = h.get("fields") or {}
        matched = False
        if isinstance(fields, dict):
            for k, v in fields.items():
                if str(k).lower() == low:
                    val = str(v or "").strip()
                    if val:
                        out.append(val[:_MAX_FIELD_VALUE])
                    matched = True
                    break
        if not matched and low == "host" and h.get("host"):
            out.append(str(h["host"]))
    return out


def _time_buckets(hits: list[dict[str, Any]], granularity: str) -> dict[str, int]:
    """Day/hour buckets from the common timestamp fields (bounded, honest)."""
    buckets: dict[str, int] = {}
    for h in hits:
        fields = h.get("fields") or {}
        stamp = ""
        if isinstance(fields, dict):
            for k in _TS_KEYS:
                if fields.get(k):
                    stamp = str(fields[k])
                    break
        if not stamp and h.get("ts"):
            stamp = str(h["ts"])
        m = _TS_RE.search(stamp or "")
        if not m:
            continue
        day = stamp[m.start():m.start() + 10]
        key = day
        if granularity == "hour" and m.group(1):
            key = f"{day}T{m.group(1)}:00"
        buckets[key] = buckets.get(key, 0) + 1
    return dict(sorted(buckets.items())[:_MAX_TOP])


def register_tools(server: FastMCP, audit: AuditWriter):
    @server.tool()
    def n4_query(case_id: str = "", dsl: str = "", limit: int = 80) -> dict:
        """Run an N4 DSL query against the ACTIVE case's evidence index.

        The LLM is gated to the active case: an explicit case_id must match
        it. `dsl` uses the N4 grammar (fields family/host/user/event/file,
        AND/OR/NOT, quoted phrases, regex:) — see the DSL few-shot pack.
        Evidence plane: ES when configured, deterministic CSV pack otherwise.
        Findings need these rows' audit_ids (FD-001).
        """
        started = time.monotonic()
        case_dir, err = _resolve_active_case(case_id)
        if err or case_dir is None:
            return {"error": err or "no active case"}
        from nexus.langgraph.query_pack import attach_hit_fields
        from nexus.langgraph.query_pack import n4_query as _n4_query

        result = _n4_query(case_dir, dsl, limit=max(1, min(int(limit), 400)))
        if result.get("error"):
            return {**result, "case_id": Path(case_dir).name}
        hits = [h for h in (result.get("hits") or []) if isinstance(h, dict)]
        with contextlib.suppress(Exception):
            hits = attach_hit_fields(case_dir, hits)  # fields are best-effort enrichment
        trimmed = [_trim_hit(h) for h in hits[: max(1, min(int(limit), 400))]]
        aid = audit.log(
            tool="n4_query",
            params={"case_id": Path(case_dir).name, "dsl": dsl[:200], "limit": limit},
            result_summary={"count": result.get("count"), "backend": result.get("backend")},
            elapsed_ms=round((time.monotonic() - started) * 1000, 1),
        )
        return {
            "case_id": Path(case_dir).name,
            "query": dsl,
            "count": result.get("count"),
            "backend": result.get("backend"),
            "hits": trimmed,
            "provenance": {"audit_id": aid, "case_id": Path(case_dir).name},
        }

    @server.tool()
    def n4_aggregate(
        case_id: str = "",
        dsl: str = "",
        field: str = "host",
        top: int = 20,
        bucket: str = "",
    ) -> dict:
        """Aggregate the active case's evidence rows (context — never evidence).

        Counts distinct values of `field` (a parsed column, or `host`) across
        the query's result set; optional `bucket` = "day"|"hour" groups by
        timestamp. Grounded: counts come from the same N4 result stream the
        examiner sees (ES backend or CSV pack).
        """
        started = time.monotonic()
        case_dir, err = _resolve_active_case(case_id)
        if err or case_dir is None:
            return {"error": err or "no active case"}
        from nexus.langgraph.query_pack import attach_hit_fields
        from nexus.langgraph.query_pack import n4_query as _n4_query

        result = _n4_query(case_dir, dsl, limit=_MAX_AGG_HITS)
        if result.get("error"):
            return {**result, "case_id": Path(case_dir).name}
        hits = [h for h in (result.get("hits") or []) if isinstance(h, dict)]
        with contextlib.suppress(Exception):
            hits = attach_hit_fields(case_dir, hits)
        values = _field_values(hits, field)
        counts: dict[str, int] = {}
        for v in values:
            counts[v] = counts.get(v, 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[: max(1, min(int(top), 100))]
        buckets = _time_buckets(hits, bucket) if bucket in ("day", "hour") else None
        aid = audit.log(
            tool="n4_aggregate",
            params={"case_id": Path(case_dir).name, "dsl": dsl[:200], "field": field,
                    "bucket": bucket},
            result_summary={"distinct": len(counts), "rows": len(hits)},
            elapsed_ms=round((time.monotonic() - started) * 1000, 1),
        )
        return {
            "case_id": Path(case_dir).name,
            "field": field,
            "rows_scanned": len(hits),
            "values_seen": len(values),
            "distinct": len(counts),
            "top": [{"value": v, "count": c} for v, c in ranked],
            "buckets": buckets,
            "backend": result.get("backend"),
            "note": "aggregations are investigation context — never evidence (FD-001)",
            "provenance": {"audit_id": aid, "case_id": Path(case_dir).name},
        }

    @server.tool()
    def index_mappings(case_id: str = "") -> dict:
        """Describe the active case's index: backend, families, N4 DSL fields.

        Grounds the LLM against hallucinated families/fields — the vocabulary
        it may query is what this case actually holds.
        """
        started = time.monotonic()
        case_dir, err = _resolve_active_case(case_id)
        if err or case_dir is None:
            return {"error": err or "no active case"}
        from nexus.langgraph.briefing import _family_inventory
        from nexus.langgraph.case_index import es_available, index_name

        inventory = _family_inventory(case_dir)
        aid = audit.log(
            tool="index_mappings",
            params={"case_id": Path(case_dir).name},
            result_summary={"families": len(inventory), "es": es_available()},
            elapsed_ms=round((time.monotonic() - started) * 1000, 1),
        )
        return {
            "case_id": Path(case_dir).name,
            "es_available": es_available(),
            "index_name": index_name(Path(case_dir).name),
            "families": sorted(inventory),
            "family_rows": {k: v.get("rows", 0) for k, v in sorted(inventory.items())},
            "dsl_fields": ["family", "host", "user", "event", "file"],
            "note": ("evidence index reachable" if es_available()
                     else "ES not reachable — deterministic CSV pack backend"),
            "provenance": {"audit_id": aid, "case_id": Path(case_dir).name},
        }
