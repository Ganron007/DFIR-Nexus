"""MCP evidence/index tools — WP 9.10 (Mode 2/3 backbone, evidence plane).

The LLM (and any MCP client) reaches a case's evidence ONLY through these
tools: per-case N4 queries over the ES index (or the CSV pack), exhaustive
aggregations over the result set, and the index/vocabulary description.

**Case gating** (operator directive 2026-09-14, revised by WO-R2F item 1 / D41):
an external MCP caller that binds nothing is gated to the active case — an
explicit ``case_id`` must MATCH it, so an agent can never touch a different
case's evidence, and ``validate_case_id`` blocks traversal. An **in-process**
caller (the Mode 1/2/3 backbone and the context loop) passes its run's own
``case_dir``; that binding is validated against the configured ``cases_root``
and is used directly, so a run reads its own case even while the examiner has
activated another one. See ``_resolve_active_case``.

Aggregation results are CONTEXT, never evidence (FD-001): a finding still
requires audit_id-backed hits. Every call is audit-logged; responses carry
the ``audit_id``.
"""
from __future__ import annotations

import contextlib
import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter
from nexus.discipline import validate_case_id

logger = logging.getLogger(__name__)

_TS_KEYS = ("TimeCreated", "Timestamp", "EventTime", "LastRun", "LastVisitTime", "ts")
_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ](\d{2})?")


def _resolve_active_case(case_id: str, case_dir: Path | str | None = None) -> tuple[Path | None, str]:
    """Resolve the case a tool call is bound to.

    Two callers, two contracts:

    * **In-process (backbone / context loop / Mode 1-3)** — the caller passes
      the run's own ``case_dir`` (WO-R2F item 1, D41). The case is validated
      against the configured ``cases_root`` and returned directly. The global
      active-case pointer is NOT consulted, because a run must read its own
      case even when the examiner has since activated a different one (36c:
      every Mode 3 seat was refused with "case_id 'X' is not the active case
      ('Y')", none of the refusals were audited, and the run still settled).
      The caller may not choose the root: a ``case_dir`` outside ``cases_root``
      is refused, so a path cannot be smuggled in (third-eye R02).
    * **External MCP caller that binds nothing** — no ``case_dir`` is given,
      the active-case pointer is resolved and an explicit ``case_id`` must
      match it (operator directive 2026-09-14).

    Returns ``(case_dir, error)``; exactly one is falsy.
    """
    if case_dir is not None:
        # WO-R2F item 1 (D41): an explicit run binding wins, validated against
        # the configured cases_root. Never the global pointer.
        from nexus.config import settings

        resolved = Path(case_dir)
        problem = validate_case_id(resolved.name)
        if problem:
            return None, problem
        if resolved.parent != settings.cases_root:
            return None, (
                f"case_dir {resolved} is outside the configured cases_root "
                f"({settings.cases_root}) — an in-process call may only bind a "
                "case that lives there"
            )
        if not (resolved / "CASE.yaml").is_file():
            return None, f"case {resolved.name!r} is not a case directory"
        if case_id and case_id != resolved.name:
            return None, (
                f"case_id {case_id!r} does not match the bound case "
                f"{resolved.name!r}"
            )
        return resolved, ""

    if case_id:
        problem = validate_case_id(case_id)
        if problem:
            return None, problem
    if not case_id:
        # An external caller names the case it reads. Without a name, the call would
        # read whichever case happens to be active (WO-R2F item 1, D41).
        return None, "case_id is required: name the case this call reads"
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
    out: dict[str, Any] = {
        "family": str(hit.get("family") or ""),
        "file": str(hit.get("file") or ""),
        "line": str(hit.get("line") or ""),
        "host": str(hit.get("host") or ""),
        "terms": str(hit.get("terms") or ""),
        "text": str(hit.get("text") or ""),
        "fields": fields if isinstance(fields, dict) else {},
    }
    # Structured envelope fields must survive for MCP consumers (timeline
    # rendering, field filters like field="ts"/"user"/"event_id").
    for key in ("user", "event_id", "ts"):
        value = hit.get(key)
        if value not in (None, ""):
            out[key] = value
    return out


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
                        out.append(val)
                    matched = True
                    break
        if not matched and low == "host" and h.get("host"):
            out.append(str(h["host"]))
    return out


def _time_buckets(hits: list[dict[str, Any]], granularity: str) -> dict[str, int]:
    """Return every day/hour bucket from the common timestamp fields."""
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
    return dict(sorted(buckets.items()))


def do_n4_query(case_id: str = "", dsl: str = "", limit: int | None = None,
                offset: int = 0,
                match_all: bool = False,
                audit: AuditWriter | None = None) -> dict:
    """Core n4_query — the MCP tool and the Mode 2/3 binding layer share this."""
    started = time.monotonic()
    case_dir, err = _resolve_active_case(case_id)
    if err or case_dir is None:
        return {"error": err or "no active case"}
    from nexus.langgraph.query_pack import attach_hit_fields
    from nexus.langgraph.query_pack import n4_query as _n4_query

    result = _n4_query(case_dir, dsl, limit=limit, offset=offset,
                       match_all=match_all)
    if result.get("error"):
        return {**result, "case_id": Path(case_dir).name}
    hits = [h for h in (result.get("hits") or []) if isinstance(h, dict)]
    if result.get("backend") != "elasticsearch":
        with contextlib.suppress(Exception):
            hits = attach_hit_fields(case_dir, hits)  # CSV rows still need parsed fields.
    trimmed = [_trim_hit(h) for h in hits]
    aid = audit.log(
        tool="n4_query",
        params={"case_id": Path(case_dir).name, "dsl": dsl, "limit": limit,
                "offset": offset,
                "match_all": match_all},
        result_summary={"count": result.get("count"), "backend": result.get("backend"),
                        "returned": len(trimmed), "complete": result.get("complete")},
        elapsed_ms=round((time.monotonic() - started) * 1000, 1),
    ) if audit else None
    return {
        "case_id": Path(case_dir).name,
        "query": dsl,
        "count": result.get("count"),
        "count_exact": result.get("count_exact", False),
        "count_lower_bound": result.get("count_lower_bound", False),
        "scan_complete": result.get("scan_complete", False),
        "incomplete_reasons": result.get("incomplete_reasons") or [],
        "offset": result.get("offset", offset),
        "complete": result.get("complete", False),
        "next_offset": result.get("next_offset"),
        "stats": result.get("stats") or {},
        "backend": result.get("backend"),
        "hits": trimmed,
        "provenance": {"audit_id": aid, "case_id": Path(case_dir).name},
    }


def do_n4_sample(case_id: str = "", family: str = "", field: str = "",
                 value: str = "", n: int = 12,
                 audit: AuditWriter | None = None) -> dict:
    """Representative raw rows for a family/field value (context, not evidence).

    The digest aggregates; this is the raw texture an interpretation needs.
    Rows are evenly spread over the matched timeline so one burst cannot
    dominate the sample.
    """
    started = time.monotonic()
    case_dir, err = _resolve_active_case(case_id)
    if err or case_dir is None:
        return {"error": err or "no active case"}
    from nexus.langgraph.query_pack import attach_hit_fields
    from nexus.langgraph.query_pack import n4_sample as _n4_sample

    result = _n4_sample(case_dir, family=family, field=field, value=value, n=n)
    if result.get("error"):
        return {**result, "case_id": Path(case_dir).name}
    hits = [h for h in (result.get("hits") or []) if isinstance(h, dict)]
    if not all(h.get("fields") for h in hits):
        with contextlib.suppress(Exception):
            hits = attach_hit_fields(case_dir, hits)
    aid = audit.log(
        tool="n4_sample",
        params={"case_id": Path(case_dir).name, "family": family, "field": field,
                "value": value, "n": n},
        result_summary={"matched": result.get("matched"),
                        "sampled": result.get("sampled")},
        elapsed_ms=round((time.monotonic() - started) * 1000, 1),
    ) if audit else None
    return {
        "case_id": Path(case_dir).name,
        "family": result.get("family"),
        "field": result.get("field"),
        "value": result.get("value"),
        "backend": result.get("backend"),
        "matched": result.get("matched"),
        "sampled": result.get("sampled"),
        "hits": [_trim_hit(h) for h in hits],
        "note": "sample rows are context — findings still cite the audit trail (FD-001)",
        "provenance": {"audit_id": aid, "case_id": Path(case_dir).name},
    }


def do_n4_aggregate(case_id: str = "", dsl: str = "", field: str = "host",
                    top: int = 0, bucket: str = "", match_all: bool = False,
                    audit: AuditWriter | None = None) -> dict:
    """Aggregate the active case's evidence rows (context — never evidence)."""
    started = time.monotonic()
    case_dir, err = _resolve_active_case(case_id)
    if err or case_dir is None:
        return {"error": err or "no active case"}
    # WP 4j.32: ES-native aggregation first (schema-v2 index) — counts computed
    # in ES, not by streaming rows. Legacy index / CSV backend falls through.
    native: dict[str, Any] | None = None
    with contextlib.suppress(Exception):
        from nexus.langgraph.case_index import es_aggregate
        from nexus.langgraph.query_pack import load_case_intake, parse_intake_window

        native = es_aggregate(
            case_dir, dsl, field=field, top=top, bucket=bucket, match_all=match_all,
            window=parse_intake_window(load_case_intake(case_dir)),
        )
    if native is not None:
        aid = audit.log(
            tool="n4_aggregate",
            params={"case_id": Path(case_dir).name, "dsl": dsl, "field": field,
                    "bucket": bucket, "match_all": match_all},
            result_summary={"distinct": native.get("distinct"),
                            "rows": native.get("rows_scanned"), "native": True},
            elapsed_ms=round((time.monotonic() - started) * 1000, 1),
        ) if audit else None
        return {
            "case_id": Path(case_dir).name,
            "note": "aggregations are investigation context — never evidence (FD-001)",
            "provenance": {"audit_id": aid, "case_id": Path(case_dir).name},
            **native,
        }
    from nexus.langgraph.query_pack import attach_hit_fields
    from nexus.langgraph.query_pack import n4_query as _n4_query

    result = _n4_query(case_dir, dsl, limit=None, match_all=match_all)
    if result.get("error"):
        return {**result, "case_id": Path(case_dir).name}
    hits = [h for h in (result.get("hits") or []) if isinstance(h, dict)]
    with contextlib.suppress(Exception):
        hits = attach_hit_fields(case_dir, hits)
    values = _field_values(hits, field)
    counts: dict[str, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    if top > 0:
        ranked = ranked[:top]
    buckets = _time_buckets(hits, bucket) if bucket in ("day", "hour") else None
    scan_complete = bool(result.get("scan_complete", False))
    aid = audit.log(
        tool="n4_aggregate",
        params={"case_id": Path(case_dir).name, "dsl": dsl, "field": field,
                "bucket": bucket, "match_all": match_all},
        result_summary={"distinct": len(counts), "rows": len(hits),
                        "scan_complete": scan_complete},
        elapsed_ms=round((time.monotonic() - started) * 1000, 1),
    ) if audit else None
    return {
        "case_id": Path(case_dir).name,
        "field": field,
        "rows_scanned": len(hits),
        "values_seen": len(values),
        "distinct": len(counts),
        "distinct_approximate": not scan_complete,
        "top": [{"value": v, "count": c} for v, c in ranked],
        "buckets": buckets,
        "backend": result.get("backend"),
        "scan_complete": scan_complete,
        "incomplete_reasons": result.get("incomplete_reasons") or [],
        "note": "aggregations are investigation context — never evidence (FD-001)",
        "provenance": {"audit_id": aid, "case_id": Path(case_dir).name},
    }


def _observed_family_fields(
    case_dir: Path, coverage: dict[str, Any] | None = None,
) -> dict[str, list[str]]:
    """Exhaustive live census of parsed columns actually present by family."""
    from nexus.langgraph.query_pack import attach_hit_fields
    from nexus.langgraph.query_pack import n4_query as _n4_query

    observed: dict[str, dict[str, None]] = {}
    try:
        result = _n4_query(case_dir, "", limit=None, match_all=True)
        if result.get("error"):
            raise RuntimeError(str(result["error"]))
        if coverage is not None:
            coverage.update({
                "complete": bool(result.get("scan_complete", False)),
                "rows_scanned": int(result.get("count") or 0),
                "incomplete_reasons": result.get("incomplete_reasons") or [],
            })
        hits = [h for h in (result.get("hits") or []) if isinstance(h, dict)]
        with contextlib.suppress(Exception):
            hits = attach_hit_fields(case_dir, hits)
        for h in hits:
            fam = str(h.get("family") or "").lower()
            fields = h.get("fields") or {}
            if not isinstance(fields, dict):
                continue
            slot = observed.setdefault(fam, {})
            for k in fields:
                slot.setdefault(str(k), None)
    except Exception as exc:  # noqa: BLE001 — report incomplete field census
        if coverage is not None:
            coverage.update({"complete": False, "error": f"{type(exc).__name__}: {exc}"})
    return {fam: sorted(cols) for fam, cols in observed.items() if cols}


_mappings_cache: dict[str, tuple[float, dict]] = {}
_MAPPINGS_TTL = 60.0


def invalidate_mappings_cache(case_id: str) -> None:
    target = str(case_id)
    for key in list(_mappings_cache):
        if key == target or Path(key).name == target:
            _mappings_cache.pop(key, None)


def do_index_mappings(case_id: str = "", audit: AuditWriter | None = None,
                      case_dir: Path | str | None = None) -> dict:
    """Describe one case's index: backend, families, fields, census.

    The run's own ``case_dir`` is used when bound (WO-R2F item 1, D41). Otherwise the
    case is an external caller's, gated to the active case.
    """
    started = time.monotonic()
    case_dir, err = _resolve_active_case(case_id, case_dir)
    if err or case_dir is None:
        return {"error": err or "no active case"}
    # WP 4j.34: cache the census per case (steering calls this every turn).
    case_name = Path(case_dir).name
    cache_key = str(Path(case_dir).resolve())
    now = time.monotonic()
    cached = _mappings_cache.get(cache_key)
    if cached and (now - cached[0]) < _MAPPINGS_TTL:
        payload = dict(cached[1])
        payload["cached"] = True
        if audit is not None:
            audit_id = audit.log(
                tool="index_mappings", params={"case_id": case_name, "cached": True},
                result_summary={"families": len(payload.get("families") or []),
                                "es": payload.get("es_available")},
                elapsed_ms=round((time.monotonic() - started) * 1000, 1),
            )
            payload["provenance"] = {"audit_id": audit_id, "case_id": case_name}
        return payload
    from nexus.langgraph.briefing import _family_inventory
    from nexus.langgraph.case_index import es_available, index_name

    inventory = _family_inventory(case_dir)
    es = es_available()
    # Field knowledge: curated profiles (KB) + the live census (this case's
    # own parsed columns) — the LLM's `field:` targets are grounded in both.
    from nexus.knowledge.loader import get_field_profiles

    profiles = {str(p.get("family") or "").lower():
                [str(f) for f in (p.get("fields") or [])]
                for p in (get_field_profiles().get("profiles") or [])
                if isinstance(p, dict)}
    field_census: dict[str, Any] = {}
    live = _observed_family_fields(case_dir, field_census)
    family_fields = {
        fam: sorted(set(profiles.get(fam) or []) | set(live.get(fam) or []))
        for fam in sorted(inventory)
    }
    aid = audit.log(
        tool="index_mappings",
        params={"case_id": Path(case_dir).name},
        result_summary={"families": len(inventory), "es": es},
        elapsed_ms=round((time.monotonic() - started) * 1000, 1),
    ) if audit else None
    payload = {
        "case_id": Path(case_dir).name,
        "es_available": es,
        "index_name": index_name(Path(case_dir).name),
        "families": sorted(inventory),
        "family_rows": {k: v.get("rows", 0) for k, v in sorted(inventory.items())},
        "family_fields": family_fields,
        "field_census": field_census,
        "dsl_fields": [
            "family", "file", "host", "user", "event_id", "line", "ts",
            "+ every parsed column (types: keyword/text/long/date)",
        ],
        "dsl_operators": (
            "field:value (contains), field:=value (exact), field:!=value, "
            "field:>n/>=n/<n/<=n (numeric/date), field:a..b (range), "
            "field:in:(a,b), exists:field; unknown fields are rejected"
        ),
        "note": ("evidence index reachable" if es
                 else "ES not reachable — deterministic CSV pack backend"),
        "provenance": {"audit_id": aid, "case_id": Path(case_dir).name},
    }
    _mappings_cache[cache_key] = (
        now, {key: value for key, value in payload.items() if key != "provenance"}
    )
    return payload


def do_family_fields(family: str, audit: AuditWriter | None = None) -> dict:
    """One family's field profile (KB) — what columns its parsers emit."""
    from nexus.knowledge.loader import get_field_profile

    profile = get_field_profile(family)
    if not profile:
        aid = audit.log(
            tool="family_fields", params={"family": family},
            result_summary={"fields": 0},
        ) if audit else None
        return {
            "family": family,
            "fields": [],
            "note": ("no curated profile — schema-on-read applies: run n4_query and "
                     "read the hit's attached fields, or use free-text/regex search"),
            "provenance": {"audit_id": aid},
        }
    aid = audit.log(tool="family_fields", params={"family": family},
                    result_summary={"fields": len(profile.get("fields") or [])}) if audit else None
    return {
        "family": str(profile.get("family") or family),
        "fields": [str(f) for f in (profile.get("fields") or [])],
        "ossem": str(profile.get("ossem") or ""),
        "note": str(profile.get("note") or ""),
        "provenance": {"audit_id": aid},
    }


def do_run_record(case_id: str = "", audit: AuditWriter | None = None,
                  case_dir: Path | str | None = None) -> dict:
    """Return the tool-lane ledger: what actually ran against this case.

    This is the honesty tool for negative answers. It lets the model (and the
    examiner) distinguish:

    - tool ran and found nothing
    - tool ran and failed
    - tool was skipped, with the reason
    - tool never ran / no ledger exists

    Context only — the ledger is routing/provenance, never a finding.

    A run passes its own ``case_dir`` (WO-R2F item 1, D41); without it the case
    is an external caller's, gated to the active case.
    """
    started = time.monotonic()
    case_dir, err = _resolve_active_case(case_id, case_dir)
    if err or case_dir is None:
        return {"error": err or "no active case"}

    run_id = ""
    run_dir = ""
    ledger_path: Path | None = None
    extractions = case_dir / "extractions"
    try:
        from nexus.langgraph.pipeline_runs import resolve_run

        run = resolve_run(case_dir, "tools")
        run_id = run.run_id
        run_dir = str(run.path)
    except Exception:  # noqa: BLE001 — no active run is a normal state
        pass
    try:
        from nexus.langgraph.pipeline_runs import resolve_tools_extractions

        extractions = resolve_tools_extractions(case_dir, run_id)
    except Exception:  # noqa: BLE001 — fall back to the case-level paths
        extractions = case_dir / "extractions"
    for candidate in (
        extractions / "_tool_lane_ledger.json",
        case_dir / "ledger" / "_tool_lane_ledger.json",
        case_dir / "extractions" / "_tool_lane_ledger.json",
    ):
        if candidate.is_file():
            ledger_path = candidate
            break
    if ledger_path is None:
        # Immutable runs keep the ledger under runs/<id>/extractions; the
        # reuse-chain resolver intentionally ignores underscore files, so
        # find the newest run ledger directly.
        candidates = sorted(
            case_dir.glob("runs/*/extractions/_tool_lane_ledger.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if candidates:
            ledger_path = candidates[0]

    rows: list[dict[str, Any]] = []
    if ledger_path is not None:
        with contextlib.suppress(OSError, ValueError, TypeError):
            loaded = json.loads(ledger_path.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                rows = [r for r in loaded if isinstance(r, dict)]

    def _command_of(row: dict[str, Any]) -> str:
        argv = row.get("argv")
        if isinstance(argv, list):
            return " ".join(str(a) for a in argv)
        return str(row.get("command") or "")

    def _output_of(row: dict[str, Any]) -> str:
        value = row.get("output_saved_to") or row.get("output") or row.get("output_file")
        if isinstance(value, dict):
            value = value.get("path") or value.get("file") or ""
        return str(value or "")

    # A ledger id that the case's log gives to another call cannot be cited (D178): Mode 2
    # workers cited such ids from this list instead of their own queries (2026-10-14), and
    # staging refuses them. They are withheld here, where the model reads them.
    not_citable: set[str] = set()
    with contextlib.suppress(Exception):
        from nexus.analysis.integrity import ambiguous_audit_ids

        not_citable = set(ambiguous_audit_ids(
            case_dir, [str(r.get("audit_id") or "") for r in rows if r.get("audit_id")]))

    entries: list[dict[str, Any]] = []
    counts = {"OK": 0, "SKIP": 0, "FAIL": 0}
    for row in rows:
        status = str(row.get("status") or "").upper()
        if status in counts:
            counts[status] += 1
        audit_id = str(row.get("audit_id") or "")
        entry = {
            "tool": str(row.get("tool") or ""),
            "status": status,
            "reason": str(row.get("reason") or ""),
            "purpose": str(row.get("purpose") or ""),
            "command": _command_of(row),
            "output": _output_of(row),
            "duration_s": row.get("duration_s"),
            "audit_id": "" if audit_id in not_citable else audit_id,
        }
        if audit_id in not_citable:
            entry["audit_id_note"] = ("not citable: this run's id also names another call in the "
                                      "case log; cite the query that returned the rows")
        entries.append(entry)

    aid = audit.log(
        tool="run_record",
        params={"case_id": Path(case_dir).name, "run_id": run_id},
        result_summary={"entries": len(rows), **counts},
        elapsed_ms=round((time.monotonic() - started) * 1000, 1),
    ) if audit else None
    return {
        "case_id": Path(case_dir).name,
        "run_id": run_id,
        "run_dir": run_dir,
        "ledger_path": str(ledger_path) if ledger_path else "",
        "available": bool(rows),
        "total": len(rows),
        "counts": counts,
        "entries": entries,
        "note": (
            "Tool-lane ledger (routing/provenance). A zero-hit query is not "
            "negative evidence until this says the relevant parser ran."
        ),
        "provenance": {"audit_id": aid, "case_id": Path(case_dir).name},
    }


def _register_native_read_tool(server: FastMCP, audit: AuditWriter, name: str) -> None:
    """Expose the native argument contract through MCP without a second signature.

    External callers still pass the existing active-case gate. MCP's legacy
    optional case/query/aggs defaults are adapter defaults, not extra arguments.
    """
    from inspect import Parameter, signature

    from nexus.langgraph import backbone, es_native

    native = getattr(es_native, name)
    native_signature = signature(native, eval_str=True)

    def read(**kwargs) -> dict:
        case_id = str(kwargs.pop("case_id", "") or "")
        case_dir, error = _resolve_active_case(case_id)
        if error or case_dir is None:
            return {"error": error or "no active case"}
        if name == "es_search":
            kwargs["query"] = kwargs.get("query") or {"match_all": {}}
        elif kwargs.get("aggs") is None:
            kwargs["aggs"] = {}
        return backbone._es_call(name, audit=audit, case_id=case_dir.name, case_dir=case_dir, **kwargs)

    parameters = []
    for parameter in native_signature.parameters.values():
        default = parameter.default
        if parameter.name == "case_id":
            default = ""
        elif default is Parameter.empty:
            default = None
        parameters.append(parameter.replace(kind=Parameter.KEYWORD_ONLY, default=default))
    read.__name__ = name
    read.__doc__ = native.__doc__
    read.__signature__ = native_signature.replace(parameters=parameters)  # type: ignore[attr-defined]
    read.__annotations__ = {parameter.name: parameter.annotation for parameter in parameters}
    read.__annotations__["return"] = dict
    server.tool(name=name)(read)


def register_tools(server: FastMCP, audit: AuditWriter):
    @server.tool()
    def n4_query(case_id: str = "", dsl: str = "", limit: int | None = None,
                 offset: int = 0,
                 match_all: bool = False) -> dict:
        """Run an N4 DSL query against the ACTIVE case's evidence index.

        The LLM is gated to the active case: an explicit case_id must match
        it. `dsl` is typed: any catalog column (including parsed fields.*)
        with contains/exact/!=/comparators/ranges/exists/in; unknown fields
        are rejected with suggestions. AND/OR/NOT, quoted phrases and regex:
        are supported. Call index_mappings/family_fields for the case columns.
        Set `match_all=true` with an empty dsl to scan every indexed row.
        By default returns every matching row. Set `limit` to request one
        response page and continue at `next_offset` until `complete=true`.
        No row or field text is truncated. Evidence plane: ES when configured,
        deterministic CSV pack otherwise.
        Findings need these rows' audit_ids (FD-001).
        """
        return do_n4_query(case_id=case_id, dsl=dsl, limit=limit, offset=offset,
                           match_all=match_all, audit=audit)

    @server.tool()
    def n4_sample(case_id: str = "", family: str = "", field: str = "",
                  value: str = "", n: int = 12) -> dict:
        """Representative raw rows for a family/field value (context, not evidence).

        The digest gives aggregates; this pulls the raw texture: N rows of
        `family` (optionally where `field == value`), evenly spread over the
        matched timeline so one burst cannot dominate. Use it before staking
        an interpretation on a pattern — the rows are grounding, and findings
        still cite the audit trail (FD-001).
        """
        return do_n4_sample(case_id=case_id, family=family, field=field,
                            value=value, n=n, audit=audit)

    @server.tool()
    def n4_aggregate(
        case_id: str = "",
        dsl: str = "",
        field: str = "host",
        top: int = 0,
        bucket: str = "",
        match_all: bool = False,
    ) -> dict:
        """Aggregate the active case's evidence rows (context — never evidence).

        Counts every distinct value of `field` (a parsed column, or `host`) across
        the query's result set; optional `bucket` = "day"|"hour" groups by
        timestamp. Set `match_all=true` with an empty dsl to aggregate across
        every indexed row. `top=0` returns every distinct value; a positive
        `top` is an examiner-requested top-N view. Grounded: counts come from the N4 result
        stream the examiner sees (ES backend or CSV pack).
        """
        return do_n4_aggregate(case_id=case_id, dsl=dsl, field=field, top=top,
                               bucket=bucket, match_all=match_all, audit=audit)

    @server.tool()
    def index_mappings(case_id: str = "") -> dict:
        """Describe the active case's index: backend, families, N4 DSL fields.

        Grounds the LLM against hallucinated families/fields — the vocabulary
        it may query is what this case actually holds (curated field profiles
        + a live census of the case's parsed columns per family).
        """
        return do_index_mappings(case_id=case_id, audit=audit)

    @server.tool()
    def family_fields(family: str) -> dict:
        """Salient columns a parser family emits (curated profile + OSSEM).

        Use before aggregating on a field: tells the LLM which column names
        exist in that family's evidence. Unknown families fall back to
        schema-on-read guidance.
        """
        return do_family_fields(family=family, audit=audit)

    @server.tool()
    def run_record(case_id: str = "") -> dict:
        """What ran against this case: the tool-lane ledger (routing/provenance).

        Returns per-tool status (OK/SKIP/FAIL), reason, purpose, command,
        output path and audit_id, plus totals. Use before claiming evidence is
        absent — a zero-hit query is not negative evidence until the relevant
        parser is shown to have run. Context only, never a finding.
        """
        return do_run_record(case_id=case_id, audit=audit)

    # ── Phase 4k.5 — ES-native surface (Mode 2/3; read-only, audited) ──
    @server.tool()
    def es_fields(case_id: str = "") -> dict:
        """Full field catalog for the active case's ES index (all columns).

        Returns every family with row counts, the typed core fields and every
        parsed column (`fields.*`), so the agent queries real schema instead
        of guessing. Call this once per case before querying. ES-only.
        """
        started = time.monotonic()
        case_dir, err = _resolve_active_case(case_id)
        if err or case_dir is None:
            return {"error": err or "no active case"}
        from nexus.langgraph.es_native import ESQueryError
        from nexus.langgraph.es_native import es_fields as _es_fields

        try:
            result = _es_fields(Path(case_dir).name)
        except ESQueryError as exc:
            with contextlib.suppress(Exception):
                audit.log(tool="es_fields",
                          params={"case_id": Path(case_dir).name},
                          result_summary={"error": str(exc)[:300]})
            return {"error": str(exc), "case_id": Path(case_dir).name}
        result["provenance"] = {
            "audit_id": audit.log(
                tool="es_fields",
                params={"case_id": Path(case_dir).name},
                result_summary={"families": len(result.get("families") or {})},
                elapsed_ms=round((time.monotonic() - started) * 1000, 1),
            ),
            "case_id": Path(case_dir).name,
        }
        return result

    _register_native_read_tool(server, audit, "es_search")
    _register_native_read_tool(server, audit, "es_aggregate")

    @server.tool()
    def es_sample(case_id: str = "", family: str = "", field: str = "",
                  value: str = "", n: int = 12) -> dict:
        """Representative ES rows for a family/field value, spread over time.

        Same role as n4_sample but ES-native (Mode 2/3): grounding texture
        before staking an interpretation; findings still cite audit_ids.
        """
        started = time.monotonic()
        case_dir, err = _resolve_active_case(case_id)
        if err or case_dir is None:
            return {"error": err or "no active case"}
        from nexus.langgraph.es_native import ESQueryError
        from nexus.langgraph.es_native import es_sample as _es_sample

        try:
            result = _es_sample(
                Path(case_dir).name, family=family, field=field, value=value, n=n,
            )
        except ESQueryError as exc:
            with contextlib.suppress(Exception):
                audit.log(tool="es_sample",
                          params={"case_id": Path(case_dir).name},
                          result_summary={"error": str(exc)[:300]})
            return {"error": str(exc), "case_id": Path(case_dir).name}
        result["provenance"] = {
            "audit_id": audit.log(
                tool="es_sample",
                params={"case_id": Path(case_dir).name, "family": family,
                        "field": field, "value": value[:120], "n": n},
                result_summary={"matched": result.get("matched"),
                                "sampled": result.get("sampled")},
                elapsed_ms=round((time.monotonic() - started) * 1000, 1),
            ),
            "case_id": Path(case_dir).name,
        }
        return result
