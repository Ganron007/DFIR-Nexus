"""Phase 4k.6 — per-case field catalog for the typed Mode 1 DSL.

Merges what the case actually holds:
- ES mapping (real types + keyword subfields) when the index exists;
- CSV header columns per family (type-sampled) for CSV-only cases.

The catalog powers: DSL field validation (unknown = hard error), typed
operator translation (numeric/date comparisons), and the prompt vocabulary
(``field_catalog_block``) so Mode 1 LLMs query columns that exist.
"""
from __future__ import annotations

import difflib
import logging
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_CACHE: dict[str, tuple[float, dict[str, dict[str, Any]]]] = {}
_TTL = 60.0

NUMERIC_TYPES = frozenset({
    "long", "integer", "short", "byte", "double", "float", "half_float",
    "scaled_float", "unsigned_long",
})
DATE_TYPES = frozenset({"date", "date_nanos"})


def _es_catalog(case_id: str) -> dict[str, dict[str, Any]]:
    try:
        from nexus.langgraph.case_index import (
            INDEX_SCHEMA_VERSION,
            _client,
            _schema_version_cached,
            index_name,
        )

        if _schema_version_cached(case_id) < INDEX_SCHEMA_VERSION:
            return {}
        with _client() as client:
            name = index_name(case_id)
            resp = client.get(f"/{name}/_mapping")
            if resp.status_code != 200:
                return {}
            props = (
                (resp.json().get(name) or {}).get("mappings") or {}
            ).get("properties") or {}
    except Exception:  # noqa: BLE001 — catalog is best-effort
        return {}

    out: dict[str, dict[str, Any]] = {}
    for key, spec in props.items():
        if key == "fields" or not isinstance(spec, dict):
            continue
        out[key.lower()] = {
            "name": key,
            "type": str(spec.get("type") or "text"),
            "has_kw": "kw" in (spec.get("fields") or {}),
            "families": [],
        }
    for key, spec in ((props.get("fields") or {}).get("properties") or {}).items():
        if not isinstance(spec, dict):
            continue
        out[key.lower()] = {
            "name": key,
            "type": str(spec.get("type") or "text"),
            "has_kw": "kw" in (spec.get("fields") or {}),
            "families": [],
        }
    return out


def _sample_type(value: str) -> str:
    v = str(value or "").strip()
    if not v:
        return "text"
    try:
        float(v)
        return "double"
    except ValueError:
        pass
    from nexus.langgraph.timestamps import parse_time_value

    if parse_time_value(v):
        return "date"
    return "text"


def _csv_catalog(case_dir: Path) -> dict[str, dict[str, Any]]:
    try:
        from nexus.langgraph.case_index import _index_header
        from nexus.langgraph.query_pack import iter_extraction_files
    except Exception:  # noqa: BLE001
        return {}
    out: dict[str, dict[str, Any]] = {}
    for path, _root, fam in iter_extraction_files(case_dir):
        header = _index_header(path)
        if not header:
            continue
        sample_line = ""
        try:
            with path.open(encoding="utf-8", errors="replace") as fh:
                fh.readline()
                sample_line = fh.readline().strip()
        except OSError:
            sample_line = ""
        values = sample_line.split(",") if sample_line else []
        for idx, col in enumerate(header):
            key = str(col).strip().lstrip("\ufeff")
            if not key or str(key).startswith("_"):
                continue
            low = key.lower()
            sample = values[idx] if idx < len(values) else ""
            entry = out.setdefault(low, {
                "name": key, "type": "text", "has_kw": True, "families": set(),
                "_typed": False,
            })
            entry["families"].add(fam)
            if sample and not entry.get("_typed"):
                sampled = _sample_type(sample)
                if sampled != "text":
                    entry["type"] = sampled
                    entry["_typed"] = True
    return out


def case_field_catalog(case_dir: str | Path) -> dict[str, dict[str, Any]]:
    """All queryable columns for a case (cached 60 s). Empty when unknown."""
    case_dir = Path(case_dir)
    key = case_dir.name
    now = time.monotonic()
    cached = _CACHE.get(key)
    if cached and now - cached[0] < _TTL:
        return cached[1]
    catalog = _es_catalog(key)
    csv_cat = _csv_catalog(case_dir)
    if not catalog:
        catalog = csv_cat
    else:
        for low, entry in csv_cat.items():
            catalog.setdefault(low, entry)
    for entry in catalog.values():
        entry.pop("_typed", None)
        fams = entry.get("families")
        entry["families"] = sorted(fams) if isinstance(fams, set) else list(fams or [])
    _CACHE[key] = (now, catalog)
    return catalog


def invalidate_catalog(case_id: str) -> None:
    _CACHE.pop(case_id, None)


def resolve_field(catalog: dict[str, dict[str, Any]] | None, name: str) -> dict[str, Any] | None:
    if not catalog:
        return None
    return catalog.get(str(name or "").strip().lower())


def suggest_field(catalog: dict[str, dict[str, Any]] | None, name: str, n: int = 3) -> list[str]:
    if not catalog:
        return []
    return difflib.get_close_matches(
        str(name or "").strip().lower(), list(catalog.keys()), n=n, cutoff=0.6,
    )


def field_catalog_block(case_dir: str | Path | None, cap: int = 150) -> str:
    """Compact prompt block: typed columns the case actually holds."""
    if not case_dir:
        return ""
    try:
        catalog = case_field_catalog(case_dir)
    except Exception:  # noqa: BLE001
        return ""
    if not catalog:
        return ""
    core = [
        "family:keyword", "file:keyword", "line:integer", "text:text",
        "host:keyword", "user:keyword", "event_id:keyword",
        "ts:date (canonical UTC; ts_src/ts_precision flags)",
    ]
    columns = [
        f"{entry['name']}:{entry['type']}"
        for low, entry in sorted(catalog.items())
        if low not in {"case_id", "family", "file", "line", "text", "host",
                       "user", "event_id", "ts", "ts_raw", "ts_src",
                       "ts_precision", "ts_tz_assumed", "ts_year_assumed"}
    ]
    body = ", ".join(columns[:cap])
    extra = "" if len(columns) <= cap else f" (+{len(columns) - cap} more via es_fields)"
    return (
        "CASE FIELD CATALOG (only these columns exist; typed):\n"
        f"  core: {', '.join(core)}\n"
        f"  parsed: {body}{extra}\n"
        "Operators: field:value (contains), field:=value (exact), field:!=value, "
        "field:>n / >=n / <n / <=n (numeric/date), field:a..b (range), "
        "field:in:(a,b), exists:field. Unknown field names are rejected."
    )
