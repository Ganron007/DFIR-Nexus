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
        subs = spec.get("fields") or {}
        out[key.lower()] = {
            "name": key,
            "type": str(spec.get("type") or "text"),
            "has_kw": "kw" in subs,
            # Core envelope columns are TOP-LEVEL: never query fields.<core>.
            "path": key,
            "families": [],
        }
    for key, spec in ((props.get("fields") or {}).get("properties") or {}).items():
        if not isinstance(spec, dict):
            continue
        subs = spec.get("fields") or {}
        out[key.lower()] = {
            "name": key,
            "type": str(spec.get("type") or "text"),
            "has_kw": "kw" in subs,
            "path": f"fields.{key}",
            "families": [],
        }
    # WO-CS1: the common `ecs.*` fields are queryable too, so Mode 1's DSL validates
    # them (unknown field = hard error). A nested ecs object has no flat mapping
    # entry, so the names come from the map's own destinations (a known set).
    try:
        from nexus.langgraph.ecs_normalize import load_ecs_map

        emap = load_ecs_map()
        for table in (emap.get("family_columns") or {}).values():
            if isinstance(table, dict):
                for dst in table.values():
                    _add_ecs_entry(out, str(dst))
        for per_event in (emap.get("winlog_event_data") or {}).values():
            if isinstance(per_event, dict):
                for dst in per_event.values():
                    _add_ecs_entry(out, str(dst))
    except Exception:  # noqa: BLE001 - catalog is best-effort
        pass
    return out


def _add_ecs_entry(out: dict[str, dict[str, Any]], dst: str) -> None:
    if not dst.startswith("ecs.") or "*" in dst:
        return
    out[dst.lower()] = {
        "name": dst,
        "type": "keyword",
        "has_kw": False,
        "path": dst,
        "families": [],
        "ecs": True,
    }


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
    import csv as _csv
    import json as _json

    from nexus.langgraph.query_pack import _open_text

    out: dict[str, dict[str, Any]] = {}
    for path, _root, fam in iter_extraction_files(case_dir):
        header = _index_header(path)
        if not header:
            continue
        values: list[str] = []
        try:
            with _open_text(path) as fh:
                fh.readline()
                sample_line = fh.readline().strip()
            if sample_line:
                values = next(_csv.reader([sample_line]), [])
        except OSError:
            values = []
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
    # Imported (non-host) evidence columns live only in the artifact store.
    store = case_dir / "ingest" / "artifacts.jsonl"
    if store.is_file():
        try:
            with store.open(encoding="utf-8", errors="replace") as fh:
                for _ in range(20):
                    line = fh.readline()
                    if not line:
                        break
                    try:
                        record = _json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(record, dict):
                        continue
                    for key, value in record.items():
                        if value in (None, "", [], {}):
                            continue
                        low = str(key).lower()
                        entry = out.setdefault(low, {
                            "name": str(key), "type": "text", "has_kw": True,
                            "_typed": False,
                        })
                        if not entry.get("_typed"):
                            sampled = _sample_type(str(value))
                            if sampled != "text":
                                entry["type"] = sampled
                                entry["_typed"] = True
                    break
        except OSError:
            pass
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


def _populated_ecs(case_id: str, cap: int = 200) -> dict[str, str]:
    """`ecs.*` field -> one sample value, for fields this case actually fills.

    WO-CS1 item 5 / CS1b item 6: the catalog shows a sample value per `ecs` field.
    One `filters`/`exists` aggregation finds the populated fields, then one bounded
    query per field reads a sample value.
    """
    try:
        from nexus.langgraph.ecs_normalize import load_ecs_map
        from nexus.langgraph.es_native import _client_and_index
    except Exception:  # noqa: BLE001
        return {}
    emap = load_ecs_map()
    if not emap:
        return {}
    declared: set[str] = set()
    for table in (emap.get("family_columns") or {}).values():
        if isinstance(table, dict):
            for dst in table.values():
                declared.add(str(dst))
    # winlog_event_data is keyed by channel -> event_id -> {name: dst}
    for channels in (emap.get("winlog_event_data") or {}).values():
        if not isinstance(channels, dict):
            continue
        for per_event in channels.values():
            if isinstance(per_event, dict):
                declared.update(str(d) for d in per_event.values())
    declared = {d for d in declared if d.startswith("ecs.") and "*" not in d
                and "event_data" not in d}
    if not declared:
        return []
    fields = sorted(declared)[:cap]
    try:
        client, name = _client_and_index(case_id)
        filters = {f: {"exists": {"field": f}} for f in fields}
        with client() as c:
            res = c.post(f"/{name}/_search",
                         json={"size": 0, "aggs": {"ecs": {"filters": {"filters": filters}}}})
            if res.status_code >= 400:
                return {}
            buckets = ((res.json().get("aggregations") or {}).get("ecs") or {}).get("buckets") or {}
            present = [f for f, b in buckets.items() if int((b or {}).get("doc_count") or 0) > 0]
            # WO-CS1b item 6: one sample value per populated ecs field, so the LLM
            # sees what a field actually holds (the WO asks for this).
            samples: dict[str, str] = {}
            for f in present:
                sres = c.post(f"/{name}/_search", json={
                    "size": 1, "_source": [f],
                    "query": {"exists": {"field": f}},
                })
                if sres.status_code >= 400:
                    samples[f] = ""
                    continue
                hits = ((sres.json().get("hits") or {}).get("hits")) or []
                if hits:
                    node: Any = hits[0].get("_source") or {}
                    for part in f.split("."):
                        node = node.get(part) if isinstance(node, dict) else None
                    samples[f] = str(node)[:80] if node is not None else ""
                else:
                    samples[f] = ""
        return samples
    except Exception:  # noqa: BLE001
        return {}


def field_sheet_block(case_dir: str | Path | None, *, cap_bytes: int = 4096) -> str:
    """A COMPACT case field sheet for every investigative prompt (WO-R1F item 2b).

    Measured in SC1's recorded model calls: the per-case field catalog appeared in
    **0 of 91 calls**. The model had to call `es_mappings` and digest hundreds of
    columns, so it guessed names and 27% of its queries were rejected.

    This is deliberately small (≤ ``cap_bytes``) so it can go in every prompt:
    the populated `ecs.*` fields with one real sample value each, plus each
    family's most useful columns. The full catalog stays one `es_mappings` call
    away. Never raises; an unindexed case yields "".
    """
    if not case_dir:
        return ""
    try:
        from nexus.langgraph.es_native import es_fields

        fields = es_fields(Path(case_dir).name)
    except Exception:  # noqa: BLE001
        return ""
    populated = fields.get("populated_columns") or {}
    ecs_pop = {}
    try:
        ecs_pop = _populated_ecs(Path(case_dir).name)
    except Exception:  # noqa: BLE001
        ecs_pop = {}

    lines: list[str] = []
    if ecs_pop:
        entries = []
        for field_name in sorted(ecs_pop):
            sample = str(ecs_pop[field_name] or "")[:32]
            entries.append(f"{field_name} (e.g. {sample})" if sample else field_name)
            if sum(len(e) + 2 for e in entries) > cap_bytes // 3:
                break
        lines.append("ecs.* (populated, with a real sample): " + "; ".join(entries))
    families = sorted((fields.get("families") or {}).keys())
    budget = cap_bytes - sum(len(line) + 1 for line in lines)
    for fam in families:
        cols = sorted(populated.get(fam) or {})
        if not cols:
            continue
        handful = ", ".join(f"fields.{c}" for c in cols[:10])
        line = f"{fam}: {handful}"
        if len(line) + 1 > budget:
            break
        lines.append(line)
        budget -= len(line) + 1
    if not lines:
        return ""
    text = (
        "CASE FIELD SHEET (columns FILLED in this case; a name absent here is not "
        "filled — call es_mappings for the full list):\n" + "\n".join(lines)
    )
    return text[:cap_bytes]


def field_catalog_block(case_dir: str | Path | None, cap: int = 150) -> str:
    """Compact prompt block: the columns this case's documents actually FILL.

    D35 (WO-KM1 item 2, finished by R0F item 2): the block must never present
    **declared** columns as present. The ES mapping types every registry column, so
    a block built from it names columns this case never filled (a CloudTrail case
    would be told `PayloadData1` exists) and a model that queries one reads "matched
    nothing". The block is therefore built from ``es_fields``' ``populated_columns``,
    **per family present in the case** - and never from the declared mapping.
    """
    if not case_dir:
        return ""
    core = [
        "family:keyword", "file:keyword", "line:integer", "text:text",
        "host:keyword", "user:keyword", "event_id:keyword",
        "ts:date (canonical UTC; ts_src/ts_precision flags)",
    ]
    operators = (
        "Operators: field:value (contains), field:=value (exact), field:!=value, "
        "field:>n / >=n / <n / <=n (numeric/date), field:a..b (range), "
        "field:in:(a,b), exists:field. Unknown field names are rejected."
    )

    # D35 item 2 + WO-CS1 item 5: populated columns, per family present, led by the
    # common `ecs.*` fields the WO wants preferred for cross-source questions.
    fam_lines: list[str] = []
    ecs_lines: list[str] = []
    used = 0
    try:
        from nexus.langgraph.es_native import es_fields

        fields = es_fields(Path(case_dir).name)
        populated = fields.get("populated_columns") or {}
        ecs_pop = _populated_ecs(Path(case_dir).name)
        if ecs_pop:
            # WO-CS1b item 6: show one sample value per ecs field.
            entries = []
            for f in sorted(ecs_pop):
                s = ecs_pop[f]
                entries.append(f"{f} (e.g. {s[:40]})" if s else f)
                if len(entries) >= cap:
                    break
            extra = "" if len(ecs_pop) <= cap else f" (+{len(ecs_pop) - cap} more)"
            ecs_lines.append(f"  {', '.join(entries)}{extra}")
        for fam in sorted((fields.get("families") or {}).keys()):
            cols = sorted(populated.get(fam) or {})
            if not cols:
                continue
            shown = [f"fields.{c}" for c in cols[:max(0, cap - used)]]
            used += len(shown)
            fam_lines.append(f"  {fam}: {', '.join(shown)}")
            if used >= cap:
                break
    except Exception:  # noqa: BLE001 - fall back to the case's own files
        fam_lines = []

    if ecs_lines or fam_lines:
        head = ("CASE FIELD CATALOG (columns populated by a family PRESENT in this case; "
                "a column absent here is not filled in this case - do not query it):\n")
        if ecs_lines:
            head += ("COMMON FIELDS (ecs.*) - prefer these for cross-source questions; "
                     "use fields.<tool column> for tool-specific detail:\n"
                     + "\n".join(ecs_lines) + "\n")
        head += ("PER-FAMILY TOOL COLUMNS:\n" + "\n".join(fam_lines) + "\n" if fam_lines else "")
        return head + operators

    # No ES (CSV-only / not yet indexed): fall back to the columns the case's own
    # parsed files carry, which is equally case-honest.
    try:
        catalog = case_field_catalog(case_dir)
    except Exception:  # noqa: BLE001
        return ""
    if not catalog:
        return ""
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
        "CASE FIELD CATALOG (the columns this case's parsed files carry):\n"
        f"  core: {', '.join(core)}\n"
        f"  parsed: {body}{extra}\n"
        + operators
    )
