"""Phase 4k.5 — ES-native query surface for Mode 2/3.

The agent queries Elasticsearch directly (bounded + audited) instead of the
typed DSL: full mapping introspection, allowlisted query/agg shapes, exact
totals with labelled paging, and the standard row identity for staging.
Read-only, case-index-pinned, ES-required (no CSV pretence).
"""
from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_SIZE = 200
MAX_SIZE = 1000
MAX_AGGS = 40

_QUERY_KEYS = {
    "bool", "term", "terms", "range", "match", "match_phrase", "multi_match",
    "wildcard", "exists", "prefix", "match_all", "match_none", "ids", "regexp",
}
_BOOL_KEYS = {"must", "should", "must_not", "filter", "minimum_should_match"}
_TERM_BODY_KEYS = {"value", "boost", "case_insensitive"}
_RANGE_BODY_KEYS = {"gte", "gt", "lte", "lt", "format", "boost", "time_zone"}
_AGG_TYPES = {
    "terms", "date_histogram", "cardinality", "composite", "min", "max",
    "avg", "sum", "value_count", "histogram", "range",
}
_COMPOSITE_SOURCES = {"terms", "date_histogram", "histogram"}
# Strict per-type body allowlists: anything else (script!) is rejected.
_AGG_BODY_KEYS = {
    "terms": {"field", "size", "order", "missing", "min_doc_count",
              "shard_size", "include", "exclude"},
    "date_histogram": {"field", "calendar_interval", "fixed_interval",
                       "time_zone", "format", "min_doc_count", "missing",
                       "order", "offset"},
    "histogram": {"field", "interval", "min_doc_count", "missing", "order",
                  "offset"},
    "range": {"field", "ranges", "keyed", "missing"},
    "cardinality": {"field", "precision_threshold", "missing"},
    "min": {"field", "missing", "format"},
    "max": {"field", "missing", "format"},
    "avg": {"field", "missing", "format"},
    "sum": {"field", "missing", "format"},
    "value_count": {"field", "missing"},
    "composite": {"sources", "size", "after"},
}
_COMPOSITE_SOURCE_KEYS = {
    "terms": {"field", "order", "missing", "size"},
    "date_histogram": {"field", "calendar_interval", "fixed_interval",
                       "time_zone", "format", "order", "offset"},
    "histogram": {"field", "interval", "order", "missing", "offset"},
}


class ESQueryError(ValueError):
    """Unsupported or unsafe ES query shape."""


def _check_bool(body: dict, depth: int) -> None:
    if depth > 6:
        raise ESQueryError("query nesting too deep (max 6)")
    for key, value in body.items():
        if key not in _BOOL_KEYS:
            raise ESQueryError(f"unsupported bool key: {key}")
        if key == "minimum_should_match":
            continue
        clauses = value if isinstance(value, list) else [value]
        for clause in clauses:
            validate_query(clause, depth + 1)


def validate_query(body: Any, depth: int = 0) -> None:
    """Allowlist recursive ES query JSON (no scripts, no cross-index, no writes)."""
    if not isinstance(body, dict) or not body:
        raise ESQueryError("query must be a non-empty object")
    if len(body) != 1:
        allowed = ", ".join(sorted(_QUERY_KEYS))
        raise ESQueryError(
            f"query must contain exactly one clause ({allowed}) at each level"
        )
    (key, value), = body.items()
    if key not in _QUERY_KEYS:
        raise ESQueryError(f"unsupported query clause: {key}")
    if key == "bool":
        if not isinstance(value, dict):
            raise ESQueryError("bool body must be an object")
        _check_bool(value, depth)
    elif key in ("term", "match", "match_phrase", "prefix", "wildcard"):
        if not isinstance(value, dict) or len(value) != 1:
            raise ESQueryError(f"{key} takes exactly one field")
        (field, spec), = value.items()
        if "." in field and "script" in str(spec).lower():
            raise ESQueryError("field names cannot contain scripts")
        if isinstance(spec, dict):
            unknown = set(spec) - _TERM_BODY_KEYS
            unknown |= {k for k in spec if k == "script"}
            if unknown:
                raise ESQueryError(f"unsupported {key} options: {sorted(unknown)}")
    elif key == "terms":
        if not isinstance(value, dict) or len(value) != 1:
            raise ESQueryError("terms takes exactly one field")
        (field, values), = value.items()
        if not isinstance(values, list) or not values:
            raise ESQueryError("terms values must be a non-empty list")
        if len(values) > 5000:
            raise ESQueryError("terms list too large (max 5000)")
    elif key == "range":
        if not isinstance(value, dict) or len(value) != 1:
            raise ESQueryError("range takes exactly one field")
        (field, spec), = value.items()
        if not isinstance(spec, dict):
            raise ESQueryError("range body must be an object")
        unknown = set(spec) - _RANGE_BODY_KEYS
        if unknown:
            raise ESQueryError(f"unsupported range options: {sorted(unknown)}")
        for bound in ("gte", "gt", "lte", "lt"):
            if bound in spec and not isinstance(spec[bound], (str, int, float)):
                raise ESQueryError(f"range {bound} must be a string or number")
    elif key == "exists":
        if not isinstance(value, dict) or not isinstance(value.get("field"), str):
            raise ESQueryError("exists requires {field: name}")
    elif key == "multi_match":
        if not isinstance(value, dict) or not isinstance(value.get("query"), str):
            raise ESQueryError("multi_match requires a query string")
        fields = value.get("fields")
        if fields is not None and (
            not isinstance(fields, list) or not all(isinstance(f, str) for f in fields)
        ):
            raise ESQueryError("multi_match fields must be a list of names")
        if any(f.startswith("_") for f in (fields or [])):
            raise ESQueryError("multi_match cannot target metadata fields")
    elif key == "regexp":
        if not isinstance(value, dict) or len(value) != 1:
            raise ESQueryError("regexp takes exactly one field")
        (field, spec), = value.items()
        if not isinstance(spec, dict) or "value" not in spec:
            raise ESQueryError("regexp requires {field: {value: pattern}}")
        unknown = set(spec) - {"value", "case_insensitive", "flags"}
        if unknown:
            raise ESQueryError(f"unsupported regexp options: {sorted(unknown)}")
        pattern = str(spec.get("value") or "")
        if len(pattern) > 200:
            raise ESQueryError("regexp pattern too long (max 200)")
        from nexus.langgraph.query_dsl import _DANGEROUS_RE

        if _DANGEROUS_RE.search(pattern):
            raise ESQueryError("regexp rejected: nested quantifier (ReDoS guard)")
    elif key == "ids":
        values = value.get("values") if isinstance(value, dict) else None
        if not isinstance(values, list) or len(values) > 1000:
            raise ESQueryError("ids requires values (max 1000)")
    elif key == "match_all" or key == "match_none":
        if value not in ({}, None):
            raise ESQueryError(f"{key} takes an empty object")


# ----- P1 failed-term honesty: refs are validated against the live mapping -----

_MAPPING_TYPES_TTL = 60.0
_mapping_types_cache: dict[str, tuple[float, dict[str, str]]] = {}

_CLAUSE_FIELD_KEYS = ("term", "match", "match_phrase", "prefix", "wildcard", "regexp", "range")
_NUMERIC_ES = {
    "long", "integer", "short", "byte", "double", "float", "half_float", "scaled_float",
}
_DATE_ES = {"date", "date_nanos"}
_BOOL_ES = {"boolean"}


def _mapping_field_types(case_id: str) -> dict[str, str]:
    """field path -> ES type for this case index (cached 60 s)."""
    import time

    now = time.monotonic()
    cached = _mapping_types_cache.get(case_id)
    if cached and (now - cached[0]) < _MAPPING_TYPES_TTL:
        return cached[1]
    out: dict[str, str] = {}
    try:
        from nexus.langgraph.case_index import _client, index_name

        name = index_name(case_id)
        with _client() as c:
            r = c.get(f"/{name}/_mapping")
            if r.status_code == 200:
                props = ((r.json().get(name) or {}).get("mappings") or {}).get("properties") or {}

                def walk(prefix: str, spec: Any) -> None:
                    if not isinstance(spec, dict):
                        return
                    kind = str(spec.get("type") or ("object" if "properties" in spec else "text"))
                    if prefix:
                        out[prefix] = kind
                    for sub, sub_spec in (spec.get("fields") or {}).items():
                        if isinstance(sub_spec, dict):
                            out[f"{prefix}.{sub}"] = str(sub_spec.get("type") or "text")
                    for child, child_spec in (spec.get("properties") or {}).items():
                        walk(f"{prefix}.{child}" if prefix else str(child), child_spec)

                for key, spec in props.items():
                    walk(str(key), spec)
    except Exception:  # noqa: BLE001 — validation is best-effort, never blocks search
        out = {}
    _mapping_types_cache[case_id] = (now, out)
    return out


def _coercible(kind: str, value: Any) -> bool:
    if value is None:
        return True
    if kind in _NUMERIC_ES:
        try:
            float(value)
            return True
        except (TypeError, ValueError):
            return False
    if kind in _DATE_ES:
        s = str(value)
        return bool(s[:4].isdigit() and ("-" in s or s.isdigit()))
    if kind in _BOOL_ES:
        return str(value).lower() in {"true", "false", "0", "1"}
    return True


def _check_ref(
    field: str, spec: Any, types: dict[str, str], context: str,
    fatal: list[dict[str, str]], optional: list[dict[str, str]], seen: set[str],
) -> None:
    if "*" in field:
        return  # wildcard patterns are checked by ES itself
    kind = types.get(field)
    if kind is None and field.endswith((".kw", ".wc")):
        kind = types.get(field.rsplit(".", 1)[0])
    if kind is None:
        entry = {"field": field, "reason": "unknown_field", "context": context}
    else:
        values: list[Any] = []
        if isinstance(spec, dict):
            values = [v for k, v in spec.items() if k in {"value", "gte", "lte", "gt", "lt"}]
        elif spec is not None and not isinstance(spec, dict):
            values = [spec]
        entry = {}
        for v in values:
            if not _coercible(kind, v):
                entry = {"field": field, "reason": f"value {v!r} cannot be a {kind}", "context": context}
                break
        if not entry:
            return
    dedupe = f"{field}\x00{context}"
    if dedupe in seen:
        return
    seen.add(dedupe)
    (fatal if context == "required" else optional).append(entry)


def _collect_failed(
    node: Any, types: dict[str, str], context: str,
    fatal: list[dict[str, str]], optional: list[dict[str, str]], seen: set[str],
) -> None:
    """Walk a query, classifying failed refs by boolean context.

    ``must``/``filter`` (and top level) are REQUIRED: a failed ref there means
    the query cannot match → degraded hard-signal. ``should``/``must_not``
    refs are OPTIONAL: the query can still match truthfully, so they are
    reported alongside a normal result instead of blocking it.
    """
    if isinstance(node, list):
        for item in node:
            _collect_failed(item, types, context, fatal, optional, seen)
        return
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        if key == "bool" and isinstance(value, dict):
            for subkey, sub in value.items():
                sub_ctx = {
                    "must": "required", "filter": "required",
                    "should": "optional", "must_not": "negated",
                }.get(subkey, "optional")
                _collect_failed(sub, types, sub_ctx, fatal, optional, seen)
            continue
        if key in _CLAUSE_FIELD_KEYS and isinstance(value, dict):
            for field, spec in value.items():
                _check_ref(str(field), spec, types, context, fatal, optional, seen)
            continue
        if key == "exists" and isinstance(value, dict) and value.get("field"):
            _check_ref(str(value["field"]), None, types, context, fatal, optional, seen)
            continue
        if key == "multi_match" and isinstance(value, dict):
            for field in value.get("fields") or []:
                _check_ref(str(field), value.get("query"), types, context, fatal, optional, seen)
            continue
        if key == "field" and isinstance(value, str):
            _check_ref(value, None, types, context, fatal, optional, seen)
            continue
        _collect_failed(value, types, context, fatal, optional, seen)


def failed_field_refs_detail(case_id: str, query: Any) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """(fatal, optional) failed refs; ([], []) when the mapping is unknown."""
    types = _mapping_field_types(case_id)
    if not types:
        return [], []
    fatal: list[dict[str, str]] = []
    optional: list[dict[str, str]] = []
    _collect_failed(query, types, "required", fatal, optional, set())
    return fatal, optional


def failed_field_refs(case_id: str, query: Any) -> list[dict[str, str]]:
    """P1: required-context refs that CANNOT match (unknown field / bad value).

    Returns [] when the mapping is unknown (ES down / no index) — validation
    must never turn into a false failure. A non-empty list means "do not
    present this as 0 hits"; callers surface it as a degraded hard-signal.
    """
    return failed_field_refs_detail(case_id, query)[0]


def validate_aggs(aggs: Any, depth: int = 0) -> None:
    """Allowlist aggregation trees (terms/date_histogram/composite/…)."""
    if not isinstance(aggs, dict) or not aggs:
        raise ESQueryError("aggs must be a non-empty object")
    if len(aggs) > MAX_AGGS:
        raise ESQueryError(f"too many aggregations (max {MAX_AGGS})")
    for name, spec in aggs.items():
        if not isinstance(spec, dict):
            raise ESQueryError(f"agg {name!r} must be an object")
        types = [k for k in spec if k in _AGG_TYPES]
        if len(types) != 1:
            raise ESQueryError(
                f"agg {name!r} must have exactly one type from {sorted(_AGG_TYPES)}"
            )
        agg_type = types[0]
        body = spec[agg_type]
        if not isinstance(body, dict):
            raise ESQueryError(f"{agg_type} body must be an object")
        if "script" in body or "scripted_metric" in spec:
            raise ESQueryError("aggregation scripts are not allowed")
        unknown_body = set(body) - _AGG_BODY_KEYS[agg_type]
        if unknown_body:
            raise ESQueryError(
                f"unsupported {agg_type} options: {sorted(unknown_body)}"
            )
        if agg_type == "composite":
            sources = body.get("sources")
            if not isinstance(sources, list) or not sources:
                raise ESQueryError("composite requires sources")
            for src in sources:
                if not isinstance(src, dict) or len(src) != 1:
                    raise ESQueryError("composite source must name one field")
                for _fname, fspec in src.items():
                    if not isinstance(fspec, dict):
                        raise ESQueryError("composite source spec must be an object")
                    source_types = [k for k in fspec if k in _COMPOSITE_SOURCES]
                    if len(source_types) != 1:
                        raise ESQueryError(
                            "composite sources support terms/date_histogram/histogram"
                        )
                    inner = fspec[source_types[0]]
                    if not isinstance(inner, dict) or "script" in inner:
                        raise ESQueryError("composite source scripts are not allowed")
                    unknown_inner = set(inner) - _COMPOSITE_SOURCE_KEYS[source_types[0]]
                    if unknown_inner:
                        raise ESQueryError(
                            f"unsupported composite source options: {sorted(unknown_inner)}"
                        )
            if "size" in body:
                try:
                    if not 1 <= int(body["size"]) <= 1000:
                        raise ESQueryError("composite size must be 1..1000")
                except (TypeError, ValueError):
                    raise ESQueryError("composite size must be an integer") from None
            after = body.get("after")
            if after is not None and not isinstance(after, dict):
                raise ESQueryError("composite after must be an object")
        elif not isinstance(body, dict):
            raise ESQueryError(f"{agg_type} body must be an object")
        sub = spec.get("aggs")
        if sub is not None:
            validate_aggs(sub, depth + 1)


def _shape_hit(src: dict[str, Any]) -> dict[str, Any]:
    fields = src.get("fields") if isinstance(src.get("fields"), dict) else {}
    hit: dict[str, Any] = {
        "family": str(src.get("family") or ""),
        "file": str(src.get("file") or ""),
        "line": str(src.get("line") or ""),
        "text": str(src.get("text") or ""),
        "fields": fields,
        "terms_list": [],
    }
    for key in ("host", "user", "event_id", "ts", "ts_src", "ts_precision"):
        value = src.get(key)
        if value not in (None, ""):
            hit[key] = str(value)[:200]
    for key in ("ts_tz_assumed", "ts_year_assumed"):
        if src.get(key) is True:
            hit[key] = True
    return hit


def _client_and_index(case_id: str):
    from nexus.langgraph.case_index import _client, es_available, index_name

    if not es_available():
        raise ESQueryError(
            "Elasticsearch unavailable — Mode 2/3 require ES (no CSV fallback "
            "for the ES-native surface)"
        )
    return _client, index_name(case_id)


def es_fields(case_id: str) -> dict[str, Any]:
    """Full per-family field catalog + family counts (no curation caps)."""
    if not case_id:
        raise ESQueryError("case_id is required")
    client, name = _client_and_index(case_id)
    with client() as c:
        head = c.head(f"/{name}")
        if head.status_code != 200:
            raise ESQueryError(f"index missing: {name} (run the pipeline / nexus index rebuild)")
        mapping_resp = c.get(f"/{name}/_mapping")
        if mapping_resp.status_code >= 400:
            raise ESQueryError(f"mapping failed: {mapping_resp.status_code}")
        props = (
            (mapping_resp.json().get(name) or {}).get("mappings") or {}
        ).get("properties") or {}
        agg = c.post(
            f"/{name}/_search",
            json={
                "size": 0,
                "track_total_hits": True,
                "aggs": {"families": {"terms": {"field": "family", "size": 1000}}},
            },
        )
        families: dict[str, int] = {}
        if agg.status_code < 400:
            for bucket in (
                ((agg.json().get("aggregations") or {}).get("families") or {}).get("buckets")
                or []
            ):
                families[str(bucket.get("key"))] = int(bucket.get("doc_count") or 0)

    def _type_of(spec: Any) -> str:
        if not isinstance(spec, dict):
            return "unknown"
        base = str(spec.get("type") or "object")
        subs = spec.get("fields") or {}
        if isinstance(subs, dict) and "kw" in subs:
            return f"{base}(kw)"
        return base

    core = sorted(
        ({"field": key, "type": _type_of(spec)} for key, spec in props.items()
         if key != "fields"),
        key=lambda row: row["field"],
    )
    parsed = (
        (props.get("fields") or {}).get("properties")
        or {}
    )
    return {
        "case_id": case_id,
        "index": name,
        "families": families,
        "core_fields": core,
        "parsed_columns": sorted(
            ({"field": key, "type": _type_of(spec)} for key, spec in parsed.items()),
            key=lambda row: row["field"],
        ),
        "ts_note": (
            "ts is the canonical event time (ts_src=event|synthesized, "
            "ts_tz_assumed/ts_year_assumed flags mark policy assumptions); "
            "use es_search range on ts for time filters"
        ),
    }


def _with_lenient(node: Any) -> Any:
    """Return a copy of the query with ``lenient: true`` on every multi_match.

    Schema v5 types numeric/date columns explicitly; without lenient a phrase
    query spanning ``fields.*`` dies with a shard 400 on those columns. Lenient
    only suppresses per-field parse errors — matching itself is unchanged.
    """
    if isinstance(node, list):
        return [_with_lenient(item) for item in node]
    if not isinstance(node, dict):
        return node
    out: dict[str, Any] = {}
    for key, value in node.items():
        if key == "multi_match" and isinstance(value, dict):
            patched = dict(value)
            patched.setdefault("lenient", True)
            out[key] = patched
        else:
            out[key] = _with_lenient(value)
    return out


def es_search(
    case_id: str,
    query: dict[str, Any],
    *,
    size: int = DEFAULT_SIZE,
    sort: list[Any] | None = None,
    search_after: list[Any] | None = None,
) -> dict[str, Any]:
    """One allowlisted ES search; exact totals and a labelled next cursor."""
    if not case_id:
        raise ESQueryError("case_id is required")
    validate_query(query)
    fatal, optional_failed = failed_field_refs_detail(case_id, query)
    if fatal:
        # P1: a query that cannot match must never read as "0 hits on real
        # evidence" — return an explicit degraded hard-signal instead.
        return {
            "case_id": case_id,
            "error": "query references fields that cannot match: "
                     + ", ".join(f"{f['field']} ({f['reason']})" for f in fatal[:5]),
            "degraded": True,
            "failed_terms": fatal,
            "total": 0,
            "returned": 0,
            "has_more": False,
            "next_search_after": None,
            "backend": "elasticsearch",
            "hits": [],
        }
    try:
        size_i = int(size)
    except (TypeError, ValueError):
        raise ESQueryError("size must be an integer") from None
    if not 1 <= size_i <= MAX_SIZE:
        raise ESQueryError(f"size must be 1..{MAX_SIZE}")
    if sort is not None:
        if not isinstance(sort, list) or len(sort) > 4:
            raise ESQueryError("sort must be a list of at most 4 entries")
        for entry in sort:
            if isinstance(entry, str):
                continue
            if not isinstance(entry, dict) or len(entry) != 1:
                raise ESQueryError("sort entries must be 'field' or {field: {...}}")
            for _f, spec in entry.items():
                if isinstance(spec, dict) and set(spec) - {"order", "missing", "unmapped_type"}:
                    raise ESQueryError("unsupported sort options")
    body: dict[str, Any] = {
        "size": size_i,
        "query": query,
        "track_total_hits": True,
    }
    if sort:
        body["sort"] = sort
    else:
        # Always provide a deterministic cursor sort so paging works even
        # when the caller did not specify one (review fix).
        body["sort"] = ["_doc"]
    if search_after:
        body["search_after"] = search_after
    body["query"] = _with_lenient(body["query"])

    client, name = _client_and_index(case_id)
    with client() as c:
        head = c.head(f"/{name}")
        if head.status_code != 200:
            raise ESQueryError(f"index missing: {name} (run the pipeline / nexus index rebuild)")
        r = c.post(f"/{name}/_search", json=body)
        if r.status_code >= 400:
            raise ESQueryError(f"ES search failed: {r.status_code} {r.text[:300]}")
        data = r.json()
    hits_raw = (data.get("hits") or {}).get("hits") or []
    total = int(((data.get("hits") or {}).get("total") or {}).get("value") or 0)
    hits = [_shape_hit(row.get("_source") or {}) for row in hits_raw]
    next_cursor = hits_raw[-1].get("sort") if hits_raw else None
    # has_more is about THIS page being full, not the global total (the old
    # len(hits) < total made the final page look paginated — review fix).
    has_more = len(hits) == size_i
    result = {
        "case_id": case_id,
        "total": total,
        "returned": len(hits),
        "has_more": has_more,
        "next_search_after": next_cursor if has_more else None,
        "took_ms": data.get("took"),
        "backend": "elasticsearch",
        "hits": hits,
    }
    if optional_failed:
        # Honesty: the query matched truthfully, but these should/must_not refs
        # can never match — surfaced instead of silently behaving as no-ops.
        result["failed_terms_optional"] = optional_failed
    return result


def es_aggregate(case_id: str, aggs: dict[str, Any], query: dict[str, Any] | None = None,
                 *, size: int = 0) -> dict[str, Any]:
    """ES-native aggregation with composite paging support."""
    if not case_id:
        raise ESQueryError("case_id is required")
    validate_aggs(aggs)
    if query is not None:
        validate_query(query)
        failed = failed_field_refs(case_id, query)
        if failed:
            raise ESQueryError(
                "aggregation query references fields that cannot match: "
                + ", ".join(f"{f['field']} ({f['reason']})" for f in failed[:5])
            )
    body: dict[str, Any] = {
        "size": max(0, min(int(size or 0), 10)),
        "track_total_hits": True,
        "aggs": aggs,
        "query": _with_lenient(query) if query else {"match_all": {}},
    }
    client, name = _client_and_index(case_id)
    with client() as c:
        r = c.post(f"/{name}/_search", json=body)
        if r.status_code >= 400:
            raise ESQueryError(f"ES aggregation failed: {r.status_code} {r.text[:300]}")
        data = r.json()
    out = dict(data.get("aggregations") or {})
    next_key = None
    for spec in out.values():
        if isinstance(spec, dict) and spec.get("after_key") is not None:
            next_key = spec["after_key"]
            break
    return {
        "case_id": case_id,
        "backend": "elasticsearch",
        "took_ms": data.get("took"),
        "aggregations": out,
        "next_after_key": next_key,
    }


def es_sample(
    case_id: str,
    family: str = "",
    field: str = "",
    value: str = "",
    n: int = 12,
) -> dict[str, Any]:
    """Representative rows from ES (family/field filter), spread over time."""
    if not case_id:
        raise ESQueryError("case_id is required")
    count = max(1, min(int(n or 12), 60))
    filt: list[dict[str, Any]] = []
    if family:
        filt.append({"term": {"family": family.lower()}})
    if field and value:
        key = field.lower()
        alias = {"event": "event_id"}.get(key, key)
        should: list[dict[str, Any]] = [
            {"term": {alias: value.lower()}},
            {"match_phrase": {"text": value}},
        ]
        parsed_key = None
        try:
            from nexus.langgraph.case_index import fields_property_names

            for name in fields_property_names(case_id):
                if name.lower() == key:
                    parsed_key = f"fields.{name}.kw"
                    break
        except Exception:  # noqa: BLE001
            parsed_key = None
        if parsed_key:
            should.insert(1, {"term": {parsed_key: value}})
        filt.append({"bool": {"should": should, "minimum_should_match": 1}})
    query: dict[str, Any] = {"bool": {"filter": filt}} if filt else {"match_all": {}}

    fetch = min(2000, max(400, count * 40))
    result = es_search(
        case_id, query, size=min(fetch, MAX_SIZE),
        sort=[{"ts": {"order": "asc", "missing": "_last", "unmapped_type": "date"}}, {"_doc": "asc"}],
    )
    hits = result.get("hits") or []
    matched_total = int(result.get("total", 0) or 0)
    step = max(1, len(hits) // count) if hits else 1
    picked = hits[::step][:count] if hits else []
    return {
        "case_id": case_id,
        "family": family,
        "field": field,
        "value": value,
        "backend": "elasticsearch",
        "matched": matched_total,
        "sampled": len(picked),
        "spread_every": step,
        # Honesty: for very large sets the spread is over the fetched window
        # (ts-ascending), not the whole corpus.
        "window_truncated": matched_total > len(hits),
        "window_rows": len(hits),
        "hits": picked,
        "note": (
            "sample rows are context — findings still cite the audit trail "
            "(FD-001); use es_search search_after for complete enumeration"
        ),
    }
