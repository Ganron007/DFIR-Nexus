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
PAGE_SIZE = 1000
MAX_AGGS = 40
AGG_PREVIEW_MAX = 10
_READ_SIZE_MINIMUM = {"es_search": 1, "es_aggregate": 0}

_QUERY_KEYS = {
    "bool", "term", "terms", "range", "match", "match_phrase", "multi_match",
    "wildcard", "exists", "prefix", "match_all", "match_none", "ids", "regexp",
}
_BOOL_KEYS = {"must", "should", "must_not", "filter", "minimum_should_match"}
#: The options each single-field clause takes beside its `value`, in the field's object
#: (`{"wildcard": {"f": {"value": "*x*", "case_insensitive": true}}}`). One definition: the validator allows exactly
#: these and the normalizer moves exactly these when a model writes them beside the field (D386).
FIELD_CLAUSE_OPTIONS: dict[str, frozenset[str]] = {
    **dict.fromkeys(("term", "match", "match_phrase", "prefix", "wildcard"), frozenset({"boost", "case_insensitive"})),
    "regexp": frozenset({"case_insensitive", "flags"}),
}
#: Clauses whose field object holds the pattern under `value` (match/match_phrase take `query`).
VALUE_CLAUSES = frozenset({"term", "prefix", "wildcard", "regexp"})
_RANGE_BODY_KEYS = {"gte", "gt", "lte", "lt", "format", "boost", "time_zone"}
_AGG_TYPES = {
    "terms", "date_histogram", "cardinality", "composite", "min", "max",
    "avg", "sum", "value_count", "histogram", "range",
    # D389: the model counts a condition with `filter` and buckets time with `date_range` (T01, T04).
    "filter", "date_range",
    # D405: a time span is `stats` on `ts`, several named conditions are `filters`, example rows per bucket are
    # `top_hits` (T21 Mode 3: eight calls refused).
    "stats", "filters", "top_hits",
}
#: Aggregations that read a field's doc values: a `text` field needs its `.kw` keyword sub-field (D391).
DOC_VALUE_AGGS = frozenset({"terms", "cardinality", "value_count"})
#: Aggregations that compute on numbers or dates: a `text` field cannot be their input (D405: `sum` on text `bytes`).
NUMERIC_AGGS = frozenset({"sum", "avg", "min", "max", "stats", "histogram", "range"})
#: Options a `terms` query takes beside its one field (`{"terms": {"f": [..], "boost": 2}}` is valid ES; D405).
TERMS_OPTIONS = frozenset({"boost"})
#: Most example rows a `top_hits` bucket may return.
TOP_HITS_MAX = 20
_COMPOSITE_SOURCES = {"terms", "date_histogram", "histogram"}
# Strict per-type body allowlists: anything else (script!) is rejected.
_AGG_BODY_KEYS = {
    "terms": {"field", "size", "order", "missing", "min_doc_count",
              "shard_size", "include", "exclude"},
    "date_histogram": {"field", "calendar_interval", "fixed_interval",
                       "time_zone", "format", "min_doc_count", "missing",
                       "order", "offset", "extended_bounds", "hard_bounds"},
    "date_range": {"field", "ranges", "format", "time_zone", "keyed", "missing"},
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
    "stats": {"field", "missing", "format"},
    "filters": {"filters", "other_bucket", "other_bucket_key"},
    "top_hits": {"size", "_source", "sort"},
}
_COMPOSITE_SOURCE_KEYS = {
    # missing_bucket keeps the documents a source field is absent from (a task registration names no
    # program, D244); ES 8 composite sources take it in place of `missing`. D406: `missing` and `size` were
    # allowed here and ES 8.17.4 refuses both in a source (measured 2026-10-26: a raw 400 "[terms] unknown
    # field [size]" on T18 Mode 3); a source's size is the composite's own `size`.
    "terms": {"field", "order", "missing_bucket"},
    "date_histogram": {"field", "calendar_interval", "fixed_interval",
                       "time_zone", "format", "order", "offset", "missing_bucket"},
    "histogram": {"field", "interval", "order", "offset", "missing_bucket"},
}


class ESQueryError(ValueError):
    """Unsupported or unsafe ES query shape."""


def is_unknown_field_hint(error: str) -> bool:
    """The recoverable schema hint, shared by run review and refused-call replay.

    A value/type failure can also say "cannot match"; it must remain an error.
    """
    return ("cannot match" in error and "unknown_field" in error
            and "ESQueryError" not in error and "cannot be a " not in error)


def read_request_size(size: Any, *, tool: str) -> int:
    """One size check for the model loop and the native read surface."""
    minimum = _READ_SIZE_MINIMUM[tool]
    try:
        parsed = int(size)
    except (TypeError, ValueError):
        raise ESQueryError("size must be an integer") from None
    if parsed < minimum:
        raise ESQueryError(f"size must be at least {minimum}")
    return parsed


def _validate_request_sort(sort: Any) -> None:
    if sort is None:
        return
    if not isinstance(sort, list) or len(sort) > 4:
        raise ESQueryError("sort must be a list of at most 4 entries")
    for entry in sort:
        if isinstance(entry, str):
            continue
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ESQueryError("sort entries must be 'field' or {field: {...}}")
        for spec in entry.values():
            if isinstance(spec, dict) and set(spec) - {"order", "missing", "unmapped_type"}:
                raise ESQueryError("unsupported sort options")


def _with_family_filter(query: Any, family: str) -> Any:
    """Conjoin every request-level scope with the supplied query; never replace it."""
    if not isinstance(family, str):
        raise ESQueryError("family must be a string")
    clauses: list[Any] = []
    if family:
        clauses.append({"term": {"family": family.lower()}})
    if not clauses:
        return query
    body = {"filter": clauses}
    if query is not None:
        body["must"] = [query]
    return {"bool": body}


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
        low_field = field.lower()
        if low_field in ("script", "_script") or low_field.startswith(("script.", "_script.")) or low_field.endswith((".script", "._script")):
            raise ESQueryError("field names cannot contain scripts")
        if isinstance(spec, dict):
            unknown = set(spec) - {"value"} - FIELD_CLAUSE_OPTIONS[key]
            unknown |= {k for k in spec if k == "script"}
            if unknown:
                raise ESQueryError(f"unsupported {key} options: {sorted(unknown)}")
    elif key == "terms":
        named = {k: v for k, v in value.items() if k not in TERMS_OPTIONS} if isinstance(value, dict) else {}
        if not isinstance(value, dict) or len(named) != 1:
            raise ESQueryError("terms takes exactly one field")
        (field, values), = named.items()
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
        if not isinstance(value, dict):
            raise ESQueryError("exists requires {field: name}")
        # `exists` supports only `field`; `missing`/`boost` are written by models
        # and are not valid there — the normalizer drops them, and this is the
        # backstop for a caller that bypasses it.
        unknown = set(value) - {"field"}
        if unknown:
            raise ESQueryError(f"unsupported exists options: {sorted(unknown)}")
        if not isinstance(value.get("field"), str):
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
        unknown = set(spec) - {"value"} - FIELD_CLAUSE_OPTIONS["regexp"]
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

_CLAUSE_FIELD_KEYS = ("term", "terms", "match", "match_phrase", "prefix", "wildcard", "regexp", "range")
_NUMERIC_ES = {
    "long", "integer", "short", "byte", "double", "float", "half_float", "scaled_float",
}
_DATE_ES = {"date", "date_nanos"}
_BOOL_ES = {"boolean"}


def _field_types(case_id: str) -> dict[str, str]:
    """field path -> ES type, plus this index's own keyword sub-fields.

    ``_mapping_field_types`` walks ``.fields`` already, so a ``text`` field's
    ``.kw`` appears as its own entry — which is exactly what the normalizer needs
    to decide whether it can offer a keyword sub-field.
    """
    return _mapping_field_types(case_id)


def _mapping_field_types(case_id: str) -> dict[str, str]:
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
        if not (s[:4].isdigit() and ("-" in s or s.isdigit())):
            return False
        # D405: the calendar date must exist: `2021-13-01` passed the shape check and ES answered a raw 400.
        parts = s[:10].split("-")
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            try:
                from datetime import date

                date(int(parts[0]), int(parts[1]), int(parts[2]))
            except ValueError:
                return False
        return True
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
        elif isinstance(spec, list):
            # A `terms` list: ES fails the whole query on one value the field cannot hold (D396).
            values = list(spec)
        elif spec is not None:
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
                if subkey == "should" and context == "required" and _should_required(value):
                    _collect_required_should(sub, types, fatal, optional, seen)
                    continue
                sub_ctx = {
                    "must": "required", "filter": "required",
                    "should": "optional", "must_not": "negated",
                }.get(subkey, "optional")
                _collect_failed(sub, types, sub_ctx, fatal, optional, seen)
            continue
        if key in _CLAUSE_FIELD_KEYS and isinstance(value, dict):
            for field, spec in value.items():
                if key == "terms" and field in TERMS_OPTIONS:
                    continue
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


def similar_fields(field: str, types: dict[str, str], *, limit: int = 4) -> list[str]:
    """Fields this index has under the same name as ``field``, ignoring case and separators.

    Matched on the full name, then on its last segment; fields in the same namespace come first.
    These are offered, never substituted: ``ecs.event_data.rule_name`` matches the Sysmon
    ``ecs.winlog.event_data.RuleName``, which is not the detection name the model meant.
    """
    def squash(text: str) -> str:
        return "".join(ch for ch in text.lower() if ch.isalnum())

    real = [f for f in types if not f.endswith((".kw", ".wc"))]
    whole = squash(field)
    last = squash(field.rsplit(".", 1)[-1])
    exact = [f for f in real if squash(f) == whole]
    by_name = [f for f in real if f not in exact and squash(f.rsplit(".", 1)[-1]) == last]
    head = field.split(".", 1)[0]
    by_name.sort(key=lambda f: (f.split(".", 1)[0] != head, len(f), f))
    return [*exact, *by_name][:limit]


def _should_required(bool_body: dict[str, Any]) -> bool:
    """True when a bool matches only if one of its ``should`` clauses does.

    Elasticsearch requires one ``should`` match when the bool has no ``must``/``filter`` clause, or
    when ``minimum_should_match`` asks for one.
    """
    if not bool_body.get("should"):
        return False
    if not (bool_body.get("must") or bool_body.get("filter")):
        return True
    try:
        return int(str(bool_body.get("minimum_should_match") or 0).rstrip("%") or 0) > 0
    except ValueError:
        return True


def _collect_required_should(
    clauses: Any, types: dict[str, str],
    fatal: list[dict[str, str]], optional: list[dict[str, str]], seen: set[str],
) -> None:
    """``should`` clauses of a bool that needs one of them: unmatchable only when all of them are.

    A bool of three ``should`` clauses on fields the case does not have can never match, and it
    used to return 0 rows with no error (2026-10-14, Mode 1 run 4: ``ecs.event_data.rule_name``,
    a near-miss of ``ecs.rule.name``). If any clause can match, the failed ones stay optional.
    """
    items = clauses if isinstance(clauses, list) else [clauses]
    per_clause: list[tuple[list[dict[str, str]], list[dict[str, str]]]] = []
    for item in items:
        clause_fatal: list[dict[str, str]] = []
        clause_optional: list[dict[str, str]] = []
        _collect_failed(item, types, "required", clause_fatal, clause_optional, set())
        per_clause.append((clause_fatal, clause_optional))
    unmatchable = bool(per_clause) and all(clause_fatal for clause_fatal, _ in per_clause)
    context = "required" if unmatchable else "optional"
    for clause_fatal, clause_optional in per_clause:
        for ref in [*({**r, "context": context} for r in clause_fatal), *clause_optional]:
            key = f"{ref['field']}\x00{ref.get('context')}"
            if key in seen:
                continue
            seen.add(key)
            (fatal if ref.get("context") == "required" else optional).append(ref)


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


def _validate_agg_structure(aggs: Any, depth: int = 0) -> None:
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
        if agg_type in ("filter", "filters"):
            # A `filter` aggregation's body is a query clause, a `filters` one names several: the query allowlist
            # applies to each.
            if agg_type == "filter":
                validate_query(body)
            else:
                named = body.get("filters")
                queries = list(named.values()) if isinstance(named, dict) else named
                if not isinstance(queries, list) or not queries:
                    raise ESQueryError("filters needs `filters`: an object of named query clauses")
                unknown_body = set(body) - _AGG_BODY_KEYS["filters"]
                if unknown_body:
                    raise ESQueryError(f"unsupported filters options: {sorted(unknown_body)}")
                for query in queries:
                    validate_query(query)
            sub = spec.get("aggs")
            if sub is not None:
                _validate_agg_structure(sub, depth + 1)
            continue
        if agg_type == "top_hits":
            if spec.get("aggs") is not None:
                raise ESQueryError("top_hits cannot have sub-aggregations")
            unknown_body = set(body) - _AGG_BODY_KEYS["top_hits"]
            if unknown_body:
                raise ESQueryError(f"unsupported top_hits options: {sorted(unknown_body)}")
            try:
                if not 1 <= int(body.get("size", 3)) <= TOP_HITS_MAX:
                    raise ESQueryError(f"top_hits size must be 1..{TOP_HITS_MAX}")
            except (TypeError, ValueError):
                raise ESQueryError("top_hits size must be an integer") from None
            continue
        if agg_type != "composite" and not body.get("field"):
            # ES answers a field-less metric with a raw 400 (D395: `{"value_count": {}}` to count rows).
            raise ESQueryError(
                f"{agg_type} needs a `field`: to count the rows a query matches, read `total` in the "
                "es_aggregate result (exact)")
        if agg_type in ("range", "date_range") and not (isinstance(body.get("ranges"), list) and body["ranges"]):
            # T01 Mode 3 asked `date_range` with no ranges for the time span: ES answers with a raw 400.
            raise ESQueryError(
                f"{agg_type} needs a non-empty `ranges` list; for the earliest and latest time use "
                '{"first": {"min": {"field": "ts"}}, "last": {"max": {"field": "ts"}}}')
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
            _validate_agg_structure(sub, depth + 1)


# ES metadata and search pseudo-fields are distinct from unknown data fields.
# `_type` is absent in ES 8 and is never aliased to an artifact family.
_ES_METADATA_FIELDS = frozenset({
    "_id", "_index", "_routing", "_source", "_field_names", "_ignored", "_size",
    "_doc_count", "_tier", "_score", "_doc", "_shard_doc", "_seq_no", "_primary_term", "_version",
})


def _aggregation_fields(aggs: dict[str, Any]):
    """Fields in an already structurally validated aggregation tree."""
    for spec in aggs.values():
        kind = next(key for key in spec if key in _AGG_TYPES)
        body = spec[kind]
        if isinstance(body.get("field"), str):
            yield body["field"]
        if kind == "composite":
            for source in body["sources"]:
                for source_spec in source.values():
                    for inner in source_spec.values():
                        if isinstance(inner, dict) and isinstance(inner.get("field"), str):
                            yield inner["field"]
        if isinstance(spec.get("aggs"), dict):
            yield from _aggregation_fields(spec["aggs"])


def _validate_agg_metadata(aggs: dict[str, Any]) -> None:
    for field in _aggregation_fields(aggs):
        if field.startswith("_"):
            raise ESQueryError(
                f"aggregation on metadata field `{field}` is not allowed: to count the rows a query matches, "
                "read `total` in the es_aggregate result (exact); aggregate a data field otherwise")


def validate_aggs(aggs: Any, depth: int = 0) -> None:
    """Strict raw ES validation; scripts/options/limits and metadata guards remain enforced."""
    _validate_agg_structure(aggs, depth)
    _validate_agg_metadata(aggs)


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
    # The ECS subject leaves (operator decision 2026-10-12): the evidence row takes its account,
    # address, process, file and registry from these (nexus.langgraph.subject). The whole ECS block
    # is not carried: only the leaves the subject rule reads.
    from nexus.langgraph.subject import ecs_leaves
    ecs = ecs_leaves(src.get("ecs"))
    if ecs:
        hit["ecs"] = ecs
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
    """Full per-family field catalog + family counts, with D35 population.

    D35 (WO-KM1 item 2): the catalog must not present **declared** columns as
    **present**. ES reports which columns the mapping types - every one the registry
    declares - and `parsed_columns` still lists them so validation keeps working.
    What is added here is what is actually **filled**: an ES ``terms`` aggregation
    per family on the columns the registry maps to that family, so a caller can see
    "listened" as populated for `zeek` and absent for `authlog`.

    ``populated_columns`` is the honest half. It is empty (and says so) when no
    aggregation ran, never silently equal to ``parsed_columns``.
    """
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

        # D35 (item 2): per family, which `fields.*` columns actually have a value.
        # ONE ES request per family: a `filters` aggregation with one `exists`
        # filter per column. The previous per-column request loop was O(columns)
        # round-trips per family (hundreds), and quoted names with spaces must be
        # sent verbatim (a spaced field path is valid; verified).
        populated: dict[str, dict[str, int]] = {}
        for fam in families:
            cols = _columns_for_family(fam)
            if not cols:
                continue
            filters: dict[str, Any] = {
                column: {"exists": {"field": f"fields.{column}"}} for column in cols
            }
            try:
                res = c.post(
                    f"/{name}/_search",
                    json={
                        "size": 0,
                        "query": {"term": {"family": fam}},
                        "aggs": {"pop": {"filters": {"filters": filters}}},
                    },
                )
            except Exception:  # noqa: BLE001 - one family must not lose the rest
                continue
            if res.status_code >= 400:
                continue
            buckets = (
                ((res.json().get("aggregations") or {}).get("pop") or {}).get("buckets")
                or {}
            )
            per = {
                column: int((bucket or {}).get("doc_count") or 0)
                for column, bucket in buckets.items()
                if int((bucket or {}).get("doc_count") or 0) > 0
            }
            if per:
                populated[fam] = per

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
        # D35: the honest half. `parsed_columns` is what the mapping TYPES (every
        # registry column for every family); this is what is FILLED in this case.
        "populated_columns": populated,
        "population_note": (
            "populated_columns is measured from the case's own documents. "
            "parsed_columns is every column the index is typed for, which includes "
            "columns this case does not have - query a parsed column on a family "
            "that is absent from populated_columns and it matches nothing."
        ),
        "ts_note": (
            "ts is the canonical event time (ts_src=event|synthesized, "
            "ts_tz_assumed/ts_year_assumed flags mark policy assumptions); "
            "use es_search range on ts for time filters"
        ),
    }


def _columns_for_family(family: str) -> list[str]:
    """The registry columns declared for `family`, as ``fields.<Name>`` names.

    WO-R0F item 2 (D35): no space/punctuation skip and no 80-column cut. ES indexes
    every column name verbatim (a spaced name like ``Event Data`` is a valid field
    path — verified), so dropping spaced/punctuated columns silently lost them from
    the population measurement.
    """
    try:
        from nexus.knowledge.query_validation import expand_families, load_field_registry

        cols = load_field_registry()
        wanted = set(expand_families([family]))
        found = []
        for name, info in cols.items():
            fams = {str(f).lower() for f in (info.get("families") or [])}
            if fams and (fams & wanted):
                found.append(name)
        return sorted(found)
    except Exception:  # noqa: BLE001 - the population probe is best-effort
        return []


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
    family: str = "",
) -> dict[str, Any]:
    """One allowlisted ES search; exact totals and a labelled next cursor.

    The body is **normalized first** (WO-R1F item 2): an LLM writes a JSON-string
    query, a string sort, several top-level clauses or plain ECS names, and ES
    rejects all four. Every rewrite is reported under ``normalized`` — the
    operator's rule is "accept and normalize; never fail silently".
    """
    from nexus.langgraph.query_normalize import (
        normalize_query,
        normalize_sort,
    )

    if not case_id:
        raise ESQueryError("case_id is required")
    types = _field_types(case_id)
    query = _with_family_filter(query, family)
    query, q_notes = normalize_query(query, field_types=types)
    sort, s_notes = normalize_sort(sort, types)
    notes = [*q_notes, *s_notes]
    validate_query(query)
    patterns = _patterns_on_non_strings(query, types)
    if patterns:
        raise ESQueryError("cannot search: " + "; ".join(patterns))
    fatal, optional_failed = failed_field_refs_detail(case_id, query)
    if fatal:
        # P1: a query that cannot match must never read as "0 hits on real
        # evidence" — return an explicit degraded hard-signal instead. An unknown
        # field carries the fields this index has under the same name, so the next
        # call can be right (2026-10-14: two of Mode 1's three rounds were spent on
        # `details` and `ecs.event_data.command_line`).
        for ref in fatal:
            if ref.get("reason") == "unknown_field":
                ref["did_you_mean"] = similar_fields(ref["field"], types)
        return {
            "case_id": case_id,
            "error": "query references fields that cannot match: "
                     + ", ".join(
                         f"{f['field']} ({f['reason']}"
                         + (f"; this index has {', '.join(f['did_you_mean'])}" if f.get("did_you_mean")
                            else "") + ")"
                         for f in fatal[:5])
                     + ". To find a phrase in any column, search the row text: "
                     '{"match_phrase":{"text":"<phrase>"}}.',
            "degraded": True,
            "failed_terms": fatal,
            "total": 0,
            "returned": 0,
            "has_more": False,
            "next_search_after": None,
            "backend": "elasticsearch",
            "hits": [],
        }
    size_i = read_request_size(size, tool="es_search")
    _validate_request_sort(sort)
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
    if notes:
        # "Never fail silently": every rewrite of the caller's body is reported.
        result["normalized"] = notes
    if optional_failed:
        # Honesty: the query matched truthfully, but these should/must_not refs
        # can never match — surfaced instead of silently behaving as no-ops.
        result["failed_terms_optional"] = optional_failed
    # WO-CS1 item 5: a query that matched nothing and names a field NOT populated
    # in this case returns that fact, with the families that do fill it, so the LLM
    # can correct itself instead of reading "not found" as "not present".
    if total == 0:
        note = _unpopulated_field_note(case_id, query)
        if note:
            result["field_population_note"] = note
        diagnosis = _zero_hit_diagnosis(case_id, query)
        if diagnosis:
            result["zero_hit"] = diagnosis
    elif total > FLOOD_ROWS and not search_after:
        composition = _flood_composition(case_id, query, total)
        if composition:
            result["flood"] = composition
    return result


def _unpopulated_field_note(case_id: str, query: dict[str, Any]) -> str:
    """Explain a zero-hit query that named a field this case does not fill.

    Returns "" when the named fields are populated (so a zero is a real zero) or
    when it cannot be certain. Never raises.
    """
    try:
        from nexus.knowledge.query_validation import load_field_registry

        refs = _field_refs(query)
        if not refs:
            return ""
        registry = load_field_registry()
        populated: dict[str, set[str]] = {}
        fills: dict[str, set[str]] = {}
        for ref in refs:
            rel = ref[len("fields."):] if ref.startswith("fields.") else ref
            base = rel[:-3] if rel.endswith(".kw") else rel
            info = (registry.get(base) or registry.get(base.lower())
                    or registry.get(base.upper()) or {})
            filled = {str(f).lower() for f in (info.get("populated_in") or [])}
            fams = {str(f).lower() for f in (info.get("families") or [])}
            populated[ref] = filled
            fills[ref] = fams
        if not any(populated.values()):
            return ""
        client, name = _client_and_index(case_id)
        with client() as c:
            agg = c.post(f"/{name}/_search", json={
                "size": 0,
                "aggs": {"fams": {"terms": {"field": "family", "size": 200}}},
            })
        case_fams: set[str] = set()
        if agg.status_code < 400:
            for b in ((agg.json().get("aggregations") or {}).get("fams") or {}).get("buckets") or []:
                case_fams.add(str(b.get("key")).lower())
        lines: list[str] = []
        for ref in refs:
            filled = populated[ref]
            if filled and not (filled & case_fams):
                who = ", ".join(sorted(fills[ref])[:6]) or "other families"
                lines.append(
                    f"{ref} is not populated by any family in this case "
                    f"(filled by: {who})")
        return "; ".join(lines)
    except Exception:  # noqa: BLE001 - feedback is best-effort, never fatal
        return ""


#: More rows than this and a page of them says nothing about what they hold (IC-9). 10,000 is Elasticsearch's own
#: result window; a search over it is answered with what the rows are made of, by family and by event.
FLOOD_ROWS = 10_000
#: The most clauses of one zero-hit query that are counted one by one.
_DIAGNOSED_CLAUSES = 8
_VALUE_CLAUSES = ("term", "terms", "wildcard", "prefix", "match", "match_phrase")


def _positive_clauses(query: Any) -> list[dict[str, Any]]:
    """The clauses a row must match: a bool's must and filter, nested bools walked; never should or must_not.

    A bool that needs one of its ``should`` clauses is one clause as a whole (an either-or a row must meet).
    """
    out: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item)
            return
        if not isinstance(node, dict) or len(node) != 1:
            return
        (kind, body), = node.items()
        if kind == "bool" and isinstance(body, dict):
            walk(body.get("must"))
            walk(body.get("filter"))
            if _should_required(body):
                out.append({"bool": {"should": body.get("should"), "minimum_should_match": 1}})
            return
        if kind == "match_all":
            return
        out.append(node)

    walk(query)
    return out


def _clause_field(clause: dict[str, Any]) -> str:
    (kind, body), = clause.items()
    if kind == "exists" and isinstance(body, dict):
        return str(body.get("field") or "")
    if kind in (*_VALUE_CLAUSES, "range", "regexp") and isinstance(body, dict) and body:
        return str(next(iter(body)))
    return ""


def _clause_values(clause: dict[str, Any]) -> tuple[str, str, list[str]]:
    """(kind, field, the string values it asks for) of a value clause; ("", "", []) for any other."""
    (kind, body), = clause.items()
    if kind not in _VALUE_CLAUSES or not isinstance(body, dict) or len(body) != 1:
        return "", "", []
    (field, spec), = body.items()
    if isinstance(spec, dict):
        spec = spec.get("value", spec.get("query"))
    values = spec if isinstance(spec, list) else [spec]
    return kind, str(field), [v for v in values if isinstance(v, str) and v][:10]


def _ignoring_case(kind: str, field: str, values: list[str]) -> dict[str, Any] | None:
    if kind in ("term", "terms"):
        return {"bool": {"should": [{"term": {field: {"value": v, "case_insensitive": True}}} for v in values],
                         "minimum_should_match": 1}}
    if kind in ("wildcard", "prefix"):
        return {"bool": {"should": [{kind: {field: {"value": v, "case_insensitive": True}}} for v in values],
                         "minimum_should_match": 1}}
    return None


def _in_row_text(kind: str, field: str, values: list[str]) -> dict[str, Any] | None:
    if field in ("text", "text.wc"):
        return None
    if kind in ("wildcard", "prefix"):
        patterns = [v if kind == "wildcard" else f"{v}*" for v in values]
        return {"bool": {"should": [{"wildcard": {"text.wc": {"value": p, "case_insensitive": True}}}
                                    for p in patterns], "minimum_should_match": 1}}
    return {"bool": {"should": [{"match_phrase": {"text": v}} for v in values], "minimum_should_match": 1}}


def _zero_hit_diagnosis(case_id: str, query: dict[str, Any]) -> dict[str, Any] | None:
    """Which clause of a zero-hit query matches nothing, counted on this index (IC-9).

    A zero answers a question only when each clause could have matched. The rows each clause matches on its own
    are counted, and within the query's family filter when it has one; a value that matches nothing is counted
    again ignoring case and as a phrase in the row text. Counts only, never values: the seat learns which clause
    to fix, not what to find. The fresh Mode 3 run had 178 zero-hit searches of 815 and saw nothing but
    ``total: 0`` for any of them. None when the index cannot be counted.
    """
    import json

    clauses = _positive_clauses(query)
    if not clauses:
        return None
    families = [c for c in clauses if _clause_field(c) == "family"]
    try:
        client, name = _client_and_index(case_id)
        with client() as c:
            def count(q: dict[str, Any]) -> int | None:
                r = c.post(f"/{name}/_count", json={"query": _with_lenient(q)})
                return int(r.json().get("count", 0)) if r.status_code < 400 else None

            rows: list[dict[str, Any]] = []
            for clause in clauses[:_DIAGNOSED_CLAUSES]:
                entry: dict[str, Any] = {"clause": json.dumps(clause, sort_keys=True, default=str)[:240],
                                         "rows": count(clause)}
                if families and clause not in families and entry["rows"]:
                    entry["rows_in_family"] = count({"bool": {"filter": [*families, clause]}})
                kind, field, values = _clause_values(clause)
                if entry["rows"] == 0 and values and field != "family":
                    variant = _ignoring_case(kind, field, values)
                    if variant is not None:
                        entry["rows_ignoring_case"] = count(variant)
                    in_text = _in_row_text(kind, field, values)
                    if in_text is not None:
                        entry["rows_with_the_value_in_their_text"] = count(in_text)
                rows.append(entry)
    except Exception:  # noqa: BLE001 - feedback is best-effort, never fatal
        log.debug("zero-hit diagnosis failed", exc_info=True)
        return None
    if any(r.get("rows") is None for r in rows):
        return None
    return {"clauses": rows, "note": _zero_hit_note(rows)}


def _rows(n: int) -> str:
    return f"{n:,} row" if n == 1 else f"{n:,} rows"


def _zero_hit_note(rows: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for r in rows:
        if r["rows"] == 0:
            text = f"{r['clause']} matches no row on its own"
            if r.get("rows_ignoring_case"):
                n = r["rows_ignoring_case"]
                text += f"; {_rows(n)} {'matches' if n == 1 else 'match'} it ignoring case"
            if r.get("rows_with_the_value_in_their_text"):
                n = r["rows_with_the_value_in_their_text"]
                text += (f"; {_rows(n)} {'holds' if n == 1 else 'hold'} the value in the row text "
                         "(another column, or another form of the value)")
            parts.append(text)
        elif r.get("rows_in_family") == 0:
            parts.append(f"{r['clause']} matches {_rows(r['rows'])} in the case and none in the family the query "
                         "names")
    if not parts:
        counts = ", ".join(f"{r['rows']:,}" for r in rows)
        parts.append(f"each clause matches rows on its own ({counts}); no row matches all of them together")
    return "; ".join(parts) + "."


def _flood_composition(case_id: str, query: dict[str, Any], total: int) -> dict[str, Any] | None:
    """What a search of more than ``FLOOD_ROWS`` rows matched, by family and by event (IC-9).

    The fresh Mode 3 run had 80 such searches of 815 (one family alone: 1,242,657 rows) and read the first page of
    each. A page is not a sample of a flood; its make-up is, and it says how to narrow the query.
    """
    try:
        client, name = _client_and_index(case_id)
        with client() as c:
            r = c.post(f"/{name}/_search", json={
                "size": 0, "query": _with_lenient(query),
                "aggs": {"family": {"terms": {"field": "family", "size": 10}},
                         "event_id": {"terms": {"field": "event_id", "size": 10}}},
            })
        if r.status_code >= 400:
            return None
        aggs = r.json().get("aggregations") or {}
    except Exception:  # noqa: BLE001 - feedback is best-effort, never fatal
        log.debug("flood composition failed", exc_info=True)
        return None

    def buckets(key: str) -> list[dict[str, Any]]:
        return [{key: b.get("key"), "rows": b.get("doc_count")}
                for b in ((aggs.get(key) or {}).get("buckets") or []) if isinstance(b, dict)]

    return {
        "rows": total,
        "by_family": buckets("family"),
        "by_event_id": buckets("event_id"),
        "note": (f"{total:,} rows match; the rows shown are the first page, not a sample of them. Narrow the query "
                 "to the family, event or time that answers the question, or count it with es_aggregate."),
    }


def _field_refs(query: dict[str, Any]) -> list[str]:
    """Every `fields.*` / `ecs.*` field named in a query (best-effort walk).

    A field is a KEY whose value is the clause (`{"wildcard": {"fields.x.kw": {...}}}`)
    or a string (`{"term": {"fields.x": "v"}}`), so both shapes are collected.
    """
    out: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if (k.startswith("fields.") or k.startswith("ecs.")) and isinstance(
                        v, (dict, str)):
                    out.add(k)
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(query)
    return sorted(out)


def _aggregation_field_problems(aggs: Any, types: dict[str, str], depth: int = 0) -> list[str]:
    """Aggregations whose field cannot feed them; ES answers each with a raw 400.

    A doc-value aggregation on analysed text with no `.kw` (D391), and a numeric one on a text or keyword field
    (D405: `sum` on T13's text `fields.bytes`).
    """
    found: list[str] = []
    if depth > 6 or not isinstance(aggs, dict) or not types:
        return found
    for spec in aggs.values():
        if not isinstance(spec, dict):
            continue
        for agg_type in (DOC_VALUE_AGGS | NUMERIC_AGGS) & set(spec):
            field = (spec.get(agg_type) or {}).get("field") if isinstance(spec.get(agg_type), dict) else None
            kind = str(types.get(field) or "") if isinstance(field, str) else ""
            if agg_type in DOC_VALUE_AGGS and kind == "text" and f"{field}.kw" not in types:
                found.append(f"`{field}` is analysed text with no keyword sub-field, which {agg_type} cannot read; "
                             "aggregate a keyword field (es_fields lists them) or find values with es_search")
            elif agg_type in NUMERIC_AGGS and kind in ("text", "keyword", "wildcard"):
                found.append(f"`{field}` is {kind} in this index, and {agg_type} needs a number or a date; "
                             "es_fields lists the numeric and date fields")
        # D406: a composite's sources read doc values too (T18 Mode 3 grouped by the analysed `text`).
        composite = spec.get("composite") if isinstance(spec.get("composite"), dict) else {}
        for source in composite.get("sources") or []:
            for inner in (source.values() if isinstance(source, dict) else []):
                terms = (inner or {}).get("terms") if isinstance(inner, dict) else None
                field = terms.get("field") if isinstance(terms, dict) else None
                if isinstance(field, str) and str(types.get(field) or "") == "text" and f"{field}.kw" not in types:
                    found.append(f"`{field}` is analysed text with no keyword sub-field, which a composite source "
                                 "cannot read; group by a keyword field (es_fields lists them)")
        found.extend(_aggregation_field_problems(spec.get("aggs"), types, depth + 1))
    return found


def _patterns_on_non_strings(query: Any, types: dict[str, str], depth: int = 0) -> list[str]:
    """Pattern clauses (wildcard, prefix, regexp) on a number, date, boolean or IP field: ES answers a raw 400."""
    found: list[str] = []
    if depth > 8 or not types:
        return found
    if isinstance(query, list):
        for item in query:
            found.extend(_patterns_on_non_strings(item, types, depth + 1))
        return found
    if not isinstance(query, dict):
        return found
    for key, value in query.items():
        if key in ("wildcard", "prefix", "regexp") and isinstance(value, dict):
            for field in value:
                kind = str(types.get(field) or "")
                if kind and kind not in ("text", "keyword", "wildcard"):
                    found.append(f"`{field}` is {kind}: a {key} pattern applies to text; use term, terms or range")
        else:
            found.extend(_patterns_on_non_strings(value, types, depth + 1))
    return found


def es_aggregate(case_id: str, aggs: dict[str, Any], query: dict[str, Any] | None = None,
                 *, size: int = 0, sort: list[Any] | None = None, family: str = "") -> dict[str, Any]:
    """ES-native aggregation with composite paging support.

    Normalized first, like `es_search`: a JSON-string `aggs`, a plain agg field
    name or a `text` field without its `.kw` are all shapes an LLM writes and ES
    rejects. A nonzero size returns a bounded sorted hit preview alongside the
    complete aggregation result and exact total. Use es_search for enumeration.
    """
    from nexus.langgraph.query_normalize import (
        compile_row_count_requests,
        lift_aggs_query,
        normalize_aggs,
        normalize_query,
        normalize_sort,
    )

    if not case_id:
        raise ESQueryError("case_id is required")
    types = _field_types(case_id)
    aggs, a_notes = normalize_aggs(aggs, types)
    notes = list(a_notes)
    # The request's `query` written among the named aggs (D387) is the request query, not an agg.
    aggs, lifted, l_notes = lift_aggs_query(aggs)
    notes.extend(l_notes)
    aggs, row_counts, count_notes = compile_row_count_requests(aggs)
    notes.extend(count_notes)
    if lifted is not None:
        query = lifted if query is None else {"bool": {"must": [query, lifted]}}
    query = _with_family_filter(query, family)
    if query is not None:
        query, q_notes = normalize_query(query, field_types=types)
        notes.extend(q_notes)
    # Validate the whole structure before issuing any schema hint: an unknown
    # field must never mask a later script or unsupported option.
    _validate_agg_structure(aggs)
    # An unmapped data field remains a legal ES aggregation. A name in the
    # reserved metadata namespace that ES does not define is a schema error,
    # distinct from a known metadata field whose aggregation is forbidden.
    unknown = list(dict.fromkeys(field for field in _aggregation_fields(aggs)
                               if types and field.startswith("_") and field not in types
                               and field not in _ES_METADATA_FIELDS))
    if unknown:
        failed = [{"field": field, "reason": "unknown_field", "did_you_mean": similar_fields(field, types)}
                  for field in unknown]
        return {"case_id": case_id, "backend": "elasticsearch", "degraded": True,
                "error": "aggregation references fields that cannot match: "
                         + ", ".join(f"{field} (unknown_field)" for field in unknown),
                "failed_terms": failed, "aggregations": {},
                **({"normalized": notes} if notes else {})}
    _validate_agg_metadata(aggs)
    problems = _aggregation_field_problems(aggs, types)
    if query is not None:
        problems.extend(_patterns_on_non_strings(query, types))
    if problems:
        raise ESQueryError("cannot aggregate: " + "; ".join(problems))
    if query is not None:
        validate_query(query)
        failed = failed_field_refs(case_id, query)
        if failed:
            # Same honesty rule as `es_search`: a query that cannot match is a
            # degraded result that SAYS SO, not an exception the model cannot act
            # on. Raising here was the 1 remaining replay failure on an
            # `unknown_field`; `es_search` already returns the degraded shape.
            return {
                "case_id": case_id,
                "backend": "elasticsearch",
                "error": "aggregation query references fields that cannot match: "
                         + ", ".join(f"{f['field']} ({f['reason']})" for f in failed[:5]),
                "degraded": True,
                "failed_terms": failed,
                "aggregations": {},
                **({"normalized": notes} if notes else {}),
            }
    body: dict[str, Any] = {
        "size": min(read_request_size(size, tool="es_aggregate"), AGG_PREVIEW_MAX),
        "track_total_hits": True,
        "aggs": aggs,
        "query": _with_lenient(query) if query else {"match_all": {}},
    }
    sort, s_notes = normalize_sort(sort, types)
    notes.extend(s_notes)
    _validate_request_sort(sort)
    if sort:
        body["sort"] = sort
    elif body["size"]:
        body["sort"] = ["_doc"]
    client, name = _client_and_index(case_id)
    with client() as c:
        r = c.post(f"/{name}/_search", json=body)
        if r.status_code >= 400 and "too_many_buckets_exception" in r.text:
            # A valid request that is too fine for this data's time span (T01: 1h over years). Say what to change.
            raise ESQueryError(
                "the aggregation makes more than 65,536 buckets over the rows it matched: use a coarser "
                "interval (e.g. 1d or a calendar month), a smaller `size`, or narrow the query with a `ts` range")
        if r.status_code >= 400:
            raise ESQueryError(f"ES aggregation failed: {r.status_code} {r.text[:300]}")
        data = r.json()
    out = dict(data.get("aggregations") or {})
    hits = [_shape_hit(row.get("_source") or {}) for row in (data.get("hits") or {}).get("hits") or []]
    if row_counts:
        measured = (data.get("hits") or {}).get("total") or {}
        if measured.get("relation") != "eq" or type(measured.get("value")) is not int:
            raise ESQueryError("ES omitted an exact hits.total for the requested row count")
        for count_name in row_counts:
            out[count_name] = {"value": measured["value"]}
    next_key = None
    for spec in out.values():
        if isinstance(spec, dict) and spec.get("after_key") is not None:
            next_key = spec["after_key"]
            break
    return {
        "case_id": case_id,
        "backend": "elasticsearch",
        "took_ms": data.get("took"),
        # The exact count of rows the query matched (`track_total_hits`), so a row count never needs an agg (D388).
        "total": ((data.get("hits") or {}).get("total") or {}).get("value"),
        "aggregations": out,
        "returned": len(hits),
        "hits": hits,
        "next_after_key": next_key,
        **({"normalized": notes} if notes else {}),
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
    try:
        count = int(n)
    except (TypeError, ValueError):
        raise ESQueryError("sample size must be an integer") from None
    if count < 1:
        raise ESQueryError("sample size must be at least 1")
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
                    # The keyword sub-field when the column has one (text); a number or a keyword
                    # column is matched as itself. `.kw` on the `long` EventId matched nothing (D69).
                    kw = f"fields.{name}.kw"
                    parsed_key = kw if kw in _field_types(case_id) else f"fields.{name}"
                    break
        except Exception:  # noqa: BLE001
            parsed_key = None
        if parsed_key:
            should.insert(1, {"term": {parsed_key: value}})
        filt.append({"bool": {"should": should, "minimum_should_match": 1}})
    sample_notes: list[str] = []
    if value and not field:
        # A value with no field is searched in the row text. It used to be dropped, and the
        # "sample" was arbitrary rows of the whole index (2026-10-14, Mode 1 run 4: matched
        # 7,236,364 for "Antivirus - Exploitation Framework Signature").
        filt.append({"match_phrase": {"text": value}})
        sample_notes.append("no field given: the value was searched in the row text")
    query: dict[str, Any] = {"bool": {"filter": filt}} if filt else {"match_all": {}}

    fetch = max(400, count * 40)
    result = es_search(
        case_id, query, size=fetch,
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
        **({"normalized": sample_notes} if sample_notes else {}),
        "note": (
            "sample rows are context — findings still cite the audit trail "
            "(FD-001); use es_search search_after for complete enumeration"
        ),
    }


def _read_tool_contracts():
    """Derive the prompt/loop argument contracts from the native functions."""
    from inspect import Parameter, signature

    functions = {"es_mappings": es_fields, "es_search": es_search,
                 "es_aggregate": es_aggregate, "sample_rows": es_sample}
    parameters = {}
    required = {}
    for name, function in functions.items():
        specs = signature(function).parameters
        parameters[name] = tuple(key for key in specs if key != "case_id")
        required[name] = tuple(key for key, spec in specs.items()
                               if key != "case_id" and spec.default is Parameter.empty)
    return parameters, required


READ_TOOL_PARAMETERS, READ_TOOL_REQUIRED_ARGS = _read_tool_contracts()
