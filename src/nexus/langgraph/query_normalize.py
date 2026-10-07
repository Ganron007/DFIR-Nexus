"""WO-R1F item 2 — an LLM-proof query surface.

Measured at R1: **27% of the LLM's ES calls were rejected in SC1** (82/303
`es_search`, 9/22 `es_aggregate`). The largest single cause (41 calls) is the
model sending shapes a human writes without thinking:

* ``query`` as a **JSON string** rather than an object;
* ``sort`` as a plain string (``"ts"``) rather than a list;
* several top-level clauses where ES allows one (``bool`` required);
* ``size`` / ``from`` / ``sort`` **inside** the query;
* plain ECS names (``process.command_line``) rather than this index's ``ecs.*``;
* aggregating or sorting a ``text`` field without the ``.kw`` sub-field.

The operator's standard is "accept and normalize; do not reject", and "never
fail silently" — so every rewrite is **reported** in the result under
``normalized``, and a genuine rejection returns the reason **and a corrected
example**.

This module is deliberately pure: it takes a body and the case's field types and
returns a new body plus the list of rewrites. The ES call itself stays in
``es_native``.
"""

from __future__ import annotations

import copy
import json
import logging
from typing import Any

log = logging.getLogger(__name__)

#: ES keys that belong to the request envelope, not the query. Lifted out of
#: the query when the model puts them there.
_ENVELOPE_KEYS = {"size", "from", "sort", "search_after", "_source", "track_total_hits"}

#: Plain names the model writes → this index's real field. Only names that exist
#: in the index are rewritten (`ecs.*` is what the indexer writes).
_FIELD_ALIASES = {
    "@timestamp": "ts",
    "timestamp": "ts",
    "time": "ts",
    "event.code": "ecs.winlog.event_data.EventId",
    "event.id": "ecs.winlog.event_data.EventId",
    "event.action": "ecs.event.action",
    "host.name": "ecs.host.name",
    "host.hostname": "ecs.host.name",
    "host.computer": "ecs.host.name",
    "user.name": "ecs.user.name",
    "user.id": "ecs.user.id",
    "source.ip": "ecs.source.ip",
    "destination.ip": "ecs.destination.ip",
    "process.name": "ecs.process.name",
    "process.command_line": "ecs.process.command_line",
    "process.parent.name": "ecs.process.parent.name",
    "process.executable": "ecs.process.executable",
    "hash.sha256": "ecs.hash.sha256",
    "winlog.event_id": "ecs.winlog.event_data.EventId",
}

#: Prefixes rewritten when the plain name is not in the map but is in the index.
_PREFIX_ALIASES = (
    ("event_data.", "ecs.winlog.event_data."),
    ("fields.event_data.", "ecs.winlog.event_data."),
    ("winlog.event_data.", "ecs.winlog.event_data."),
)
#: The sub-field an analysable text field needs for term/agg/sort.
_KW_SUFFIX = ".kw"


def _as_dict(value: Any) -> tuple[Any, bool]:
    """Parse a JSON string into an object. Returns (value, changed)."""
    if isinstance(value, str):
        text = value.strip()
        if text[:1] in "{[":
            try:
                return json.loads(text), True
            except ValueError:
                return value, False
    return value, False


def _is_text(kind: str | None) -> bool:
    return str(kind or "") == "text"


def normalize_query(
    query: Any,
    *,
    field_types: dict[str, str] | None = None,
    allow: set[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Return ``(query, rewrites)``. Never raises; a caller validates after.

    The input is **never mutated**: the caller keeps the body it sent (the tool
    audit-logs it, and a retry re-sends it). An in-place `pop` here emptied the
    caller's query on the second use — measured as "query must be a non-empty
    object" on a body that had just parsed.
    """
    return _normalize_query(copy.deepcopy(query), field_types=field_types)


def _normalize_query(
    query: Any,
    *,
    field_types: dict[str, str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    notes: list[str] = []
    types = field_types or {}

    body, changed = _as_dict(query)
    if changed:
        notes.append("query was a JSON string; parsed to an object")

    if body in (None, {}, []):
        return {"match_all": {}}, notes + ["query was empty; used match_all"]
    if not isinstance(body, dict):
        return {"match_all": {}}, notes + [
            f"query was {type(body).__name__}, not an object; used match_all"
        ]

    # `{"size":3,"query":{…},"sort":[…]}` is a FULL REQUEST BODY, not a query.
    # Unwrap `query` FIRST and drop the envelope keys — doing it after the
    # sibling-fold pushed `query: {...}` into `bool.must` as a null clause.
    if "query" in body:
        envelope = {k: v for k, v in body.items() if k in _ENVELOPE_KEYS}
        inner_query = body["query"]
        if isinstance(inner_query, (dict, str)) and inner_query not in ({}, ""):
            notes.append("unwrapped `query` from a full request body")
            if envelope:
                notes.append(
                    "the body also carried "
                    + ", ".join(sorted(envelope))
                    + " (request options; the caller keeps them)"
                )
            inner, sub = _normalize_query(inner_query, field_types=types)
            notes.extend(sub)
            return inner, notes

    # A bare `filter`/`must`/`must_not`/`should` beside `bool` is a bool clause,
    # not a query clause (measured 4 shapes). Fold each into its sibling `bool`
    # under its OWN key, before the generic stray pass.
    if "bool" in body and len(body) > 1:
        inner = dict(body["bool"]) if isinstance(body["bool"], dict) else {}
        moved: list[str] = []
        for bool_key in ("must", "should", "must_not", "filter"):
            if bool_key in body:
                extra = body.pop(bool_key)
                have = inner.get(bool_key)
                if have is None:
                    inner[bool_key] = extra
                else:
                    inner[bool_key] = ([*have, *extra] if isinstance(have, list)
                                       else [have, *extra])
                moved.append(bool_key)
        if moved:
            notes.append(f"moved sibling {moved} inside `bool` (ES allows one clause)")
            body = {**body, "bool": inner}

    # `{"query": {...}}` is the full request body, not a query. Unwrap it.
    if set(body) == {"query"}:
        notes.append("unwrapped the `query` envelope (the tool takes the query itself)")
        return normalize_query(body["query"], field_types=field_types)

    # A bare `filter` is a bool clause, not a query clause.
    if "filter" in body and "bool" not in body:
        body = {"bool": {"filter": body.pop("filter")}}
        notes.append("wrapped top-level `filter` in bool.filter")
    if "must" in body and "bool" not in body:
        body = {"bool": {"must": body.pop("must")}}
        notes.append("wrapped top-level `must` in bool.must")
    if "must_not" in body and "bool" not in body:
        body = {"bool": {"must_not": body.pop("must_not")}}
        notes.append("wrapped top-level `must_not` in bool.must_not")
    # A stray clause beside `bool` (`{"bool": {...}, "enable": false}`): fold it
    # inside, because ES allows ONE clause per level.
    if "bool" in body and len(body) > 1:
        strays = {k: v for k, v in body.items() if k != "bool"}
        droppable = {k: v for k, v in strays.items()
                     if k in ("enable", "size", "from", "sort")}
        for key in droppable:
            notes.append(f"dropped `{key}` beside `bool` (not a query clause)")
        strays = {k: v for k, v in strays.items() if k not in droppable}
        inner = dict(body["bool"]) if isinstance(body["bool"], dict) else {}
        if strays:
            must = inner.get("must")
            strays = [{k: v} for k, v in strays.items()]
            inner["must"] = ([*must, *strays] if isinstance(must, list)
                             else ([*(must or []), *strays] if must else strays))
            notes.append(f"moved {[list(s)[0] for s in strays]} inside its sibling `bool`")
        body = {"bool": inner}

    # Envelope keys lifted out of the query body — at ANY level, because the
    # model puts them inside bool as well as at the top.
    lifted = _strip_envelope(body, notes)

    # Several top-level clauses → bool.must.
    if len(body) > 1:
        clauses = [normalize_query({k: v}, field_types=types)[0]
                   for k, v in body.items()]
        notes.append(
            f"combined {len(body)} top-level clauses into bool.must "
            "(ES allows one clause per level)"
        )
        body = {"bool": {"must": clauses}}
    elif not body:
        body = {"match_all": {}}

    out, field_notes = _normalize_node(body, types, depth=0)
    notes.extend(field_notes)
    if lifted:
        notes.append(f"lifted {sorted(lifted)} out of the query (request options)")
    return out, notes


def _strip_envelope(node: Any, notes: list[str], _depth: int = 0) -> dict[str, Any]:
    """Remove request-envelope keys from a query body, recursively."""
    lifted: dict[str, Any] = {}
    if _depth > 6 or not isinstance(node, dict):
        return lifted
    for key in list(node):
        if key in _ENVELOPE_KEYS:
            lifted[key] = node.pop(key)
            continue
        child = node.get(key)
        if key == "bool" and isinstance(child, dict):
            lifted.update(_strip_envelope(child, notes, _depth + 1))
        elif isinstance(child, list):
            for item in child:
                lifted.update(_strip_envelope(item, notes, _depth + 1))
    return lifted


def _normalize_node(node: Any, types: dict[str, str], *, depth: int) -> tuple[Any, list[str]]:
    notes: list[str] = []
    if depth > 8:
        return node, notes
    if isinstance(node, list):
        out_list = []
        for item in node:
            fixed, sub = _normalize_node(item, types, depth=depth + 1)
            out_list.append(fixed)
            notes.extend(sub)
        return out_list, notes
    if not isinstance(node, dict):
        return node, notes

    # `{"exists": {"field": "x", "missing": false}}` used bare as a clause.
    if set(node) == {"exists"} and "missing" in (node.get("exists") or {}):
        spec = {k: v for k, v in node["exists"].items() if k == "field"}
        notes.append("dropped unsupported exists options ['missing']")
        return {"exists": spec}, notes

    out: dict[str, Any] = {}
    for key, value in node.items():
        if key in _ENVELOPE_KEYS:
            notes.append(f"dropped `{key}` (a request option, not a query clause)")
            continue
        if key == "bool" and isinstance(value, dict):
            # `bool.min_should_match` is a bool option, not a clause — rename it
            # BEFORE the stray-key pass, or it gets moved into `must` as a clause.
            if "min_should_match" in value:
                value = dict(value)
                value["minimum_should_match"] = value.pop("min_should_match")
                notes.append("renamed bool `min_should_match` → `minimum_should_match`")
            # A `bool` body whose keys are not bool keys: the model put clauses
            # beside `must` (measured: `{"bool":{"must":[...],"range":{...}}}`).
            # Move the strays into `must` KEEPING THEIR KEY — dropping it turned
            # `{"range": {"ts": ...}}` into a bare `{"ts": ...}` clause.
            stray = {k: v for k, v in value.items()
                     if k not in ("must", "should", "must_not", "filter",
                                  "minimum_should_match")}
            if stray:
                cleaned = {k: v for k, v in value.items() if k not in stray}
                strays = [{k: v} for k, v in stray.items()]
                must = cleaned.get("must")
                if must is None:
                    cleaned["must"] = strays
                else:
                    if not isinstance(must, list):
                        must = [must]
                    cleaned["must"] = [*must, *strays]
                notes.append(
                    f"moved {sorted(stray)} into bool.must "
                    "(a bool body holds only bool keys)"
                )
                value = cleaned
            fixed, sub = _normalize_node(value, types, depth=depth + 1)
            out[key] = fixed
            notes.extend(sub)
            continue
        if key in ("must", "should", "must_not", "filter") and isinstance(value, (dict, list)):
            fixed, sub = _normalize_node(value, types, depth=depth + 1)
            out[key] = fixed
            notes.extend(sub)
            continue
        if key in ("min_should_match",):
            notes.append("renamed `min_should_match` → `minimum_should_match`")
            out["minimum_should_match"] = value
            continue
        if key in ("term", "match", "match_phrase", "prefix", "wildcard", "regexp", "range", "terms"):
            if not isinstance(value, dict):
                out[key] = value
                continue
            # `match` written as `{query: {field: …}}` or `{field: {query: …}}`.
            if key == "match":
                value, sub = _normalize_match_body(value, notes)
                if value is None:
                    continue
                if set(value) == {"_fieldless"}:
                    out["multi_match"] = {"query": value["_fieldless"]}
                    notes.append("converted a field-less `match` to `multi_match`")
                    continue
            # `terms` with several fields is not valid ES (it takes exactly one);
            # it means "any of these", which is bool.should of term clauses.
            if key == "terms" and len(value) > 1:
                # `{"terms": {"fields": [..], "query_texts": [..]}}` is a
                # multi-field text search, not a terms list. Treat the string
                # list as the pattern over each named field.
                if isinstance(value.get("fields"), list) and len(value) == 2:
                    texts = value.get("query_texts") or value.get("values") or []
                    if isinstance(texts, list) and texts:
                        should = [
                            {"match": {_alias_field(str(f), types): texts[0]}}
                            for f in value["fields"]
                        ]
                        notes.append(
                            "converted a multi-field `terms {fields, query_texts}` "
                            "to bool.should of match clauses"
                        )
                        out["bool"] = {"should": should}
                        continue
                should = [
                    {"term": {_alias_field(str(field), types): spec}}
                    for field, spec in value.items()
                ]
                notes.append(
                    f"split a {len(value)}-field `terms` into bool.should "
                    "(ES takes one field per terms clause)"
                )
                out["bool"] = {"should": should}
                continue
            # `term` with several fields means "any of" too.
            if key == "term" and len(value) > 1:
                should = [
                    {"term": {_alias_field(str(field), types): spec}}
                    for field, spec in value.items()
                ]
                notes.append(
                    f"split a {len(value)}-field `term` into bool.should "
                    "(ES takes one field per term clause)"
                )
                out["bool"] = {"should": should}
                continue
            # `query` / `enable` as a *clause key* is not ES — the model nested a
            # clause inside {query: {...}}. Unwrap the inner clause.
            if set(value) == {"query"} and isinstance(value["query"], dict):
                notes.append("unwrapped a `query` key used as a clause")
                inner, sub = _normalize_node({"bool": value["query"]}
                                             if "bool" not in value["query"] else value["query"],
                                             types, depth=depth + 1)
                notes.extend(sub)
                out["bool"] = inner if isinstance(inner, dict) else {"must": [inner]}
                continue
            fixed, sub = _normalize_field_clause(key, value, types)
            out[key] = fixed
            notes.extend(sub)
            continue
        if key in ("query", "enable") and isinstance(value, dict):
            # `query`/`enable` used as a clause: `should` defaults to enable.
            inner = value.get("query") if key == "query" else value
            notes.append(f"unwrapped a `{key}` key used as a clause")
            fixed, sub = _normalize_node(inner, types, depth=depth + 1)
            notes.extend(sub)
            out["bool"] = {"must": [fixed]}
            continue
        if key == "query_string" and isinstance(value, dict):
            # A full-text clause by another name; multi_match is the allowlisted
            # equivalent and keeps the meaning. `fields: ["*"]` is every field,
            # which multi_match expresses by omitting `fields`.
            patched: dict[str, Any] = {"query": value.get("query") or ""}
            fields = value.get("fields")
            if isinstance(fields, list) and fields and fields != ["*"]:
                patched["fields"] = [_alias_field(f, types) for f in fields]
            notes.append("converted `query_string` to `multi_match` (allowlisted equivalent)")
            out["multi_match"] = patched
            continue
        if key == "match_all":
            # `{"match_all": {"_all": true}}` and friends: options are not allowed.
            if isinstance(value, dict) and value:
                notes.append("dropped options from `match_all` (it takes {})")
            out["match_all"] = {}
            continue
        if key == "multi_match" and isinstance(value, dict):
            patched = dict(value)
            fields = patched.get("fields")
            if isinstance(fields, list):
                patched["fields"] = [_alias_field(f, types) for f in fields]
            out[key] = patched
            continue
        out[key] = value
    return out, notes


#: Short column names this index carries at the top level. A model writes
#: `provider`, `event_id`, `host`, `family` — these are the index's own names,
#: not ECS paths, so they are used as-is; listed here so the normalizer does not
#: treat them as unknown and so a reader can see the intent.
_SHORT_COLUMNS = (
    "family", "host", "event_id", "provider", "channel", "user", "ts", "text",
    "source", "computer",
)


def _alias_field(field: str, types: dict[str, str]) -> str:
    """Map a plain field name to this index's name."""
    name = str(field or "").strip()
    if not name:
        return name
    if name in types or not types:
        return name
    if name in _SHORT_COLUMNS and name in types:
        return name
    if name in _FIELD_ALIASES and _FIELD_ALIASES[name] in types:
        return _FIELD_ALIASES[name]
    for prefix, replacement in _PREFIX_ALIASES:
        if name.startswith(prefix):
            candidate = replacement + name[len(prefix):]
            if candidate in types:
                return candidate
    # Already-looking ECS path that the index carries as-is.
    if f"ecs.{name}" in types:
        return f"ecs.{name}"
    return name


def _normalize_match_body(value: dict[str, Any], notes: list[str]) -> tuple[Any, list[str]]:
    """The several shapes a model writes for `match`.

    Returns ``(body, notes)``; ``body is None`` means "already emitted elsewhere".
    """
    # `{query: {field: "text"}}` — the whole clause wrapped in a query key.
    if set(value) == {"query"}:
        inner = value["query"]
        if isinstance(inner, dict) and len(inner) == 1:
            notes.append("unwrapped `match {query: {field: …}}`")
            return inner, notes
        if isinstance(inner, str):
            return {"_fieldless": inner}, notes
    # `{field: {query: "…", type: "phrase"}}` — options inside the field body.
    lifted: dict[str, Any] = {}
    for field, spec in value.items():
        if isinstance(spec, dict) and "query" in spec:
            lifted[field] = spec["query"]
    if lifted:
        notes.append("lifted `query` out of the `match` body")
        value = {**value, **lifted}
    return {k: v for k, v in value.items() if k != "type"}, notes


def _normalize_field_clause(
    key: str, value: Any, types: dict[str, str]
) -> tuple[Any, list[str]]:
    notes: list[str] = []
    if not isinstance(value, dict):
        return value, notes

    # `wildcard` sometimes arrives as {case_sensitive, wildcard: {field: v}} —
    # the ES option object wrapped around the clause. Unwrap it.
    if key == "wildcard" and set(value) >= {"case_sensitive", "wildcard"}:
        inner = value.get("wildcard")
        if isinstance(inner, dict):
            notes.append("unwrapped the `wildcard` clause from its option object")
            value = inner

    # `match` sometimes carries the whole clause: {query: ..., type: "phrase"}.
    if key == "match" and "query" in value and "field" not in value:
        inner_query = value.get("query")
        if isinstance(inner_query, dict) and len(inner_query) >= 1:
            notes.append("unwrapped `match` clause supplied as {query: {...}}")
            value = inner_query
        elif isinstance(inner_query, str) and len(value) == 1:
            # {query: "text"} with no field: no field to match on; the caller
            # meant a full-text search, so use multi_match over the text column.
            notes.append("converted a field-less `match {query: ...}` to `multi_match`")
            value = {"_fieldless": inner_query}
            return {"multi_match": {"query": inner_query}}, notes
        else:
            # {field: {query: "..."}} — the value holds the pattern.
            cleaned: dict[str, Any] = {}
            for field, spec in value.items():
                if isinstance(spec, dict) and "query" in spec:
                    cleaned[field] = spec["query"]
                    notes.append(f"lifted `query` out of the `match` body for `{field}`")
                else:
                    cleaned[field] = spec
            value = cleaned

    # wildcard's `case_sensitive` is not a valid ES option here; drop it.
    if key == "wildcard":
        cleaned = {k: v for k, v in value.items() if k != "case_sensitive"}
        if len(cleaned) != len(value):
            notes.append("dropped unsupported `case_sensitive` from wildcard")
            value = cleaned

    out: dict[str, Any] = {}
    for field, spec in value.items():
        # `wildcard` written as {field: {wildcard: "*x*", case_sensitive: false}}:
        # the value is a bare pattern, the options belong beside `value`.
        if key == "wildcard" and isinstance(spec, dict) and "wildcard" in spec:
            pattern = spec.get("wildcard")
            if isinstance(pattern, str):
                notes.append("flattened the `wildcard` value object")
                spec = {"value": pattern}
        # `case_sensitive` is not a valid ES wildcard option at either level.
        if key == "wildcard" and isinstance(spec, dict) and "case_sensitive" in spec:
            spec = {k: v for k, v in spec.items() if k != "case_sensitive"}
            notes.append("dropped unsupported `case_sensitive` from wildcard")
        # `exists` takes only `field`; `missing`/`boost` are not valid there.
        if key == "exists" and isinstance(spec, dict):
            unknown = set(spec) - {"field"}
            if unknown:
                notes.append(f"dropped unsupported exists options {sorted(unknown)}")
                spec = {k: v for k, v in spec.items() if k in ("field",)}
        target = _alias_field(str(field), types)
        if target != field:
            notes.append(f"aliased field `{field}` → `{target}`")
        # A `text` field cannot be term/agg/sorted without its keyword sub-field.
        if key in ("term", "terms", "prefix", "wildcard", "regexp") and _is_text(
            types.get(target)
        ):
            kw = target + _KW_SUFFIX
            if kw in types:
                notes.append(f"used keyword sub-field `{kw}` for `{target}` (text field)")
                target = kw
        # A `match` spec that is {query: ...} keeps its options; a scalar is fine.
        if key == "match" and isinstance(spec, dict) and "query" in spec:
            allowed = {"query", "operator", "minimum_should_match", "fuzziness", "lenient"}
            spec = {k: v for k, v in spec.items() if k in allowed}
        out[target] = spec
    return out, notes


def normalize_sort(sort: Any, types: dict[str, str] | None = None) -> tuple[list[Any], list[str]]:
    """`sort` → a list; a string becomes an ascending entry; `_id` becomes `ts`."""
    notes: list[str] = []
    types = types or {}
    if sort is None:
        return [], notes
    value, changed = _as_dict(sort)
    if changed:
        notes.append("sort was a JSON string; parsed")
        sort = value
    if isinstance(sort, (str, dict)):
        sort = [sort]
        notes.append("sort was not a list; wrapped it (ES requires a list)")
    if not isinstance(sort, list):
        return [], notes + [f"sort was {type(sort).__name__}; ignored"]
    out: list[Any] = []
    for entry in sort:
        if isinstance(entry, str):
            field = _alias_field(entry, types)
            if field == "_id":
                field, note = "ts", "sorting on `_id` is disallowed; used `ts`"
                notes.append(note)
            elif field != entry:
                notes.append(f"aliased sort field `{entry}` → `{field}`")
            if _is_text(types.get(field)) and field + _KW_SUFFIX in types:
                field = field + _KW_SUFFIX
                notes.append(f"sorted on `{field}` (keyword sub-field of a text field)")
            elif types and field not in types:
                notes.append(
                    f"`{field}` is not mapped in this index; sorted on `ts` instead"
                )
                field = "ts"
            out.append({field: "asc"})
        elif isinstance(entry, dict) and len(entry) == 1:
            (field, spec), = entry.items()
            target = _alias_field(str(field), types)
            if target == "_id":
                target = "ts"
                notes.append("sorting on `_id` is disallowed; used `ts`")
            elif target != field:
                notes.append(f"aliased sort field `{field}` → `{target}`")
            if isinstance(spec, str):
                spec = {"order": spec}
            if _is_text(types.get(target)) and target + _KW_SUFFIX in types:
                target = target + _KW_SUFFIX
                notes.append(f"sorted on `{target}` (keyword sub-field of a text field)")
            elif types and target not in types:
                # Sorting on a field this index does not map is a shard 400. Fall
                # back to the timestamp, which every row has, and say so.
                notes.append(
                    f"`{target}` is not mapped in this index; sorted on `ts` instead"
                )
                target = "ts"
            out.append({target: spec})
        else:
            notes.append(f"dropped unusable sort entry {entry!r}")
    return out[:4], notes


def normalize_aggs(aggs: Any, types: dict[str, str] | None = None) -> tuple[dict[str, Any], list[str]]:
    """Aggregations: a JSON string is parsed; text fields get their `.kw`."""
    notes: list[str] = []
    types = types or {}
    body, changed = _as_dict(aggs)
    if changed:
        notes.append("aggs was a JSON string; parsed to an object")
    if not isinstance(body, dict) or not body:
        return {}, notes
    # A single unnamed agg (`{"terms": {"field": ...}}`) — ES needs a name, so
    # wrap it under a stable one rather than rejecting the call.
    if any(k in body for k in _AGG_TYPES) and not any(
        isinstance(v, dict) and any(k in v for k in _AGG_TYPES)
        for v in body.values()
    ):
        body = {"agg": body}
        notes.append("wrapped an unnamed aggregation under `agg` (ES needs a name)")

    def walk(node: Any, depth: int) -> Any:
        if depth > 6 or not isinstance(node, dict):
            return node
        out: dict[str, Any] = {}
        for name, spec in node.items():
            if isinstance(spec, dict) and any(k in spec for k in _AGG_TYPES):
                agg_type = next(k for k in spec if k in _AGG_TYPES)
                agg_body = spec.get(agg_type)
                # Options written BESIDE the agg type, not inside it:
                # `{"terms": {...}, "shard_size": 200}`. Move them in.
                strag = {k: v for k, v in spec.items() if k != agg_type}
                if strag and isinstance(agg_body, dict):
                    agg_body = {**agg_body, **strag}
                    notes.append(f"moved {sorted(strag)} inside the `{agg_type}` body")
                if isinstance(agg_body, dict):
                    patched = dict(agg_body)
                    # ES wants numbers for these; a model writes "100".
                    for num_key in ("size", "shard_size", "min_doc_count",
                                    "precision_threshold"):
                        raw = patched.get(num_key)
                        if isinstance(raw, str) and raw.strip().isdigit():
                            patched[num_key] = int(raw.strip())
                            notes.append(f"coerced `{num_key}` from a string to a number")
                    field = patched.get("field")
                    if isinstance(field, str):
                        target = _alias_field(field, types)
                        # `host`, `provider`, `family` and friends are this
                        # index's own short columns, not ECS paths.
                        if types and target not in types and target in ("host",):
                            notes.append(f"`{target}` is not mapped; no agg field change")
                        if target != field:
                            notes.append(f"aliased agg field `{field}` → `{target}`")
                        if agg_type == "terms" and _is_text(types.get(target)):
                            kw = target + _KW_SUFFIX
                            if kw in types:
                                notes.append(
                                    f"aggregated on `{kw}` (keyword sub-field of `{target}`)"
                                )
                                target = kw
                        patched["field"] = target
                    # Nested aggs / composite sources recurse.
                    if isinstance(patched.get("aggs"), dict):
                        patched["aggs"] = walk(patched["aggs"], depth + 1)
                    if isinstance(patched.get("sources"), list):
                        patched["sources"] = [
                            walk({f"s{i}": s}, depth + 1).get(f"s{i}", s)
                            for i, s in enumerate(patched["sources"])
                        ]
                    spec = {agg_type: patched}
                out[name] = spec
            else:
                out[name] = walk(spec, depth + 1)
        return out

    return walk(body, 0), notes


#: The three rules the model must follow, stated plainly (WO-R1F item 2b).
QUERY_RULES = (
    "query is a JSON OBJECT, sort is a LIST, and there is ONE top-level clause "
    "(combine with bool.must). e.g. "
    '{"query":{"bool":{"must":[{"term":{"ecs.host.name":"WS01"}},'
    '{"range":{"ts":{"gte":"2023-01-24"}}}]}},"sort":[{"ts":"asc"}],"size":50}'
)


#: Aggregation types this surface rewrites. Mirrors `es_native._AGG_TYPES` so the
#: normalizer can find the inner body without importing the validator.
_AGG_TYPES = {
    "terms", "date_histogram", "cardinality", "composite", "min", "max",
    "avg", "sum", "value_count", "histogram", "range",
}


def corrected_example(reason: str) -> str:
    """A corrected example for a rejection message.

    The operator's standard: a rejection returns the reason **and a corrected
    example**, so the model's next attempt can succeed.
    """
    return f"{reason}. Correct shape — {QUERY_RULES}"


#: Three worked examples, exactly as the model must write them (WO-R1F item 2b).
#: Measured in SC1's recorded calls: the protocol showed `"args":{...}` and never
#: one complete, correct `es_search` call, so the model invented the shape.
_WORKED_EXAMPLES = (
    "WORKED EXAMPLES (write them exactly like this):\n"
    "1. a filtered search:\n"
    '{"tool_calls":[{"tool":"es_search","args":{'
    '"query":{"bool":{"must":['
    '{"term":{"ecs.winlog.event_data.TargetUserName":"admin"}},'
    '{"range":{"ts":{"gte":"2023-01-24"}}}]}},'
    '"sort":[{"ts":"asc"}],"size":50},"why":"..."}]}\n'
    "2. a terms aggregation:\n"
    '{"tool_calls":[{"tool":"es_aggregate","args":{'
    '"aggs":{"by_host":{"terms":{"field":"host","size":50}}},'
    '"query":{"match_all":{}}},"why":"..."}]}\n'
    "3. an EventData wildcard:\n"
    '{"tool_calls":[{"tool":"es_search","args":{'
    '"query":{"wildcard":{"ecs.winlog.event_data.CommandLine":'
    '{"value":"*EncodedCommand*"}}},"size":25},"why":"..."}]}\n'
    "THREE RULES: `query` is a JSON object, `sort` is a list, and there is ONE "
    "top-level clause (combine with bool)."
)


def query_protocol_block() -> str:
    """The three rules plus three worked examples, for every investigative prompt."""
    return f"ES QUERY PROTOCOL\n{QUERY_RULES}\n{_WORKED_EXAMPLES}"
