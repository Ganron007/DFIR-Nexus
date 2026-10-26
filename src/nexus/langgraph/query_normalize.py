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
import re
from typing import Any

# The validator's own tables (one definition each, rule 16): what this surface rewrites is exactly what it accepts.
# `es_native` imports only the standard library at module level, so this stays a pure module.
from nexus.langgraph.es_native import (
    _AGG_BODY_KEYS,
    _AGG_TYPES,
    _QUERY_KEYS,
    DOC_VALUE_AGGS,
    FIELD_CLAUSE_OPTIONS,
    TERMS_OPTIONS,
    VALUE_CLAUSES,
)

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
    # The event's id is `ecs.event.code` (the ECS map writes EvtxECmd's EventId and Hayabusa's
    # EventID there); these names pointed at an EventId in event_data no event carries (D218).
    "event.code": "ecs.event.code",
    "event.id": "ecs.event.code",
    "ecs.winlog.event_data.EventId": "ecs.event.code",
    "ecs.winlog.event_data.EventID": "ecs.event.code",
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
    "winlog.event_id": "ecs.event.code",
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
            # An aggregation written inside a query item (D405, T12 Mode 3: `{"wildcard": {...}, "cardinality":
            # {...}}`) is not a filter: it is dropped, said, and the query clause it sat beside stays.
            if isinstance(item, dict) and len(item) > 1:
                aggs_here = [k for k in item if k in _AGG_TYPES and k not in _QUERY_KEYS]
                if aggs_here and any(k in _QUERY_KEYS for k in item):
                    notes.append(f"dropped {sorted(aggs_here)} from the query: an aggregation goes in es_aggregate's "
                                 "aggs, not in a query clause")
                    item = {k: v for k, v in item.items() if k not in aggs_here}
            # One list item holding several clauses is several clauses (D393, T01 Mode 3:
            # `{"wildcard": {...}, "term": {...}}` as one `must` entry).
            if isinstance(item, dict) and len(item) > 1 and all(k in _QUERY_KEYS for k in item):
                notes.append(f"split a list item holding {len(item)} clauses into {len(item)} clauses")
                parts: list[Any] = [{k: v} for k, v in item.items()]
            else:
                parts = [item]
            for part in parts:
                fixed, sub = _normalize_node(part, types, depth=depth + 1)
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
    # `{"exists": {"fields.ValueData": {}}}`: the field named as the key (D392, T04 Mode 2).
    exists = node.get("exists") if set(node) == {"exists"} else None
    if isinstance(exists, dict) and "field" not in exists and len(exists) == 1:
        (named,) = exists
        notes.append(f"rewrote `exists` naming `{named}` as its key to {{field: `{named}`}}")
        return {"exists": {"field": _alias_field(str(named), types)}}, notes
    # `{"family": "evtxecmd"}` as a clause: a mapped field with a value means `term` (D394, T05 Mode 2).
    if len(node) == 1 and types:
        ((bare, bare_value),) = node.items()
        target = _alias_field(str(bare), types)
        if (bare not in _QUERY_KEYS and bare not in _ENVELOPE_KEYS and target in types
                and isinstance(bare_value, (str, int, float, bool))):
            clause = "match" if _is_text(types.get(target)) else "term"
            notes.append(f"`{bare}` used as a clause with a value; matched it as {clause} {{{target}: {bare_value!r}}}")
            return {clause: {target: bare_value}}, notes

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
            # First, before any rule counts the fields: an option beside the one field is not a field.
            value = _fold_beside_options(key, value, notes)
            exact = _pattern_without_wildcards_on_non_string(key, value, types)
            if exact is not None:
                field, pattern = exact
                notes.append(f"`{field}` is {types.get(field)}: the {key} `{pattern}` has no wildcard, so it is a term")
                out["term"] = {field: pattern}
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
            # `boost` beside the one field is a terms option, not a second field (D405, T13 Mode 3).
            if key == "terms" and len([k for k in value if k not in TERMS_OPTIONS]) > 1:
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
                # A list value stays `terms`: a `term` with a list is a raw ES 400 (D405).
                should = [
                    {("terms" if isinstance(spec, list) else "term"): {_alias_field(str(field), types): spec}}
                    for field, spec in value.items() if field not in TERMS_OPTIONS
                ]
                notes.append(
                    f"split a {len(should)}-field `terms` into bool.should "
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
    # A `.kw` or `.wc` sub-field this index does not have: only text fields carry one. On a number,
    # a date or a keyword it matched nothing and raised no error: `fields.EventId.kw` on the `long`
    # EventId returned 0 hits (D69). The field itself is what the query meant.
    # `.keyword` is the sub-field other Elasticsearch indexes name; this one names it `.kw` (D218).
    if name.endswith(".keyword"):
        base = _alias_field(name[: -len(".keyword")], types)
        if base + _KW_SUFFIX in types:
            return base + _KW_SUFFIX
        if base in types:
            return base
    for suffix in (_KW_SUFFIX, ".wc"):
        if name.endswith(suffix):
            base = _alias_field(name[: -len(suffix)], types)
            if base in types:
                return base
    if name in _SHORT_COLUMNS and name in types:
        return name
    # A core column written as a tool column (`fields.family`): the envelope holds it (D218).
    if name.startswith("fields.") and name[len("fields."):] in types:
        return name[len("fields."):]
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
    # A tool column written bare (`sa`, `ibyt`, `action`): the index holds it as `fields.<name>` (D405: T18's Mode 2
    # spent calls on `sa`/`da` answered "this index has fields.sa"). Exact name only; anything looser is below.
    if f"fields.{name}" in types:
        return f"fields.{name}"
    # The one field the name means, written in another case or with underscores (`fields.task_name`
    # for `fields.TaskName`, D218). Only a single match is taken; two or more stay an unknown field.
    loose = _loose_key(name)
    matches = [field for field in types if _loose_key(field) == loose]
    if len(matches) == 1:
        return matches[0]
    return name


def _loose_key(name: str) -> str:
    """A field name with case and underscores ignored."""
    return name.replace("_", "").lower()


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


def _pattern_without_wildcards_on_non_string(
    key: str, value: dict[str, Any], types: dict[str, str]
) -> tuple[str, str] | None:
    """(field, value) when a wildcard/prefix on a number, date, boolean or IP field holds no wildcard character.

    D405 (T13 Mode 3): `{"wildcard": {"fields.source_port.kw": "49208"}}` on the `long` port answered a raw 400. With
    no `*` or `?` it means equals, a term. A real pattern on such a field stays and is refused with a pointer.
    """
    if key not in ("wildcard", "prefix") or len(value) != 1 or not types:
        return None
    ((field, spec),) = value.items()
    target = _alias_field(str(field), types)
    kind = str(types.get(target) or "")
    if not kind or kind in ("text", "keyword", "wildcard"):
        return None
    pattern = spec.get("value") if isinstance(spec, dict) else spec
    if not isinstance(pattern, (str, int, float)) or any(ch in str(pattern) for ch in "*?"):
        return None
    return target, str(pattern)


def _fold_beside_options(key: str, value: dict[str, Any], notes: list[str]) -> dict[str, Any]:
    """Options written BESIDE a clause's one field, ES's short form plus options (D386).

    `{"wildcard": {"text": "*x*", "case_insensitive": true}}`: ES and the validator read the option as a second field,
    and the multi-field `term` split read it as one more field to match; every such call in T10's and T21's Mode 2 was
    refused. The option belongs in the field's object (an option already there wins); match/match_phrase are analysed,
    so a case option beside them is dropped with a note. Two real fields are left alone.
    """
    options = FIELD_CLAUSE_OPTIONS.get(key)
    if not options:
        return value
    beside = {k: v for k, v in value.items() if k in options}
    named = [k for k in value if k not in options]
    if not beside or len(named) != 1:
        return value
    field = named[0]
    spec = value[field]
    if key in VALUE_CLAUSES:
        spec = {**beside, **spec} if isinstance(spec, dict) else {"value": spec, **beside}
        notes.append(f"moved {sorted(beside)} inside the `{field}` {key} object (options belong there)")
    else:
        notes.append(f"dropped {sorted(beside)} beside `{field}`: {key} is analysed, so already case-insensitive")
    return {field: spec}


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
            elif _is_text(types.get(field)):
                notes.append(f"`{field}` is analysed text and cannot be sorted; sorted on `ts` instead")
                field = "ts"
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
            elif _is_text(types.get(target)):
                # D391: `sort: [{"text": "asc"}]` came back as a raw fielddata 400 (T01, T10).
                notes.append(f"`{target}` is analysed text and cannot be sorted; sorted on `ts` instead")
                target = "ts"
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


#: date_histogram intervals that are calendar units; anything else is a fixed interval.
_CALENDAR_INTERVALS = {"minute", "1m", "hour", "1h", "day", "1d", "week", "1w", "month", "1M", "quarter", "1q",
                       "year", "1y"}
_ISO_DURATION = re.compile(r"P(?:(\d+)([DW]))|PT(\d+)([HMS])")


def _query_clause_as_filter_agg(name: str, spec: Any, notes: list[str]) -> Any:
    """A query clause written as a named aggregation is a `filter` aggregation (D389).

    Measured on T01 Mode 3: `{"by_run_match": {"bool": {"filter": [...]}}}`. A `range`/`terms` body that names a
    `field` (or `ranges`/`sources`) is a real aggregation and stays one; `query` is the request query (D387).
    """
    if name == "query" or not isinstance(spec, dict):
        return spec
    clauses = [k for k in spec if k not in ("aggs", "aggregations")]
    if len(clauses) != 1:
        return spec
    clause = clauses[0]
    body = spec[clause]
    is_agg = clause in _AGG_TYPES and isinstance(body, dict) and bool({"field", "ranges", "sources"} & set(body))
    if clause not in _QUERY_KEYS or is_agg or clause == "filter":
        return spec
    notes.append(f"`{name}` is a query clause (`{clause}`); used it as a `filter` aggregation")
    rest = {k: v for k, v in spec.items() if k in ("aggs", "aggregations")}
    return {"filter": {clause: body}, **rest}


def _normalize_date_histogram(body: dict[str, Any], notes: list[str]) -> dict[str, Any]:
    """The date_histogram shapes models write that ES 8 rejects (D390, T01 and T04 Mode 2/3)."""
    body = dict(body)
    if "interval" in body and not {"calendar_interval", "fixed_interval"} & set(body):
        value = str(body.pop("interval"))
        key = "calendar_interval" if value in _CALENDAR_INTERVALS else "fixed_interval"
        body[key] = value
        notes.append(f"renamed date_histogram `interval` to `{key}` (ES 8 removed `interval`)")
    for key in ("fixed_interval", "calendar_interval"):
        value = body.get(key)
        match = _ISO_DURATION.fullmatch(str(value).upper()) if isinstance(value, str) else None
        if match:
            n, unit = (match.group(1), match.group(2)) if match.group(1) else (match.group(3), match.group(4))
            converted = f"{int(n) * 7}d" if unit == "W" else f"{n}{unit.lower()}"
            body[key] = converted
            notes.append(f"converted the ISO-8601 `{key}` {value!r} to {converted!r}")
    # A calendar interval is ONE unit (1m, 1h, 1d, 1w, 1M, 1q, 1y); `10m` is a fixed interval (D405, T21 Mode 3: a raw
    # 400 "failed to parse field [calendar_interval]"). Weeks become days; a multiple of months, quarters or years has
    # no fixed equivalent and is left for the validator to answer.
    calendar = body.get("calendar_interval")
    multiple = re.fullmatch(r"(\d+)([smhdw])", calendar) if isinstance(calendar, str) else None
    if multiple and int(multiple.group(1)) != 1 and "fixed_interval" not in body:
        n, unit = int(multiple.group(1)), multiple.group(2)
        body.pop("calendar_interval")
        body["fixed_interval"] = f"{n * 7}d" if unit == "w" else f"{n}{unit}"
        notes.append(f"`calendar_interval` {calendar!r} is a multiple, so a fixed interval: {body['fixed_interval']!r}")
    if "target_bounds" in body and "extended_bounds" not in body:
        bounds = body.pop("target_bounds")
        if isinstance(bounds, dict):
            extended = {"min": bounds.get("gte", bounds.get("min")), "max": bounds.get("lte", bounds.get("max"))}
            body["extended_bounds"] = {k: v for k, v in extended.items() if v is not None}
            notes.append("used `target_bounds` as `extended_bounds` (the date_histogram option for empty buckets)")
    for key in ("size", "target", "target_bounds"):
        if key in body:
            body.pop(key)
            notes.append(f"dropped `{key}`: not a date_histogram option")
    order = body.get("order")
    if isinstance(order, dict) and not set(order) <= {"_key", "_count"}:
        body.pop("order")
        notes.append("dropped a date_histogram `order` that is not {_key|_count: asc|desc}")
    return body


def _drop_open_range_bounds(kind: str, body: dict[str, Any], notes: list[str]) -> dict[str, Any]:
    """`{"from": "*", "to": "*"}` means unbounded; ES wants the bound left out (D397: a raw date-parse 400)."""
    ranges = body.get("ranges")
    if not isinstance(ranges, list):
        return body
    cleaned = []
    dropped = False
    for item in ranges:
        if isinstance(item, dict):
            kept = {k: v for k, v in item.items() if not (k in ("from", "to") and v in ("*", None, ""))}
            dropped |= len(kept) != len(item)
            cleaned.append(kept)
        else:
            cleaned.append(item)
    if dropped:
        notes.append(f"left out `*` bounds in the {kind} ranges (an open bound is written by omitting it)")
    return {**body, "ranges": cleaned}


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
            spec = _query_clause_as_filter_agg(name, spec, notes)
            if isinstance(spec, dict) and any(k in spec for k in _AGG_TYPES):
                agg_type = next(k for k in spec if k in _AGG_TYPES)
                agg_body = spec.get(agg_type)
                if agg_type == "filter":
                    # A filter aggregation's body is a query: the query surface normalizes it.
                    fixed, sub_notes = normalize_query(agg_body, field_types=types)
                    notes.extend(sub_notes)
                    inner = spec.get("aggs") if isinstance(spec.get("aggs"), dict) else spec.get("aggregations")
                    out[name] = {"filter": fixed, **({"aggs": walk(inner, depth + 1)} if isinstance(inner, dict) else {})}
                    continue
                if agg_type == "filters" and isinstance(agg_body, dict) and isinstance(agg_body.get("filters"), dict):
                    # D405: each named condition of a `filters` aggregation is a query.
                    named = {}
                    for label, clause in agg_body["filters"].items():
                        fixed, sub_notes = normalize_query(clause, field_types=types)
                        notes.extend(sub_notes)
                        named[label] = fixed
                    inner = spec.get("aggs") if isinstance(spec.get("aggs"), dict) else spec.get("aggregations")
                    out[name] = {"filters": {**agg_body, "filters": named},
                                 **({"aggs": walk(inner, depth + 1)} if isinstance(inner, dict) else {})}
                    continue
                # Sub-aggregations belong BESIDE the agg type (`{"terms": {...}, "aggs": {...}}`). They were
                # moved inside the body with the stray options, which ES and validate_aggs reject: every
                # nested aggregation failed (6 of CASE-C5B04D31's 282 es_aggregate calls, D246). One written
                # inside the body is moved out.
                sub = spec.get("aggs") if isinstance(spec.get("aggs"), dict) else spec.get("aggregations")
                if isinstance(agg_body, dict) and isinstance(agg_body.get("aggs"), dict) and not isinstance(sub, dict):
                    sub = agg_body["aggs"]
                    agg_body = {k: v for k, v in agg_body.items() if k != "aggs"}
                    notes.append(f"moved `aggs` out of the `{agg_type}` body (sub-aggregations sit beside it)")
                # Named sub-aggregations written straight into the body (D405, T21 Mode 3: `first_ts: {min: ...}`
                # inside a `terms` body, refused as "unsupported terms options"). An entry that is itself an
                # aggregation and not one of the type's own options is a sub-aggregation.
                if isinstance(agg_body, dict):
                    own = _AGG_BODY_KEYS.get(agg_type, set())
                    nested = {k: v for k, v in agg_body.items() if k not in own and isinstance(v, dict)
                              and any(t in v for t in _AGG_TYPES)}
                    if nested:
                        agg_body = {k: v for k, v in agg_body.items() if k not in nested}
                        sub = {**(sub if isinstance(sub, dict) else {}), **nested}
                        notes.append(f"moved {sorted(nested)} out of the `{agg_type}` body: they are sub-aggregations")
                # Options written BESIDE the agg type, not inside it:
                # `{"terms": {...}, "shard_size": 200}`. Move them in.
                # An entry beside the type that is itself an aggregation is a named sub-aggregation (D405, T21 -518:
                # `by_dtype`/`first_ts`/`last_ts` beside `terms`, moved into its body as options and refused).
                beside_aggs = {k: v for k, v in spec.items() if k not in (agg_type, "aggs", "aggregations")
                               and isinstance(v, dict) and any(t in v for t in _AGG_TYPES)}
                if beside_aggs:
                    sub = {**(sub if isinstance(sub, dict) else {}), **beside_aggs}
                    notes.append(f"moved {sorted(beside_aggs)} into `aggs`: they are sub-aggregations, not "
                                 f"`{agg_type}` options")
                strag = {k: v for k, v in spec.items()
                         if k not in (agg_type, "aggs", "aggregations") and k not in beside_aggs}
                if strag and isinstance(agg_body, dict):
                    agg_body = {**agg_body, **strag}
                    notes.append(f"moved {sorted(strag)} inside the `{agg_type}` body")
                if isinstance(agg_body, dict):
                    patched = dict(agg_body)
                    # ES wants numbers for these; a model writes "100", or `true` for min_doc_count (D390).
                    for num_key in ("size", "shard_size", "min_doc_count",
                                    "precision_threshold"):
                        raw = patched.get(num_key)
                        if isinstance(raw, bool):
                            patched[num_key] = int(raw)
                            notes.append(f"coerced `{num_key}` from a boolean to {int(raw)}")
                        elif isinstance(raw, str) and raw.strip().isdigit():
                            patched[num_key] = int(raw.strip())
                            notes.append(f"coerced `{num_key}` from a string to a number")
                    if agg_type == "date_histogram":
                        patched = _normalize_date_histogram(patched, notes)
                    if agg_type in ("range", "date_range"):
                        patched = _drop_open_range_bounds(agg_type, patched, notes)
                    field = patched.get("field")
                    if isinstance(field, str):
                        target = _alias_field(field, types)
                        # `host`, `provider`, `family` and friends are this
                        # index's own short columns, not ECS paths.
                        if types and target not in types and target in ("host",):
                            notes.append(f"`{target}` is not mapped; no agg field change")
                        if target != field:
                            notes.append(f"aliased agg field `{field}` → `{target}`")
                        # Every doc-value aggregation needs the keyword sub-field of a text field (D391: a
                        # `cardinality` on text `fields.Executed` came back as a raw 400; only `terms` had it).
                        if agg_type in DOC_VALUE_AGGS and _is_text(types.get(target)):
                            kw = target + _KW_SUFFIX
                            if kw in types:
                                notes.append(
                                    f"aggregated on `{kw}` (keyword sub-field of `{target}`)"
                                )
                                target = kw
                        patched["field"] = target
                    # Composite sources recurse.
                    if isinstance(patched.get("sources"), list):
                        patched["sources"] = [
                            walk({f"s{i}": s}, depth + 1).get(f"s{i}", s)
                            for i, s in enumerate(patched["sources"])
                        ]
                    spec = {agg_type: patched}
                    if isinstance(sub, dict):
                        spec["aggs"] = walk(sub, depth + 1)
                out[name] = spec
            else:
                out[name] = walk(spec, depth + 1)
        return out

    return walk(body, 0), notes


def lift_aggs_query(aggs: Any) -> tuple[Any, dict[str, Any] | None, list[str]]:
    """The request's `query` written among the named aggs (D387) is the request query, not an aggregation.

    Measured on T21 Mode 2: `{"by_hash": {"terms": ...}, "query": {"match_all": {}}}` was refused as an aggregation
    called "query". It is lifted out when its body is a query clause; a real aggregation that happens to be named
    "query" (an agg body names its `field` or `sources`) stays where it is.
    """
    notes: list[str] = []
    if isinstance(aggs, dict) and "size" in aggs and not isinstance(aggs["size"], dict):
        # `size` among the named aggs (D405, T13 Mode 3) is a request option, refused as "agg 'size' must be an object".
        aggs = {name: value for name, value in aggs.items() if name != "size"}
        notes.append("dropped `size` from `aggs`: it is a request option (es_aggregate's size), not an aggregation")
    spec = aggs.get("query") if isinstance(aggs, dict) else None
    if not isinstance(spec, dict) or len(spec) != 1:
        return aggs, None, notes
    ((clause, body),) = spec.items()
    is_agg = clause in _AGG_TYPES and isinstance(body, dict) and ("field" in body or "sources" in body)
    if clause not in _QUERY_KEYS or is_agg:
        return aggs, None, notes
    rest = {name: value for name, value in aggs.items() if name != "query"}
    return rest, spec, [*notes, "moved `query` out of `aggs`: it is the request's query, not an aggregation"]


#: The three rules the model must follow, stated plainly (WO-R1F item 2b).
QUERY_RULES = (
    "query is a JSON OBJECT, sort is a LIST, and there is ONE top-level clause "
    "(combine with bool.must). e.g. "
    '{"query":{"bool":{"must":[{"term":{"ecs.host.name":"WS01"}},'
    '{"range":{"ts":{"gte":"2023-01-24"}}}]}},"sort":[{"ts":"asc"}],"size":50}'
)




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


#: How free-text search on ``text`` behaves (D195). Measured on CASE-C5B04D31 (2026-10-14):
#: ``{"match":{"text":"lsass"}}`` found 20 rows where ``*lsass*`` on ``text.wc`` found 18,970 (the
#: standard analyzer keeps ``lsass.exe`` as one word), and ``match`` on "Pass the Hash" returned
#: 37,786 rows holding ANY of the words where the phrase holds 17. The wording is true of every
#: index schema: the wildcard field matches inside words on old and new indexes alike.
_TEXT_SEARCH = (
    "TEXT SEARCH on `text` (the whole row):\n"
    "- A name or part of one (lsass, mimikatz, a file, host or task name): "
    '{"wildcard":{"text.wc":{"value":"*lsass*","case_insensitive":true}}} - it matches '
    'inside words. {"match":{"text":"lsass"}} can miss lsass.exe.\n'
    '- Several words in order: {"match_phrase":{"text":"pass the hash"}}. A multi-word '
    "`match` returns rows holding ANY of the words."
)


def query_protocol_block() -> str:
    """The three rules, three worked examples and text search, for every investigative prompt."""
    return f"ES QUERY PROTOCOL\n{QUERY_RULES}\n{_WORKED_EXAMPLES}\n{_TEXT_SEARCH}"
