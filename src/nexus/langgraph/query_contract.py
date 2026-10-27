"""Canonical ES query grammar and mapped value compatibility for both ends.

The structural safety guard remains a separate check (scripts, depth and regex
work). This contract supplies complete recursive shapes and option values. Case
field enums constrain known types while unknown names remain legal schema hints.
"""
from __future__ import annotations

import math
import re
from copy import deepcopy
from functools import lru_cache
from typing import Any

from nexus.langgraph.aggregation_contract import normalize_scalar_options, object_schema

MAX_BOOL_DEPTH = 6
MAX_TERMS = 5000
MAX_IDS = 1000
MAX_REGEXP = 200
CASE_FIELD_PREFIX = "case_fields_"
NUMERIC_TYPES = frozenset({"long", "integer", "short", "byte", "double", "float", "half_float",
                           "scaled_float", "unsigned_long"})
DATE_TYPES = frozenset({"date", "date_nanos"})
BOOL_TYPES = frozenset({"boolean"})
PATTERN_TYPES = frozenset({"text", "keyword", "wildcard"})
PATTERN_CLAUSES = frozenset({"prefix", "wildcard", "regexp"})
ANALYZED_CLAUSES = frozenset({"match", "match_phrase"})
SCRIPT_FIELD_CLAUSES = frozenset({"term", "match", "match_phrase", "prefix", "wildcard"})
SCRIPT_FIELD_PATTERN = r"(?:^_?[sS][cC][rR][iI][pP][tT](?:\.|$)|\._?[sS][cC][rR][iI][pP][tT]$)"
SCALAR = {"type": ["string", "number", "boolean"]}
STRING = {"type": "string"}
NUMBER = {"type": "number"}
BOOLEAN = {"type": "boolean"}
MINIMUM_SHOULD_MATCH = {"type": ["integer", "string"]}
CLAUSE_OPTIONS = {
    **{kind: {"boost": NUMBER, "case_insensitive": BOOLEAN} for kind in ("term", "prefix", "wildcard")},
    "match": {"boost": NUMBER, "operator": {"enum": ["and", "or"]},
              "minimum_should_match": MINIMUM_SHOULD_MATCH,
              "fuzziness": {"type": ["string", "number"]}, "lenient": BOOLEAN},
    "match_phrase": {"boost": NUMBER, "slop": {"type": "integer", "minimum": 0}},
    "regexp": {"case_insensitive": BOOLEAN, "flags": STRING},
}
VALUE_KEYS = {kind: "query" if kind in ANALYZED_CLAUSES else "value" for kind in CLAUSE_OPTIONS}
# Legacy spellings are recognized structurally so normalization can report them;
# they are not valid canonical options and cannot reach ES through this contract.
STRUCTURAL_FIELD_OPTIONS = {
    kind: frozenset(options) | ({"case_insensitive"} if kind in ANALYZED_CLAUSES else set())
    for kind, options in CLAUSE_OPTIONS.items()
}
VALUE_CLAUSES = frozenset(set(CLAUSE_OPTIONS) - ANALYZED_CLAUSES)
RANGE_BOUND_KEYS = frozenset({"gte", "gt", "lte", "lt"})
RANGE_OPTIONS = {**dict.fromkeys(sorted(RANGE_BOUND_KEYS), {"type": ["string", "number"]}),
                 "format": STRING, "boost": NUMBER, "time_zone": STRING}
TERMS_OPTIONS = {"boost": NUMBER}
FIELD_CLAUSES = frozenset(set(CLAUSE_OPTIONS) | {"terms", "range"})
QUERY_KEYS = FIELD_CLAUSES | {"bool", "multi_match", "exists", "match_all", "match_none", "ids"}
BOOL_KEYS = frozenset({"must", "should", "must_not", "filter", "minimum_should_match"})


def normalize_clause_options(clause: str, body):
    options = TERMS_OPTIONS if clause == "terms" else CLAUSE_OPTIONS[clause]
    return normalize_scalar_options(options, body, label=clause)


def value_group(kind: str) -> str:
    return ("numeric" if kind in NUMERIC_TYPES else "date" if kind in DATE_TYPES else
            "boolean" if kind in BOOL_TYPES else "unsupported" if kind in ("object", "nested") else "scalar")


def value_schema(group: str):
    if group == "numeric":
        return {"anyOf": [NUMBER, {"type": "string", "pattern":
                r"^\s*[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\s*$"}]}
    if group == "date":
        return {"anyOf": [NUMBER, {"type": "string", "pattern": r"^(?:[0-9]+|[0-9]{4}-.*)$"}]}
    if group == "boolean":
        return {"anyOf": [BOOLEAN, {"type": "string", "enum": ["true", "false"]}]}
    return False if group == "unsupported" else deepcopy(SCALAR)


def value_compatible(kind: str, value: Any) -> bool:
    """Native semantic backstop beyond what JSON schema/provider patterns express."""
    if value is None:
        return True  # Null members of a terms list do not supply a term.
    if kind in NUMERIC_TYPES:
        if isinstance(value, bool):
            return False
        try:
            return math.isfinite(float(value))
        except (TypeError, ValueError):
            return False
    if kind in DATE_TYPES:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return math.isfinite(value)
        s = str(value)
        if isinstance(value, bool) or not (s[:4].isdigit() and ("-" in s or s.isdigit())):
            return False
        parts = s[:10].split("-")
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            from datetime import date

            try:
                date(int(parts[0]), int(parts[1]), int(parts[2]))
            except ValueError:
                return False
        return True
    if kind in BOOL_TYPES:
        return isinstance(value, bool) or (isinstance(value, str) and value in ("true", "false"))
    return kind not in ("object", "nested")


def field_problem(clause: str, field: str, types: dict[str, str]) -> str:
    if clause in SCRIPT_FIELD_CLAUSES and unsafe_field_name(field):
        return "field names cannot contain scripts"
    kind = types.get(field)
    if kind and clause in PATTERN_CLAUSES and kind not in PATTERN_TYPES:
        return f"`{field}` is {kind}: a {clause} pattern applies to text; use term, terms or range"
    if kind and clause == "match_phrase" and kind not in PATTERN_TYPES:
        return f"`{field}` is {kind}: match_phrase needs a text or keyword field"
    return ""


def unsafe_field_name(field: str) -> bool:
    return bool(re.search(SCRIPT_FIELD_PATTERN, field))


def definitions(types: dict[str, str] | None = None) -> dict[str, Any]:
    """Recursive grammar; field-dependent values are shared with native checks."""
    out: dict[str, Any] = {}
    known = sorted(types or {})
    all_key = CASE_FIELD_PREFIX + "query_all"
    enum_sets = {}
    if known:
        out[all_key] = {"type": "string", "enum": known}
        enum_sets[tuple(known)] = all_key

    def field_body(clause, wrap):
        # A body is always exactly one field, except the optional terms boost.
        groups = {}
        for field, kind in (types or {}).items():
            if not field_problem(clause, field, types or {}):
                groups.setdefault(value_group(kind), []).append(field)
        choices = []
        for group, fields in sorted(groups.items()):
            if group == "unsupported":
                continue
            key = CASE_FIELD_PREFIX + "query_" + clause + "_" + group
            values = tuple(sorted(fields))
            previous = enum_sets.get(values)
            out[key] = ({"$ref": "#/$defs/" + previous} if previous else
                        {"type": "string", "enum": list(values)})
            enum_sets.setdefault(values, key)
            choices.append(({"$ref": "#/$defs/" + key}, wrap(value_schema(group))))
        unknown = {"not": {"$ref": "#/$defs/" + all_key}} if known else {"type": "string"}
        if clause in SCRIPT_FIELD_CLAUSES:
            unknown = {"allOf": [unknown, {"not": {"pattern": SCRIPT_FIELD_PATTERN}}]}
        choices.append((unknown, wrap(deepcopy(SCALAR))))
        bodies = []
        for names, value in choices:
            if clause == "terms":
                body = {"type": "object", "properties": deepcopy(TERMS_OPTIONS),
                        "additionalProperties": value,
                        "propertyNames": {"anyOf": [{"enum": sorted(TERMS_OPTIONS)}, names]},
                        "if": {"required": ["boost"]},
                        "then": {"minProperties": 2, "maxProperties": 2},
                        "else": {"minProperties": 1, "maxProperties": 1}}
            else:
                body = {"type": "object", "minProperties": 1, "maxProperties": 1,
                        "propertyNames": names, "additionalProperties": value}
            bodies.append(body)
        return {"anyOf": bodies}

    bodies = {}
    for clause, options in CLAUSE_OPTIONS.items():
        def wrap(value, clause=clause, options=options):
            if value is False:
                return False
            if clause in PATTERN_CLAUSES:
                value = {"type": "string", **({"maxLength": MAX_REGEXP} if clause == "regexp" else {})}
            obj = object_schema({VALUE_KEYS[clause]: value, **deepcopy(options)}, [VALUE_KEYS[clause]])
            return obj if clause == "regexp" else {"anyOf": [value, obj]}

        bodies[clause] = field_body(clause, wrap)
    bodies["terms"] = field_body("terms", lambda value: {
        "type": "array", "minItems": 1, "maxItems": MAX_TERMS,
        "items": {"anyOf": [value, {"type": "null"}]},
    })
    bodies["range"] = field_body("range", lambda value: object_schema({
        **deepcopy(RANGE_OPTIONS), **{key: value for key in sorted(RANGE_BOUND_KEYS)},
    }))
    bodies["exists"] = object_schema({"field": {"type": "string"}}, ["field"])
    bodies["ids"] = object_schema({"values": {"type": "array", "maxItems": MAX_IDS,
                                              "items": {"type": ["string", "number"]}}}, ["values"])
    for clause in ("match_all", "match_none"):
        bodies[clause] = object_schema({})
    bodies["multi_match"] = object_schema({
        "query": STRING, "fields": {"type": "array", "items": {"type": "string", "pattern": "^[^_]"}},
        "type": {"enum": ["best_fields", "most_fields", "cross_fields", "phrase", "phrase_prefix", "bool_prefix"]},
        "operator": {"enum": ["and", "or"]}, "minimum_should_match": MINIMUM_SHOULD_MATCH,
        "analyzer": STRING, "boost": NUMBER, "lenient": BOOLEAN, "slop": {"type": "integer", "minimum": 0},
        "fuzziness": {"type": ["string", "number"]}, "fuzzy_rewrite": STRING, "tie_breaker": NUMBER,
        "prefix_length": {"type": "integer", "minimum": 0},
        "max_expansions": {"type": "integer", "minimum": 1},
        "fuzzy_transpositions": BOOLEAN, "auto_generate_synonyms_phrase_query": BOOLEAN,
        "zero_terms_query": {"enum": ["none", "all"]},
    }, ["query"])
    for clause, body in bodies.items():
        out["query_body_" + clause] = body
    # The same six-bool-level bound as the native safety guard. A leaf can sit
    # one level below the last bool, but cannot start another bool there.
    for depth in range(MAX_BOOL_DEPTH + 2):
        props = {kind: {"$ref": "#/$defs/query_body_" + kind} for kind in bodies}
        if depth <= MAX_BOOL_DEPTH:
            child = {"$ref": "#/$defs/query_" + str(depth + 1)}
            props["bool"] = object_schema({
                **{key: {"anyOf": [child, {"type": "array", "items": child}]}
                   for key in sorted(BOOL_KEYS - {"minimum_should_match"})},
                "minimum_should_match": MINIMUM_SHOULD_MATCH,
            })
        out["query_" + str(depth)] = object_schema(props, minProperties=1, maxProperties=1)
    out["query"] = {"$ref": "#/$defs/query_0"}
    return out


@lru_cache(maxsize=1)
def _validator():
    from jsonschema import Draft202012Validator

    return Draft202012Validator({"$ref": "#/$defs/query", "$defs": definitions()})


def canonical_problem(query) -> str:
    error = next(_validator().iter_errors(query), None)
    if error is None:
        return ""
    return "query contract " + ".".join(map(str, error.absolute_path)) + ": " + error.message
