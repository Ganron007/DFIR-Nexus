"""Canonical aggregation option values, shared by generation and execution.

Names belong to the investigator; options belong to the ES 8 read contract.
The normalizer converts unambiguous scalar spellings to these canonical types
and reports each conversion. It never guesses a size from a list of values.
"""
from __future__ import annotations

import math
import re
from copy import deepcopy
from typing import Any

TOP_HITS_MIN = 1
TOP_HITS_MAX = 20
COMPOSITE_SIZE_MIN = 1
COMPOSITE_SIZE_MAX = 1000
RANGE_BOUND_KEYS = frozenset({"from", "to", "key"})
FIXED_DURATION = re.compile(r"[1-9][0-9]*(?:ms|[smhd])")


def object_schema(properties, required=(), **kwargs):
    return {"type": "object", "properties": properties, "required": list(required),
            "additionalProperties": False, **kwargs}


STRING = {"type": "string"}
FIELD = {"type": "string", "minLength": 1}
SCALAR = {"type": ["string", "number", "boolean", "null"]}
BOUND = {"type": ["string", "number", "null"]}
DIRECTION = {"type": "string", "enum": ["asc", "desc"]}
STRING_LIST = {"type": "array", "items": STRING}
STRINGS = {"anyOf": [STRING, STRING_LIST]}
ORDER_MAP = {"type": "object", "minProperties": 1, "additionalProperties": DIRECTION}
ORDER = {"anyOf": [ORDER_MAP, {"type": "array", "minItems": 1, "items": ORDER_MAP}]}
SORT_SPEC = {"anyOf": [DIRECTION, object_schema({
    "order": DIRECTION, "missing": SCALAR, "unmapped_type": STRING,
})]}
SORT_ENTRY = {"anyOf": [STRING, {"type": "object", "minProperties": 1, "maxProperties": 1,
                               "additionalProperties": SORT_SPEC}]}
SORT = {"type": "array", "items": SORT_ENTRY}
SOURCE = {"anyOf": [{"type": "boolean"}, STRINGS, object_schema({
    "includes": STRINGS, "excludes": STRINGS,
})]}
RANGES = {"type": "array", "minItems": 1,
          "items": object_schema({key: STRING if key == "key" else BOUND
                                  for key in sorted(RANGE_BOUND_KEYS)})}
BOUNDS = object_schema({"min": BOUND, "max": BOUND})
VALUES_OR_PATTERN = {"anyOf": [STRING, {"type": "array", "items": SCALAR}]}
INCLUDE = {"anyOf": [VALUES_OR_PATTERN, object_schema({
    "partition": {"type": "integer", "minimum": 0},
    "num_partitions": {"type": "integer", "minimum": 1},
}, ["partition", "num_partitions"])]}

OPTIONS: dict[str, dict[str, Any]] = {
    "terms": {
        "field": FIELD, "size": {"type": "integer", "minimum": 1}, "order": ORDER,
        "missing": SCALAR, "min_doc_count": {"type": "integer", "minimum": 0},
        "shard_size": {"type": "integer", "minimum": 1}, "include": INCLUDE, "exclude": VALUES_OR_PATTERN,
    },
    "date_histogram": {
        "field": FIELD, "calendar_interval": STRING,
        "fixed_interval": {"type": "string", "pattern": "^" + FIXED_DURATION.pattern + "$"},
        "time_zone": STRING, "format": STRING, "min_doc_count": {"type": "integer", "minimum": 0},
        "missing": SCALAR, "order": ORDER, "offset": {"type": ["string", "number"]},
        "extended_bounds": BOUNDS, "hard_bounds": BOUNDS,
    },
    "date_range": {"field": FIELD, "ranges": RANGES, "format": STRING, "time_zone": STRING,
                   "keyed": {"type": "boolean"}, "missing": SCALAR},
    "histogram": {"field": FIELD, "interval": {"type": "number", "exclusiveMinimum": 0},
                  "min_doc_count": {"type": "integer", "minimum": 0}, "missing": SCALAR,
                  "order": ORDER, "offset": {"type": "number"}},
    "range": {"field": FIELD, "ranges": RANGES, "keyed": {"type": "boolean"}, "missing": SCALAR},
    "cardinality": {"field": FIELD, "precision_threshold": {"type": "integer", "minimum": 0},
                    "missing": SCALAR},
    **{kind: {"field": FIELD, "missing": SCALAR, "format": STRING}
       for kind in ("min", "max", "avg", "sum", "stats")},
    "value_count": {"field": FIELD, "missing": SCALAR},
    "composite": {
        "sources": {"type": "array", "minItems": 1, "items": {
            "type": "object", "minProperties": 1, "maxProperties": 1,
            "additionalProperties": {"type": "object"},
        }},
        "size": {"type": "integer", "minimum": COMPOSITE_SIZE_MIN, "maximum": COMPOSITE_SIZE_MAX},
        "after": {"type": "object", "additionalProperties": SCALAR},
    },
    "filters": {
        "filters": {"anyOf": [{"type": "object", "minProperties": 1,
                                "additionalProperties": {"type": "object"}},
                               {"type": "array", "minItems": 1, "items": {"type": "object"}}]},
        "other_bucket": {"type": "boolean"}, "other_bucket_key": STRING,
    },
    "top_hits": {"size": {"type": "integer", "minimum": TOP_HITS_MIN, "maximum": TOP_HITS_MAX},
                 "_source": SOURCE, "sort": SORT},
}

COMPOSITE_OPTIONS = {
    kind: {**{key: OPTIONS[kind][key] for key in keys},
           "order": DIRECTION, "missing_bucket": {"type": "boolean"}}
    for kind, keys in {
        "terms": ["field"],
        "date_histogram": ["field", "calendar_interval", "fixed_interval", "time_zone", "format", "offset"],
        "histogram": ["field", "interval", "offset"],
    }.items()
}

REQUIRED_KEYS = {
    kind: (["sources"] if kind == "composite" else
           ["filters"] if kind == "filters" else
           [] if kind in ("filter", "top_hits") else
           ["field", "ranges"] if kind in ("range", "date_range") else
           ["field", "interval"] if kind == "histogram" else ["field"])
    for kind in set(OPTIONS) | {"filter"}
}


def body_constraints(kind: str) -> dict[str, Any]:
    constraints: dict[str, Any] = {"required": REQUIRED_KEYS[kind]}
    if kind == "date_histogram":
        constraints["oneOf"] = [{"required": [name]} for name in ("calendar_interval", "fixed_interval")]
    return deepcopy(constraints)


def option_properties(kind: str, *, composite_source: bool = False) -> dict[str, Any]:
    """Give callers independent schemas; case-specific field enums never mutate the owner."""
    return deepcopy((COMPOSITE_OPTIONS if composite_source else OPTIONS)[kind])


def option_problem(kind: str, body: dict[str, Any], *, composite_source: bool = False) -> str:
    """Only option values here; the native structural guard owns unknown-key errors."""
    from jsonschema import Draft202012Validator

    error = next(Draft202012Validator({
        "type": "object", "properties": option_properties(kind, composite_source=composite_source),
        **body_constraints(kind),
    }).iter_errors(body), None)
    if error is None:
        return ""
    path = " ".join(map(str, error.absolute_path))
    return f"{kind} {path}: {error.message}"


def normalize_option_values(kind: str, body: Any, *, composite_source: bool = False):
    """Convert exact scalar spellings, never containers or fractional sizes."""
    if not isinstance(body, dict) or kind == "filter":
        return body, []
    properties = (COMPOSITE_OPTIONS if composite_source else OPTIONS).get(kind, {})
    out = dict(body)
    notes = []
    for key, spec in properties.items():
        value = out.get(key)
        expected = spec.get("type")
        if expected == "integer" and isinstance(value, bool):
            # Existing D390 compiler semantics: a boolean document-count switch
            # is explicit 0/1. Generation itself emits canonical integers.
            out[key] = int(value)
            notes.append(f"normalized {kind}.{key} boolean to integer {int(value)}")
            continue
        if not isinstance(value, str):
            continue
        converted: Any = value
        if expected == "integer" and re.fullmatch(r"[+-]?[0-9]+", value.strip()):
            converted = int(value)
        elif expected == "number":
            try:
                number = float(value)
            except ValueError:
                continue
            if math.isfinite(number):
                converted = number
        elif expected == "boolean" and value.lower() in ("true", "false"):
            converted = value.lower() == "true"
        if converted != value:
            out[key] = converted
            notes.append(f"normalized {kind}.{key} scalar {value!r} to {expected}")
    return out, notes
