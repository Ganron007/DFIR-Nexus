"""Generate the read-loop response contract from its consumers' contracts.

This constrains syntax, never evidence values or investigative choices. Native
Elasticsearch query objects and investigator-chosen aggregation names stay JSON.
The runtime validators and audit remain the authority even with a schema-capable
transport: a provider that ignores its contract must fail visibly.
"""
from __future__ import annotations

from inspect import signature
from types import UnionType
from typing import Any, Union, get_args, get_origin, get_type_hints

from nexus.langgraph import es_native as es
from nexus.langgraph.aggregation_contract import body_constraints, option_properties

CASE_FIELD_PREFIX = "case_fields_"


def _object(properties, required=(), **kwargs):
    return {"type": "object", "properties": properties, "required": list(required),
            "additionalProperties": False, **kwargs}


def _annotation(annotation):
    origin = get_origin(annotation)
    if origin in (Union, UnionType):
        return {"anyOf": [_annotation(part) for part in get_args(annotation)]}
    if origin is list:
        return {"type": "array", "items": _annotation(get_args(annotation)[0])}
    if origin is dict:
        return {"type": "object"}
    return {"type": {str: "string", int: "integer", float: "number", bool: "boolean",
                     type(None): "null"}[annotation]} if annotation in (str, int, float, bool, type(None)) else {}


def response_schema(case_id, parameters, required, string_fields, *, allowed_tools=()):
    """An argument grammar, not a query language or an answer/finding schema.

    Final domain objects retain their caller-defined keys. Every reply carries
    tool_calls (empty for a final answer), so a free final branch cannot bypass
    argument constraints. Tools without a field catalog can still introspect it.
    """
    types = es._field_types(case_id)
    definitions: dict[str, Any] = {}
    field_sets = {}
    for kind in sorted(es._AGG_TYPES | es._COMPOSITE_SOURCES):
        eligible = sorted(field for field in types if not field.startswith("_")
                          and not es.aggregation_field_problem(kind, field, types))
        key = CASE_FIELD_PREFIX + kind
        previous = field_sets.get(tuple(eligible))
        definitions[key] = ({"$ref": "#/$defs/" + previous} if previous else
                            {"type": "string", "enum": eligible})
        field_sets.setdefault(tuple(eligible), key)

    def body_schema(kind, keys, *, composite_source=False):
        props = option_properties(kind, composite_source=composite_source)
        assert set(props) == set(keys)
        if "field" in keys:
            props["field"] = {"$ref": "#/$defs/" + CASE_FIELD_PREFIX + kind}
        body = _object(props, **body_constraints(kind))
        if "ranges" in keys:
            body["description"] = es.aggregation_range_requirement(kind)
        return body

    sources = []
    for kind in sorted(es._COMPOSITE_SOURCES):
        sources.append(_object({kind: body_schema(kind, es._COMPOSITE_SOURCE_KEYS[kind], composite_source=True)}, [kind]))
    definitions["source"] = {"type": "object", "minProperties": 1, "maxProperties": 1,
                              "additionalProperties": {"anyOf": sources}}
    definitions["aggregations"] = {"type": "object", "minProperties": 1, "maxProperties": es.MAX_AGGS,
                                    "additionalProperties": {"$ref": "#/$defs/aggregation"}}
    nodes = []
    for kind in sorted(es._AGG_TYPES):
        body = {"type": "object"} if kind == "filter" else body_schema(kind, es._AGG_BODY_KEYS[kind])
        if kind == "composite":
            body["properties"].update({
                "sources": {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/source"}},
            })
        props = {kind: body}
        if kind != "top_hits":
            props["aggs"] = {"$ref": "#/$defs/aggregations"}
        nodes.append(_object(props, [kind]))
    definitions["aggregation"] = {"anyOf": nodes}
    calls = []
    for tool, names in parameters.items():
        if allowed_tools and tool not in allowed_tools:
            continue
        function = es.READ_TOOL_FUNCTIONS.get(tool)
        annotations = get_type_hints(function) if function else {}
        props = {name: _annotation(annotations.get(name)) for name in sorted(names)}
        for name in string_fields.get(tool, ()):
            props[name] = {"type": "string"}
        if function:
            assert set(props) == set(signature(function).parameters) - {"case_id"}
        if tool in es._READ_SIZE_MINIMUM:
            props["size"] = {"type": "integer", "minimum": es._READ_SIZE_MINIMUM[tool]}
        if tool == "es_aggregate":
            props["aggs"] = {"$ref": "#/$defs/aggregations"}
        args = _object(props, required.get(tool, ()))
        calls.append(_object({"tool": {"const": tool}, "args": args,
                              "why": {"type": "string"}}, ["tool", "args"]))
    return {"type": "object", "properties": {
        "tool_calls": {"type": "array", "items": {"anyOf": calls}},
    }, "required": ["tool_calls"], "additionalProperties": True, "$defs": definitions}


def supports_generation_schema(model):
    """The transport capability, shared by schema construction and binding."""
    return getattr(model, "_llm_type", "") == "openai-chat"


def generation_format(model, schema):
    """Use the OpenAI-compatible client's schema transport, without changing models.

    Other client transports keep their existing JSON protocol. They are not
    silently retried through it if a schema-capable request fails.
    """
    if not supports_generation_schema(model):
        return None
    return {"type": "json_schema", "json_schema": {
        "name": "read_loop", "strict": True, "schema": schema,
    }}
