"""Generate the read-loop response contract from its consumers' contracts.

This constrains syntax, never evidence values or investigative choices. Native
Elasticsearch query objects and investigator-chosen aggregation names stay JSON.
The runtime validators and audit remain the authority even with a schema-capable
transport: a provider that ignores its contract must fail visibly.
"""
from __future__ import annotations

from copy import deepcopy
from inspect import signature
from types import UnionType
from typing import Any, Union, get_args, get_origin, get_type_hints

from nexus.langgraph import es_native as es
from nexus.langgraph.aggregation_contract import body_constraints, option_properties
from nexus.langgraph.query_contract import CASE_FIELD_PREFIX
from nexus.langgraph.query_contract import definitions as query_definitions
from nexus.langgraph.read_request_contract import CURSOR, REQUEST_SORT, paging_constraints


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


def response_schema(case_id, parameters, required, string_fields, *, allowed_tools=(), extra_properties=None):
    """An argument grammar, not a query language or an answer/finding schema.

    Final domain objects retain their caller-defined keys. Every reply carries
    tool_calls (empty for a final answer), so a free final branch cannot bypass
    argument constraints. Tools without a field catalog can still introspect it.
    ``extra_properties`` declares a caller's own required keys beside tool_calls (Mode 1's plan: its
    hypotheses or notes): under strict decoding a key the schema does not declare is not generated.
    """
    types = es._field_types(case_id)
    definitions: dict[str, Any] = query_definitions(types)
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
        body = {"$ref": "#/$defs/query"} if kind == "filter" else body_schema(kind, es._AGG_BODY_KEYS[kind])
        if kind == "filters":
            body["properties"]["filters"] = {"anyOf": [
                {"type": "object", "minProperties": 1, "additionalProperties": {"$ref": "#/$defs/query"}},
                {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/query"}},
            ]}
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
        if tool in ("es_search", "es_aggregate"):
            query = {"$ref": "#/$defs/query"}
            props["query"] = query if "query" in required.get(tool, ()) else {"anyOf": [query, {"type": "null"}]}
            props["sort"] = {"anyOf": [REQUEST_SORT, {"type": "null"}]}
        if tool == "es_search":
            props["search_after"] = {"anyOf": [CURSOR, {"type": "null"}]}
        if tool == "es_aggregate":
            props["aggs"] = {"$ref": "#/$defs/aggregations"}
        args = _object(props, required.get(tool, ()))
        if tool == "es_search":
            variants = []
            for branch in paging_constraints():
                variant_props = {**deepcopy(props), **branch["properties"]}
                variant_required = list(dict.fromkeys([*required.get(tool, ()), *branch.get("required", ())]))
                variants.append(_object(variant_props, variant_required))
            args["anyOf"] = variants
        calls.append(_object({"tool": {"const": tool}, "args": args,
                              "why": {"type": "string"}}, ["tool", "args"]))
    extra = dict(extra_properties or {})
    return {"type": "object", "properties": {
        "tool_calls": {"type": "array", "items": {"anyOf": calls}}, **extra,
    }, "required": ["tool_calls", *extra], "additionalProperties": True, "$defs": definitions}


def refused_calls(schema, reply):
    """The calls of a schema-bound reply that the schema refuses, each with the validator's own reason (D464).

    A provider can ignore the strict schema. Validating the reply whole refused every call in it for one bad
    argument and said only "not valid under any of the given schemas"; each call is checked against its own
    tool's branch, so the valid calls run and the model is told what was wrong with the others.
    """
    from jsonschema import Draft202012Validator

    def deepest(errors):
        """The failures under each `anyOf` (the query union, the paging variants hide the argument at fault),
        deepest first: up to three distinct ones, so a call with two faults names both."""
        leaves, stack = [], list(errors)
        while stack:
            error = stack.pop()
            if error.context:
                stack.extend(error.context)
            else:
                leaves.append(error)
        leaves.sort(key=lambda error: -len(error.absolute_path))
        reasons = dict.fromkeys(f"{'/'.join(str(part) for part in error.absolute_path) or 'the call'}: "
                                f"{error.message}" for error in leaves)
        return "; ".join(list(reasons)[:3])[:600]

    defs = schema.get("$defs") or {}
    branches = {}
    for branch in schema["properties"]["tool_calls"]["items"]["anyOf"]:
        branches[branch["properties"]["tool"]["const"]] = branch
    refused = []
    for call in reply.get("tool_calls") or []:
        tool = call.get("tool") if isinstance(call, dict) else None
        branch = branches.get(tool)
        if branch is None:
            refused.append((call, f"`{tool}` is not one of this seat's tools ({', '.join(sorted(branches))})"))
            continue
        errors = list(Draft202012Validator({**branch, "$defs": defs}).iter_errors(call))
        if errors:
            refused.append((call, deepest(errors)))
    return refused


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
