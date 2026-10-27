"""Shared search paging contract; request options never belong to query clauses."""
from __future__ import annotations

import json
import math
from copy import deepcopy
from functools import lru_cache

from jsonschema import Draft202012Validator

from nexus.langgraph.aggregation_contract import SCALAR, SORT

MAX_SORT_FIELDS = 4
DEFAULT_CURSOR_SORT = ("_doc",)
ENVELOPE_KEYS = frozenset({"size", "from", "sort", "search_after", "_source", "track_total_hits"})
REQUEST_SORT = {**deepcopy(SORT), "maxItems": MAX_SORT_FIELDS}
CURSOR = {"type": "array", "maxItems": MAX_SORT_FIELDS, "items": deepcopy(SCALAR)}


def paging_constraints():
    """Equivalent union branches avoid unsupported conditional schema keywords.

    No cursor permits every supported sort. A nonempty cursor fixes the
    effective sort length; the single default sort also permits omission/null.
    Native validation enforces the same relationship independently.
    """
    branches = [{"properties": {"search_after": {"anyOf": [
        {"type": "null"}, {**deepcopy(CURSOR), "maxItems": 0}]}}}]
    for count in range(1, MAX_SORT_FIELDS + 1):
        exact_sort = {**deepcopy(REQUEST_SORT), "minItems": count, "maxItems": count}
        branch = {"properties": {"sort": exact_sort}, "required": ["sort", "search_after"]}
        if count == len(DEFAULT_CURSOR_SORT):
            branch = {"properties": {"sort": {"anyOf": [exact_sort,
                {"type": "null"}, {"type": "array", "maxItems": 0}]}}, "required": ["search_after"]}
        branch["properties"]["search_after"] = {**deepcopy(CURSOR), "minItems": count, "maxItems": count}
        branches.append(branch)
    return branches


@lru_cache(maxsize=1)
def _sort_validator():
    return Draft202012Validator(REQUEST_SORT)


def sort_problem(sort):
    if sort is None:
        return ""
    error = next(_sort_validator().iter_errors(sort), None)
    return f"sort must be a list of at most {MAX_SORT_FIELDS} entries with valid directions/options" if error else ""


def paging_problem(sort, cursor):
    if error := sort_problem(sort):
        return error
    if cursor is None:
        return ""
    if (not isinstance(cursor, list) or len(cursor) > MAX_SORT_FIELDS
            or any(not (v is None or isinstance(v, (str, int, float, bool)))
                   or isinstance(v, float) and not math.isfinite(v) for v in cursor)):
        return "search_after must be a list of finite scalar values, one per sort entry"
    count = len(sort or DEFAULT_CURSOR_SORT)
    if cursor and len(cursor) != count:
        return f"search_after has {len(cursor)} values but effective sort has {count} entries"
    return ""


def query_envelope_problem(query, path="query", depth=0):
    """Inspect clause slots, never field names or user-provided scalar data.

    A nested size can conflict with an explicit argument or its materialized
    default; lifting it would guess intent. Refuse it before normalization can
    discard it. The producer supplies canonical request arguments instead.
    """
    if depth > 12:
        return ""
    if isinstance(query, str):
        try:
            query = json.loads(query)
        except (ValueError, TypeError):
            return ""
    if not isinstance(query, dict):
        return ""
    misplaced = sorted(set(query) & ENVELOPE_KEYS)
    if misplaced:
        return (f"request option(s) {', '.join(misplaced)} at {path}: pass supported options "
                "as tool arguments; conflicting or unsupported envelopes cannot be discarded")
    if "query" in query:
        if set(query) != {"query"}:
            return f"request option or sibling clause at {path}.query envelope: pass a single query and separate tool arguments"
        if problem := query_envelope_problem(query["query"], path + ".query", depth + 1):
            return problem
    body = query.get("bool", query if set(query) & {"must", "filter", "must_not", "should"} else None)
    if isinstance(body, dict):
        misplaced = sorted(set(body) & ENVELOPE_KEYS)
        if misplaced:
            return f"request option(s) {', '.join(misplaced)} at {path}.bool: pass them as tool arguments"
        for key in ("must", "filter", "must_not", "should"):
            children = body.get(key, [])
            children = children if isinstance(children, list) else [children]
            for child in children:
                if problem := query_envelope_problem(child, path + ".bool." + key, depth + 1):
                    return problem
    return ""


def aggregation_envelope_problem(aggs, depth=0):
    if isinstance(aggs, str):
        try:
            aggs = json.loads(aggs)
        except (ValueError, TypeError):
            return ""
    if depth > 12 or not isinstance(aggs, dict):
        return ""
    for name, node in aggs.items():
        if not isinstance(node, dict):
            continue
        if name == "query" and (problem := query_envelope_problem(node)):
            return problem
        if "filter" in node and (problem := query_envelope_problem(node["filter"], "aggs." + name + ".filter")):
            return problem
        if isinstance(node.get("filters"), dict):
            filters = node["filters"].get("filters", {})
            queries = filters.values() if isinstance(filters, dict) else filters if isinstance(filters, list) else []
            for query in queries:
                if problem := query_envelope_problem(query, "aggs." + name + ".filters"):
                    return problem
        if problem := aggregation_envelope_problem(node.get("aggs", {}), depth + 1):
            return problem
    return ""
