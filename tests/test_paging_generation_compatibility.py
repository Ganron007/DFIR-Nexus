"""Preserve the exact paging language while avoiding unenforced conditionals."""
import copy
import itertools
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from nexus.langgraph.query_contract import definitions
from nexus.langgraph.read_request_contract import CURSOR, REQUEST_SORT, paging_constraints
from tests.test_read_paging_contract import schema  # noqa: F401

FIXTURES = Path(__file__).parent / "fixtures"


def test_union_accepts_exactly_the_original_outbound_paging_language():
    original = json.loads((FIXTURES / "agnes_paging_conditional_contract.json").read_text())
    replacement = {"type": "object", "properties": {
        "sort": {"anyOf": [REQUEST_SORT, {"type": "null"}]},
        "search_after": {"anyOf": [CURSOR, {"type": "null"}]},
    }, "additionalProperties": False, "anyOf": paging_constraints()}
    before = Draft202012Validator(original)
    after = Draft202012Validator(replacement)
    absent = object()
    sorts = [absent, None, [], *[["ts"] * n for n in range(1, 6)],
             "ts", [False], [{"ts": "up"}], [{"ts": {"order": "asc"}}]]
    cursors = [absent, None, [], *[[0] * n for n in range(1, 6)], "0", [{}], [[0]], [False], [None]]
    for sort, cursor in itertools.product(sorts, cursors):
        args = {}
        if sort is not absent:
            args["sort"] = sort
        if cursor is not absent:
            args["search_after"] = cursor
        assert before.is_valid(args) == after.is_valid(args), args


def test_actual_generation_schema_contains_no_conditional_keywords(request):
    contract = request.getfixturevalue("schema")
    def walk(node):
        if isinstance(node, dict):
            assert not set(node) & {"if", "then", "else"}
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    walk(contract)
    calls = contract["properties"]["tool_calls"]["items"]["anyOf"]
    args = next(c["properties"]["args"] for c in calls if c["properties"]["tool"]["const"] == "es_search")
    # The old signature metadata remains usable, and every independently
    # compilable branch retains the same complete argument allowlist.
    assert len(args["anyOf"]) == 5
    for branch in args["anyOf"]:
        assert set(branch["properties"]) == set(args["properties"])
        assert branch["additionalProperties"] is False
        assert "query" in branch["required"]
        wrong = {"query": {"match_all": {}}, "sort": ["ts"], "search_after": [{"not": "scalar"}]}
        standalone = {**branch, "$defs": contract["$defs"]}
        assert not Draft202012Validator(standalone).is_valid(wrong)


def test_terms_union_preserves_the_exact_optional_boost_contract():
    original = json.loads((FIXTURES / "query_terms_conditional_contract.json").read_text())
    before = Draft202012Validator(original)
    after = Draft202012Validator(definitions()["query_body_terms"])
    values = [[], ["cloudtrail"], [1, False, None], "cloudtrail", 2, False, {}, [[1]]]
    absent = object()
    for first, second, boost in itertools.product(values, [absent, *values], [absent, 2, "2", False, [2]]):
        body = {"family": first}
        if second is not absent:
            body["other"] = second
        if boost is not absent:
            body["boost"] = boost
        assert before.is_valid(body) == after.is_valid(body), body
    for body in ({}, {"boost": 2}, {"boost": [2]}):
        assert before.is_valid(body) == after.is_valid(body) is False


@pytest.mark.parametrize("entry", json.loads((FIXTURES / "agnes_paging_refusals.json").read_text()),
                         ids=lambda e: e["control"])
def test_both_exact_refused_provider_replies_remain_invalid(request, entry):
    contract = request.getfixturevalue("schema")
    reply = copy.deepcopy(entry["reply"])
    assert list(Draft202012Validator(contract).iter_errors(reply))
    assert reply == entry["reply"]
