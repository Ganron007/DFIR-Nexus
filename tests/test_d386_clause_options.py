"""D386: a field clause's options written beside its field are moved inside the field's object.

R1z3 (2026-10-25): T10 Mode 2 lost 5 verifier `es_search` calls and T21 Mode 2 more, all refused with "wildcard
takes exactly one field". The model wrote ES's short form with an option beside the field,
`{"wildcard": {"text": "*x*", "case_insensitive": true}}`; Elasticsearch reads that as two fields, and so did the
validator. The normalizer repaired other wildcard shapes but not this one, for any field clause. The queries below are
the refused ones, verbatim from the case audit logs. The options a clause takes have one definition,
`es_native.FIELD_CLAUSE_OPTIONS`, read by both the validator and the normalizer (rule 16).
"""
from __future__ import annotations

import pytest

from nexus.langgraph import es_native, query_normalize
from nexus.langgraph.es_native import ESQueryError, validate_query
from nexus.langgraph.query_normalize import normalize_query

TYPES = {"ts": "date", "text": "text", "text.wc": "wildcard", "file": "keyword", "family": "keyword"}

#: es_search params from audit nexus-claudebot-20261025-011 (T21) and -022 (T10).
_T21 = {"bool": {"must": [{"wildcard": {"text": "*downloadfile*", "case_insensitive": True}}]}}
_T10 = {"wildcard": {"text": "*recommendations@explore.pinterest.com*", "case_insensitive": True}}


def test_the_recorded_queries_were_refused_before_normalizing():
    for query in (_T21, _T10):
        with pytest.raises(ESQueryError, match="wildcard takes exactly one field"):
            validate_query(query)


def test_the_recorded_queries_normalize_to_valid_es_and_say_so():
    out, notes = normalize_query(_T10, field_types=TYPES)
    validate_query(out)
    ((field, spec),) = out["wildcard"].items()
    assert spec == {"value": "*recommendations@explore.pinterest.com*", "case_insensitive": True}
    assert any("case_insensitive" in n and "inside" in n for n in notes)

    out, notes = normalize_query(_T21, field_types=TYPES)
    validate_query(out)
    ((field, spec),) = out["bool"]["must"][0]["wildcard"].items()
    assert spec == {"value": "*downloadfile*", "case_insensitive": True}


@pytest.mark.parametrize("kind", ["term", "prefix", "wildcard"])
def test_every_value_clause_folds_its_options(kind):
    out, notes = normalize_query({kind: {"file": "Zoom", "case_insensitive": True, "boost": 2}}, field_types=TYPES)
    validate_query(out)
    assert out == {kind: {"file": {"value": "Zoom", "case_insensitive": True, "boost": 2}}}
    assert notes


def test_regexp_folds_its_own_options():
    out, _ = normalize_query({"regexp": {"file": "zoom.*", "flags": "ALL"}}, field_types=TYPES)
    validate_query(out)
    assert out == {"regexp": {"file": {"value": "zoom.*", "flags": "ALL"}}}


def test_an_option_already_inside_the_field_object_wins():
    out, _ = normalize_query(
        {"wildcard": {"file": {"value": "*a*", "case_insensitive": False}, "case_insensitive": True}}, field_types=TYPES)
    assert out == {"wildcard": {"file": {"value": "*a*", "case_insensitive": False}}}


def test_two_real_fields_are_still_refused_not_guessed():
    out, _ = normalize_query({"wildcard": {"file": "*a*", "family": "*b*"}}, field_types=TYPES)
    with pytest.raises(ESQueryError, match="exactly one field"):
        validate_query(out)


def test_the_normalizer_and_the_validator_read_one_option_table():
    assert query_normalize.FIELD_CLAUSE_OPTIONS is es_native.FIELD_CLAUSE_OPTIONS
    for kind, options in es_native.FIELD_CLAUSE_OPTIONS.items():
        field = "file"
        validate_query({kind: {field: {"value": "x", **{o: True for o in options}}}})
