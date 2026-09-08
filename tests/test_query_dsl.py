"""Tests for the N4 query DSL (Phase 1.1)."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nexus.langgraph.query_dsl import (  # noqa: E402
    QuerySyntaxError,
    parse_query,
    row_matches,
)


class TestParse:
    def test_bare_terms_are_or(self):
        q = parse_query("sdelete cipher")
        assert q.or_terms == ["sdelete", "cipher"]
        assert not q.and_terms and not q.not_terms

    def test_and_not_fields(self):
        q = parse_query("sdelete AND host:WS01 NOT setup.exe")
        assert q.or_terms == ["sdelete"]
        assert q.not_terms == ["setup.exe"]
        assert q.fields == {"host": "ws01"}

    def test_field_filters(self):
        q = parse_query("family:evtx event:4624 file:mft")
        assert q.fields == {"family": "evtx", "event": "4624", "file": "mft"}
        assert q.is_empty() is False

    def test_quoted_phrase(self):
        q = parse_query('"faulting application"')
        assert q.or_terms == ['"faulting application"']

    def test_regex_mode(self):
        q = parse_query("regex:sdelete.*\\.exe")
        assert q.regex is not None
        assert q.regex.pattern == "sdelete.*\\.exe"

    def test_regex_redos_guard(self):
        with pytest.raises(QuerySyntaxError):
            parse_query("regex:(a+)+b")

    def test_regex_too_long(self):
        with pytest.raises(QuerySyntaxError):
            parse_query("regex:" + "a" * 200)

    def test_bad_regex_raises(self):
        with pytest.raises(QuerySyntaxError):
            parse_query("regex:sdelete[")
        q = parse_query("regex:sdelete.*exe")
        assert q.regex is not None

    def test_empty(self):
        assert parse_query("").is_empty()
        assert parse_query("   ").is_empty()

    def test_caps(self):
        with pytest.raises(QuerySyntaxError):
            parse_query(" OR ".join(f"t{i}" for i in range(40)))

    def test_short_terms_dropped(self):
        q = parse_query("a ab abc")
        assert "a" not in q.or_terms

    def test_all_needles_dedupe(self):
        q = parse_query("sdelete AND sdelete")
        assert q.all_needles() == ["sdelete"]


class TestRowMatch:
    def test_or_match(self):
        q = parse_query("sdelete OR cipher")
        m, terms = row_matches(q, line_lower="ran sdelete.exe", family="p", file_rel="f.csv")
        assert m and terms == ["sdelete"]

    def test_and_requires(self):
        q = parse_query("sdelete AND admin")
        m, _ = row_matches(q, line_lower="sdelete.exe run by admin on ws01", family="f", file_rel="x")
        assert m
        m2, _ = row_matches(q, line_lower="sdelete.exe run by user", family="p", file_rel="f")
        assert not m2

    def test_not_blocks(self):
        q = parse_query("sdelete NOT setup.exe")
        m, _ = row_matches(q, line_lower="sdelete and setup.exe seen", family="f", file_rel="x")
        assert not m

    def test_family_filter(self):
        q = parse_query("family:evtx")
        m, _ = row_matches(q, line_lower="anything", family="prefetch", file_rel="x")
        assert not m
        m2, _ = row_matches(q, line_lower="anything", family="evtx", file_rel="x")
        assert m2

    def test_file_filter(self):
        q = parse_query("file:hayabusa")
        m, _ = row_matches(q, line_lower="x", family="f", file_rel="hayabusa/timeline.csv")
        assert m
        m2, _ = row_matches(q, line_lower="x", family="f", file_rel="pecmd/out.csv")
        assert not m2

    def test_regex_mode(self):
        q = parse_query("regex:sdelete\\d+\\.tmp")
        m, _ = row_matches(q, line_lower="usn: sdelete42.tmp renamed", family="usn", file_rel="f")
        assert m

    def test_empty_matches_all(self):
        m, terms = row_matches(parse_query(""), line_lower="anything", family="x", file_rel="y")
        assert m and terms == []

    def test_combined(self):
        q = parse_query("error OR fail AND family:evtx NOT defender")
        m, _ = row_matches(
            q,
            line_lower="application error 1000 in app.exe",
            family="evtx",
            file_rel="x",
        )
        assert m
        m2, _ = row_matches(q, line_lower="error in hayabusa scan", family="hayabusa", file_rel="f")
        assert not m2  # family filter blocks
