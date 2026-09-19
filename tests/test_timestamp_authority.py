"""Phase 4k.4 — timestamp authority: extraction matrix, schema v3 docs,
coverage stats, typed ts ranges (ES + CSV parity).
"""
from __future__ import annotations

from pathlib import Path

from nexus.langgraph.timestamps import extract_event_ts, parse_time_value


def test_iso_with_offset_is_honored():
    got = parse_time_value("2024-11-23 04:06:23 +05:30")
    assert got is not None
    assert got["dt"].isoformat() == "2024-11-22T22:36:23+00:00"
    assert got["tz_assumed"] is False


def test_iso_z_and_fraction_precision():
    got = parse_time_value("2020-11-14T04:49:43.634Z")
    assert got is not None
    assert got["precision"] == "ms"
    assert got["tz_assumed"] is False


def test_naive_iso_is_utc_flagged():
    got = parse_time_value("2020-11-14 04:49:43")
    assert got is not None
    assert got["dt"].isoformat() == "2020-11-14T04:49:43+00:00"
    assert got["tz_assumed"] is True


def test_us_format_and_epoch_variants():
    us = parse_time_value("11/14/2020 4:49:43 PM")
    assert us is not None and us["dt"].hour == 16
    sec = parse_time_value("1755000000")
    assert sec is not None and sec["precision"] == "s"
    ms = parse_time_value("1755000000123")
    assert ms is not None and ms["precision"] == "ms"


def test_filetime_and_syslog_year_hint():
    ft = parse_time_value("133005678900000000")
    assert ft is not None and ft["dt"].year >= 2020
    syslog = parse_time_value("Nov 14 04:49:43", year_hint=2020)
    assert syslog is not None
    assert syslog["dt"].year == 2020 and syslog["year_assumed"] is True


def test_unparseable_stays_empty():
    assert parse_time_value("Computer Startup") is None
    assert parse_time_value("") is None


def test_extract_prefers_parsed_time_column_from_epoch_text():
    got = extract_event_ts(
        "1755000000\t25\t10.0.0.1\t8.8.8.8",
        {"ts": "1755000000", "uid": "C1"},
    )
    assert got is not None and got["dt"].year == 2025


def _case(tmp_path: Path) -> Path:
    ext = tmp_path / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "timeline.csv").write_text(
        "TimeCreated,Channel,EventID,Computer\n"
        "2020-11-14T04:49:43.123Z,Security,4688,WS01\n"
        "2020-11-14T05:00:00.000Z,System,7045,WS01\n",
        encoding="utf-8",
    )
    zeek = tmp_path / "extractions" / "zeek"
    zeek.mkdir(parents=True)
    (zeek / "conn.log").write_text(
        "#fields\tts\tuid\tid.orig_h\n1755000000.123\tC1\t10.0.0.5\n",
        encoding="utf-8",
    )
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  question: what happened\n  window: 2025-08-01..2025-08-31\n",
        encoding="utf-8",
    )
    return tmp_path


def test_index_docs_carry_ts_authority_fields(tmp_path):
    from nexus.langgraph.case_index import iter_index_docs

    docs = iter_index_docs(_case(tmp_path))
    hay = [d for d in docs if d["family"] == "hayabusa"]
    assert hay and all(d["ts"].endswith("Z") for d in hay)
    assert hay[0]["ts_src"] == "event"
    assert hay[0]["ts_precision"] == "ms"
    assert hay[0]["ts_raw"].startswith("2020-11-14")
    assert "ts_tz_assumed" not in hay[0]  # offset was explicit
    zeek = [d for d in docs if d["family"] == "zeek"]
    assert zeek and zeek[0]["ts"].startswith("2025-08-12")


def test_index_coverage_stats_per_family(tmp_path):
    from nexus.langgraph.case_index import iter_index_doc_batches

    stats: dict = {}
    list(iter_index_doc_batches(_case(tmp_path), stats=stats))
    cov = stats["ts_coverage"]
    assert cov["hayabusa"]["present"] == 2
    assert cov["hayabusa"]["missing"] == 0
    assert cov["zeek"]["present"] == 1


def test_dsl_ts_ranges_parse_and_push_down():
    from nexus.langgraph.case_index import ast_to_es
    from nexus.langgraph.query_dsl import QuerySyntaxError, parse_query

    q = parse_query("sdelete ts:>=2020-11-14 ts:<=2020-11-15")
    assert q.ts_start is not None and q.ts_end is not None
    es = ast_to_es(q, search_fields=True)
    assert any("range" in f and "ts" in f["range"] for f in es["bool"]["filter"])

    q2 = parse_query("after:2020-11-14 AND before:2020-11-15")
    assert q2.ts_start is not None and q2.ts_end is not None

    q3 = parse_query("ts:2020-11-14")
    assert q3.ts_start is not None and q3.ts_end is not None
    assert q3.ts_end > q3.ts_start  # whole day

    try:
        parse_query("ts:not-a-date")
        raise AssertionError("expected QuerySyntaxError")
    except QuerySyntaxError:
        pass


def test_row_matches_enforces_ts_range_and_excludes_undated():
    from nexus.langgraph.query_dsl import parse_query, row_matches

    q = parse_query("ts:>=2020-11-14 ts:<=2020-11-15")
    ok, _ = row_matches(q, line_lower="2020-11-14 04:49:43 sdelete", row_ts="2020-11-14T04:49:43Z")
    assert ok
    ok, _ = row_matches(q, line_lower="2020-11-20 04:49:43 sdelete", row_ts="2020-11-20T04:49:43Z")
    assert not ok
    ok, _ = row_matches(q, line_lower="sdelete no date at all", row_ts="")
    assert not ok, "rows with no parseable time must not silently match an explicit ts filter"
