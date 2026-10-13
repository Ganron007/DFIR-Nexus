"""Phase 4k.4 — timestamp authority: extraction matrix, schema v3 docs,
coverage stats, typed ts ranges (ES + CSV parity).
"""
from __future__ import annotations

from pathlib import Path

from nexus.langgraph.timestamps import extract_event_ts, parse_text_time, parse_time_value


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


def test_a_number_inside_free_text_is_not_a_time():
    # D120: a 10-digit field inside a row (a handle's pointer, a registry key) was read as epoch and dated events
    # 2034 and 2059 in the case index.
    row = '{"GrantedAccess": 15, "HandleValue": 1636, "Object": 2033287795}'
    assert parse_text_time(row) is None
    assert extract_event_ts(row, {"grantedaccess": "15"}) is None
    assert parse_time_value("Error 2145103866") is None  # a whole value only


def test_a_nine_digit_epoch_cell_is_a_time():
    # Zeek writes 2000-era epochs with nine digits: the time column is read, not dropped (D120).
    got = extract_event_ts("964953086.310131\tCabc", {"ts": "964953086.310131"})
    assert got is not None and got["dt"].isoformat() == "2000-07-30T10:31:26+00:00"


def test_a_filetime_inside_free_text_is_not_a_time():
    assert parse_text_time("row 133005678900000000 flags 1") is None


def test_naive_us_and_syslog_times_are_utc_not_local():
    # A naive time is UTC by policy (D120): an untagged value would be read in the machine's own zone.
    assert parse_time_value("11/14/2020 4:49:43 PM")["dt"].isoformat() == "2020-11-14T16:49:43+00:00"
    assert parse_time_value("Nov 14 04:49:43", year_hint=2020)["dt"].isoformat() == "2020-11-14T04:49:43+00:00"


def test_dsl_time_filter_does_not_read_a_number_in_the_line_as_a_time():
    from nexus.langgraph.query_dsl import parse_query, row_matches

    q = parse_query("ts:>=2020-11-14 ts:<=2020-11-15")
    ok, _ = row_matches(q, line_lower="handle 2033287795 granted", row_ts="")
    assert not ok


def test_a_numeric_value_cell_is_not_a_time():
    # D120: "value" is not a time column. NTSTATUS 0xC0000225 (3221226021) dated eventlog rows to 2072.
    assert extract_event_ts("", {"value": "3221226021"}) is None
    assert extract_event_ts("", {"timestamp": "1755000000"}) is not None


def test_a_row_marked_no_event_time_keeps_no_ts_even_with_a_date_in_its_text():
    # D120: a YARA block names the rule's date and the process's start, never the time of the match.
    text = "Creation_date: 2022-08-10\nCreated: 2023-01-25 14:38:28 UTC"
    assert extract_event_ts(text, {"ts_none": "true"}) is None
    assert extract_event_ts(text, {"ts_none": "false"}) is not None


def test_a_registry_key_takes_its_own_lastwrite_not_an_earlier_date_in_its_text():
    # D120: the key's write time is a named column, so a date earlier in the row's text cannot stand in for it.
    text = '{"key":"HKLM\\\\SOFTWARE\\\\2022-10-14\\\\x","type":"key","lastwrite":"2023-01-10T05:43:52Z"}'
    got = extract_event_ts(text, {"key": "HKLM\\SOFTWARE\\2022-10-14\\x", "type": "key", "lastwrite": "2023-01-10T05:43:52Z"})
    assert got is not None and got["dt"].isoformat() == "2023-01-10T05:43:52+00:00"


def test_registry_value_rows_and_yara_blocks_get_no_event_time(tmp_path):
    from nexus.langgraph.case_index import iter_indexable_rows

    reg = tmp_path / "forensic" / "json" / "registry.json"
    reg.parent.mkdir(parents=True)
    reg.write_text(
        '{"class":"REG","ver":"5.19","sys":"22000","key":"HKLM\\\\SOFTWARE\\\\A","type":"key","lastwrite":"2023-01-10T05:43:52Z"}\n'
        '{"class":"REG","ver":"5.19","sys":"22000","key":"HKLM\\\\SOFTWARE\\\\A\\\\v","type":"value","data":"LinkDate 2099-05-10T06:23:29Z"}\n',
        encoding="utf-8",
    )
    with reg.open(encoding="utf-8") as fh:
        key_row, value_row = list(iter_indexable_rows(reg, fh, None))
    assert extract_event_ts(key_row[1], key_row[2])["dt"].isoformat() == "2023-01-10T05:43:52+00:00"
    assert extract_event_ts(value_row[1], value_row[2]) is None

    report = tmp_path / "yara.txt"
    report.write_text(
        "Match Index:  0\n"
        "Rule:         Windows_Trojan_CobaltStrike_8d5963a2\n"
        "Creation_date: 2022-08-10\n"
        "Created:      2023-01-25 14:38:28 UTC\n"
        "\n"
        "Matches:\n"
        "[string_0]: 1a802d60000\n",
        encoding="utf-8",
    )
    with report.open(encoding="utf-8") as fh:
        blocks = list(iter_indexable_rows(report, fh, None))
    assert blocks and all(extract_event_ts(text, fields) is None for _line, text, fields in blocks)

    csv_path = tmp_path / "yara.csv"
    csv_path.write_text("Rule,Created\nWindows_Trojan,2023-01-25 14:38:28\n", encoding="utf-8")
    with csv_path.open(encoding="utf-8") as fh:
        csv_rows = list(iter_indexable_rows(csv_path, fh, ["Rule", "Created"]))
    assert csv_rows and all(extract_event_ts(text, fields) is None for _line, text, fields in csv_rows)
