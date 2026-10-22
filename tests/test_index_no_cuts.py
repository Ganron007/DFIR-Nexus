"""Valid evidence is not capped or cut at index time (operator decision, 2026-10-11).

CASE-C5B04D31 (run RUN-20261011T110426201672Z-tools-5618aeb2) lost evidence to four silent
rules, each reproduced here on the real indexing path:

- the walk kept 120 files per family, so 394 PowerShell-transcript and WER files never reached ES;
- a row's text was cut at 4,000 characters (9,029 rows) and a field value at 4,096;
- the first line of a text file with a comma was taken as a header (five DeepBlueCLI outputs);
- ``.tsv`` was never walked (wmi-parser.tsv: one WMI consumer row).
"""

from __future__ import annotations

from pathlib import Path

import pytest

WMI_TSV = (
    "Name\tType\tArguments\tFilter Name\tFilter Query\n"
    "SCM Event Log Consumer\t\t\tSCM Event Log Filter\tselect * from MSFT_SCMEventLogEvent\n"
)


@pytest.fixture()
def run_case(tmp_path, monkeypatch):
    from nexus.langgraph import pipeline_runs

    case_dir = tmp_path / "CASE-NOCUT-0001"
    extractions = case_dir / "runs" / "RUN-1" / "extractions"
    extractions.mkdir(parents=True)
    monkeypatch.setattr(
        pipeline_runs, "resolve_tools_extractions",
        lambda case_dir, run_id="": extractions,
    )
    return case_dir, extractions


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _docs(case_dir: Path) -> list[dict]:
    from nexus.langgraph.case_index import iter_index_doc_batches

    return [doc for batch in iter_index_doc_batches(case_dir) for doc in batch]


def test_a_family_keeps_every_file_by_default(run_case):
    from nexus.langgraph.query_pack import iter_extraction_files

    case_dir, extractions = run_case
    for n in range(130):
        _write(extractions / "pstranscript" / f"PowerShell_transcript.{n:03d}.txt", "one\ntwo\n")
    stats: dict = {}
    found = iter_extraction_files(case_dir, stats=stats)
    assert len(found) == 130
    assert stats.get("files_skipped_family_cap", 0) == 0


def test_legacy_index_caps_do_not_drop_files_or_rows(run_case, monkeypatch):
    from nexus.langgraph.case_index import iter_index_doc_batches

    case_dir, extractions = run_case
    monkeypatch.setenv("NEXUS_INDEX_MAX_DOCS", "1")
    monkeypatch.setenv("NEXUS_INDEX_PER_FILE_CAP", "1")
    monkeypatch.setenv("NEXUS_INDEX_PER_FAMILY_CAP", "1")
    for n in range(3):
        _write(extractions / "wer" / f"Report{n}.wer.txt", "row one\nrow two\n")
    stats: dict = {}
    docs = [doc for batch in iter_index_doc_batches(case_dir, stats=stats) for doc in batch]
    assert len(docs) == 6
    assert stats["docs_capped"] is False
    assert stats["families_capped"] == []
    assert stats["files_capped"] == 0


def test_a_tsv_output_is_walked_and_its_rows_are_indexed(run_case):
    from nexus.langgraph.case_index import iter_index_files

    case_dir, extractions = run_case
    _write(extractions / "wmi_parser" / "wmi-parser.tsv", WMI_TSV)
    assert any(p.name == "wmi-parser.tsv" for p in iter_index_files(case_dir))
    rows = [d for d in _docs(case_dir) if d["file"] == "wmi_parser/wmi-parser.tsv"]
    assert [d["line"] for d in rows] == [2]  # line 1 is the header, not a record
    assert "SCM Event Log Consumer" in rows[0]["text"]
    assert rows[0]["fields"]["Name"] == "SCM Event Log Consumer"
    assert rows[0]["fields"]["Filter Name"] == "SCM Event Log Filter"


def test_a_comma_on_line_one_of_a_text_file_is_a_record(run_case):
    case_dir, extractions = run_case
    summary = "deepblue: 4 detection(s) from 1 file(s), 0 hard error(s) -> C:\\out\\system.json"
    _write(extractions / "deepbluecli" / "deepbluecli-System.txt", summary + "\n")
    rows = [d for d in _docs(case_dir) if d["file"] == "deepbluecli/deepbluecli-System.txt"]
    assert [d["line"] for d in rows] == [1]
    assert "4 detection(s) from 1 file(s)" in rows[0]["text"]


def test_a_csv_header_is_not_a_record_and_still_names_the_fields(run_case):
    case_dir, extractions = run_case
    _write(extractions / "evtxecmd" / "out.csv", "Channel,EventId,Payload\nSecurity,4624,abc\n")
    rows = [d for d in _docs(case_dir) if d["file"] == "evtxecmd/out.csv"]
    assert [d["line"] for d in rows] == [2]
    assert rows[0]["fields"]["Channel"] == "Security"
    assert rows[0]["fields"]["EventId"] == "4624"


def test_a_long_row_and_a_long_field_are_indexed_whole(run_case):
    case_dir, extractions = run_case
    long_line = "x" * 50_000 + " tail-marker"
    _write(extractions / "bigtext" / "big.txt", long_line + "\n")
    long_value = "y" * 50_000
    _write(extractions / "bigcsv" / "big.csv", "Name,Payload\nrow," + long_value + "\n")
    text_rows = [d for d in _docs(case_dir) if d["file"] == "bigtext/big.txt"]
    assert text_rows[0]["text"] == long_line
    csv_rows = [d for d in _docs(case_dir) if d["file"] == "bigcsv/big.csv"]
    assert csv_rows[0]["fields"]["Payload"] == long_value
    assert csv_rows[0]["text"].endswith(long_value)


def test_a_tab_separated_log_names_its_columns_and_drops_no_row(run_case):
    """A Zeek-style tab table keeps its header rule: line 1 names the columns, line 2 is a row."""
    case_dir, extractions = run_case
    _write(extractions / "zeek" / "conn.log",
           "#fields\tts\tuid\tid.orig_h\n1755000000.123\tC1\t10.0.0.5\n")
    rows = [d for d in _docs(case_dir) if d["file"] == "zeek/conn.log"]
    assert [d["line"] for d in rows] == [2]
    assert rows[0]["fields"]


def test_host_and_user_keyword_copies_are_bounded_in_the_mapping():
    """A long host or user value must not reject its document (Lucene term limit)."""
    from nexus.langgraph.case_index import _mapping_body

    props = _mapping_body()["mappings"]["properties"]
    assert props["host"]["ignore_above"] == 1024
    assert props["user"]["ignore_above"] == 1024


def test_the_wildcard_subfields_have_no_length_cap():
    """A substring search reaches a row of any length (operator decision 2026-10-11)."""
    from nexus.langgraph.case_index import _mapping_body

    body = _mapping_body()["mappings"]
    assert body["properties"]["text"]["fields"]["wc"] == {"type": "wildcard"}
    ecs_strings = next(d for d in body["dynamic_templates"] if "ecs_strings" in d)["ecs_strings"]
    assert ecs_strings["mapping"]["fields"]["wc"] == {"type": "wildcard"}


def test_text_indexes_the_word_parts_of_a_dotted_name():
    """D195: the standard analyzer kept lsass.exe as one word, so {"match":{"text":"lsass"}} found
    20 of 18,970 lsass rows. The parts are indexed beside the name and the query is split the same
    way; the version is not bumped, so an index built before keeps working until it is rebuilt."""
    from nexus.langgraph.case_index import INDEX_SCHEMA_VERSION, _mapping_body

    body = _mapping_body()
    text = body["mappings"]["properties"]["text"]
    assert (text["analyzer"], text["search_analyzer"]) == ("forensic_text", "forensic_text_search")
    analysis = body["settings"]["analysis"]
    parts = analysis["filter"]["forensic_word_parts"]
    assert parts["type"] == "word_delimiter_graph" and parts["preserve_original"] is True
    assert analysis["analyzer"]["forensic_text"]["filter"] == [
        "forensic_word_parts", "flatten_graph", "lowercase"]
    assert "flatten_graph" not in analysis["analyzer"]["forensic_text_search"]["filter"]
    assert body["mappings"]["_meta"] == {"schema_version": INDEX_SCHEMA_VERSION,
                                         "text_analyzer": "forensic_text_v1"}


def test_old_csv_size_caps_do_not_truncate_a_multiline_record(monkeypatch):
    """Legacy record-size settings have no effect; every quoted row stays whole."""
    import io

    from nexus.langgraph.case_index import iter_record_rows

    monkeypatch.setenv("NEXUS_CSV_MAX_RECORD_LINES", "5")
    monkeypatch.setenv("NEXUS_CSV_MAX_RECORD_BYTES", "32")
    body = "line\n" * 12_000
    fallbacks: list[tuple[int, str]] = []
    records = list(iter_record_rows(
        io.StringIO(f'1,"{body}"\n2,tail\n'), delimiter=",",
        on_fallback=lambda start, reason: fallbacks.append((start, reason)),
    ))
    assert fallbacks == []
    by_id = {cells[0]: cells for _start, _raw, cells in records if cells}
    assert by_id["1"][1] == body
    assert by_id["2"][1] == "tail"


MPLOG_HEADER = ("start_time,threat_name,threat_id,action,resource_action_complete,schema,path,"
                "resource_refcount,result,finished_threat_id,threat_result,threat_status_flags,"
                "threat_effective_removalpolicy")
MPLOG_ROW = ("2023-01-25T00:41:57.000Z,Behavior:Win32/CobaltStrike.E!sms,2147735503,remove,1,file,"
             "C:\\Windows\\System32\\SRLUpdate.exe,1,0x0,2147735503,0x0,0x0,1")


@pytest.mark.parametrize("encoding,bom", [("utf-16-le", b"\xff\xfe"), ("utf-16-le", b""),
                                          ("utf-8", b"\xef\xbb\xbf")])
def test_a_utf16_tool_output_is_indexed_as_text(run_case, encoding, bom):
    """D207: Mplog-Parser's CSVs and the WER reports are UTF-16. Read as UTF-8 they indexed with a
    NUL after every character (310 files of CASE-C5B04D31), unsearchable, and their column names
    reached the field sheet as NUL-interleaved strings."""
    case_dir, extractions = run_case
    path = extractions / "mplog" / "MPLog_ThreatAction.csv"
    path.parent.mkdir(parents=True)
    path.write_bytes(bom + (MPLOG_HEADER + "\r\n" + MPLOG_ROW + "\r\n").encode(encoding))

    (doc,) = [d for d in _docs(case_dir) if d["family"] == "mplog"]
    assert "\x00" not in doc["text"] and "CobaltStrike" in doc["text"]
    assert doc["fields"]["threat_name"] == "Behavior:Win32/CobaltStrike.E!sms"
    assert not [k for k in doc["fields"] if "\x00" in k or "\ufeff" in k]
