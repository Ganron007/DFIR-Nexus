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


def test_an_explicit_family_cap_is_applied_and_reported(run_case):
    from nexus.langgraph.query_pack import iter_extraction_files

    case_dir, extractions = run_case
    for n in range(5):
        _write(extractions / "wer" / f"Report{n}.wer.txt", "x\n")
    stats: dict = {}
    found = iter_extraction_files(case_dir, max_files_per_family=2, stats=stats)
    assert len(found) == 2
    assert stats["files_skipped_family_cap"] == 3
    assert stats["families_capped"] == ["wer"]


def test_the_index_state_records_a_walk_cap(run_case, monkeypatch):
    from nexus.langgraph import query_pack
    from nexus.langgraph.case_index import iter_index_doc_batches

    case_dir, extractions = run_case
    monkeypatch.setattr(query_pack, "_MAX_FILES_PER_FAMILY", 1)
    for n in range(3):
        _write(extractions / "wer" / f"Report{n}.wer.txt", "x\n")
    stats: dict = {}
    for _batch in iter_index_doc_batches(case_dir, stats=stats):
        pass
    assert stats["files_skipped_family_cap"] == 2
    assert "wer" in stats["families_capped"]


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
