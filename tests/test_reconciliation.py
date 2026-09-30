"""WO-3: per-file row reconciliation (report-only phase).

Fixtures reproduce the defect shapes the manual method caught:
D35 (a JSON first record consumed as a CSV header) and D1 (two jobs writing one
output name) both surface as a non-zero delta when a doc count comes up short;
a quoted multi-line CSV cell counts as one record; index dedupe is accounted,
not treated as a mismatch.
"""
from __future__ import annotations

import gzip
import json
import os
import time

from nexus.analysis.reconciliation import (
    _classify,
    load_or_reconcile,
    reconcile_case,
    render_reconciliation_markdown,
    source_record_count,
    summary_line,
)


def _case(tmp_path, counts: dict, files: dict[str, str]):
    case = tmp_path / "CASE-RECON0001"
    (case / "extractions").mkdir(parents=True)
    for name, content in files.items():
        (case / "extractions" / name).write_text(content, encoding="utf-8")
    (case / "analysis").mkdir(parents=True, exist_ok=True)
    (case / "analysis" / "es_index.json").write_text(
        json.dumps(
            {
                "docs": sum(int(c.get("docs") or 0) for c in counts.values()),
                "file_counts": counts,
            }
        ),
        encoding="utf-8",
    )
    return case


def _row(rec: dict, name: str) -> dict:
    return next(f for f in rec["files"] if f["file"] == name)


CSV_3 = "a,b\n1,2\n3,4\n5,6\n"


def test_csv_matches_and_writes_the_artifact(tmp_path):
    case = _case(tmp_path, {"records.csv": {"docs": 3, "deduped": 0}}, {"records.csv": CSV_3})
    rec = reconcile_case(case)
    row = _row(rec, "records.csv")
    assert row["source_records"] == 3
    assert row["delta"] == 0
    assert row["status"] == "match"
    assert rec["totals"]["mismatch"] == 0
    assert rec["report_only"] is True
    assert (case / "analysis" / "reconciliation.json").is_file()


def test_missing_record_shows_nonzero_delta(tmp_path):
    # D35/D1 shape: the index took one fewer row than the file contains.
    case = _case(tmp_path, {"records.csv": {"docs": 2, "deduped": 0}}, {"records.csv": CSV_3})
    rec = reconcile_case(case)
    row = _row(rec, "records.csv")
    assert row["delta"] == 1
    assert row["status"] == "mismatch"
    assert rec["totals"]["mismatch"] == 1
    md = render_reconciliation_markdown(rec)
    assert "records.csv" in md and "| 1 |" in md


def test_quoted_multiline_cell_is_one_record(tmp_path):
    text = 'a,b\n1,"line one\nline two"\n2,plain\n'
    case = _case(tmp_path, {"multi.csv": {"docs": 2, "deduped": 0}}, {"multi.csv": text})
    rec = reconcile_case(case)
    row = _row(rec, "multi.csv")
    assert row["source_records"] == 2
    assert row["status"] == "match"


def test_dedupe_is_accounted_not_a_mismatch(tmp_path):
    case = _case(tmp_path, {"dup.csv": {"docs": 2, "deduped": 1}}, {"dup.csv": CSV_3})
    rec = reconcile_case(case)
    row = _row(rec, "dup.csv")
    assert row["delta"] == 0
    assert row["status"] == "match"


def test_source_record_count_formats(tmp_path):
    csv_path = tmp_path / "plain.csv"
    csv_path.write_text(CSV_3, encoding="utf-8")
    assert source_record_count(csv_path) == 3

    gz_path = tmp_path / "boxed.csv.gz"
    with gzip.open(gz_path, "wt", encoding="utf-8") as fh:
        fh.write(CSV_3)
    assert source_record_count(gz_path) == 3

    jsonl = tmp_path / "rows.jsonl"
    jsonl.write_text('{"a": 1}\n\n{"a": 2}\n', encoding="utf-8")
    assert source_record_count(jsonl) == 2

    array = tmp_path / "array.json"
    array.write_text("[1, 2, 3]", encoding="utf-8")
    # WO-15: .json is parsed - an array counts its elements, not its lines.
    assert source_record_count(array) == 3
    pretty = tmp_path / "pretty.json"
    pretty.write_text("[\n  1,\n  2,\n  3\n]\n", encoding="utf-8")
    assert source_record_count(pretty) == 3
    single = tmp_path / "single.json"
    single.write_text('{"a": 1}', encoding="utf-8")
    assert source_record_count(single) == 1

    txt = tmp_path / "notes.txt"
    txt.write_text("one\ntwo\n\n", encoding="utf-8")
    assert source_record_count(txt) == 2

    unknown = tmp_path / "image.evtx"
    unknown.write_bytes(b"\x00\x01")
    assert source_record_count(unknown) is None
    assert source_record_count(tmp_path / "missing.csv") is None


def test_unknown_format_is_unreconcilable():
    status, delta, note, _reason = _classify("fam", None, 5, 0)
    assert status == "unreconcilable"
    assert delta is None
    assert note


def test_json_array_reconciles_by_elements(tmp_path):
    """WO-15: a pretty array indexed as records is a match (2 elements/2 docs)."""
    text = '[\n  {"a": 1},\n  {"a": 2}\n]\n'
    case = _case(tmp_path, {"arr.json": {"docs": 2, "deduped": 0}}, {"arr.json": text})
    rec = reconcile_case(case)
    row = _row(rec, "arr.json")
    assert row["source_records"] == 2
    assert row["status"] == "match", row


def test_fragmented_json_array_is_named_not_silent(tmp_path):
    """WO-15: docs == the non-empty-line count of a json array -> `fragmented`."""
    text = '[\n  {"a": 1},\n  {"a": 2}\n]\n'
    case = _case(tmp_path, {"arr.json": {"docs": 4, "deduped": 0}}, {"arr.json": text})
    rec = reconcile_case(case)
    row = _row(rec, "arr.json")
    assert row["status"] == "fragmented", row
    assert row["delta"] == -2
    assert "line" in row["note"]
    assert rec["totals"]["fragmented"] == 1
    assert "fragmented" in summary_line(rec)
    assert "arr.json" in render_reconciliation_markdown(rec)


def test_family_override_is_explicit(monkeypatch):
    from nexus.analysis import reconciliation as rc

    monkeypatch.setitem(rc.FAMILY_OVERRIDES, "zeek", "one connection row is indexed as two docs by design")
    status, delta, _note, reason = _classify("zeek", 10, 9, 0)
    assert status == "override"
    assert delta == 1
    assert reason
    status2, *_ = _classify("other", 10, 9, 0)
    assert status2 == "mismatch"


def test_load_or_reconcile_caches_and_invalidates(tmp_path):
    case = _case(tmp_path, {"records.csv": {"docs": 3, "deduped": 0}}, {"records.csv": CSV_3})
    reconcile_case(case)
    cached = load_or_reconcile(case)
    assert cached.get("cached") is True

    meta = case / "analysis" / "es_index.json"
    future = time.time() + 10
    os.utime(meta, (future, future))
    fresh = load_or_reconcile(case)
    assert not fresh.get("cached")


def test_no_file_counts_is_explicit(tmp_path):
    case = tmp_path / "CASE-NOCOUNTS"
    (case / "analysis").mkdir(parents=True)
    (case / "analysis" / "es_index.json").write_text('{"docs": 5}', encoding="utf-8")
    rec = reconcile_case(case)
    assert rec["file_counts_present"] is False
    assert "re-index" in rec["note"]
    assert "not available" in summary_line(rec)


def test_indexer_records_per_file_counts(tmp_path):
    case = _case(tmp_path, {}, {"records.csv": CSV_3})
    from nexus.langgraph.case_index import iter_index_docs

    stats: dict = {}
    docs = iter_index_docs(case, stats=stats)
    assert len(docs) == 3
    assert stats["file_counts"]["records.csv"] == {"docs": 3, "deduped": 0}
