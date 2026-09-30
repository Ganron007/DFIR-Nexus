"""WO-17/D63: delimited files are read (and searched) by CSV record.

A quoted cell containing newlines is ONE record; the doc's and a hit's
``line`` is the record's starting physical line. Index, collect, and exhaustive
stream all use the same record iterator, so ES/CSV parity holds by construction.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph.case_index import iter_index_docs, iter_record_rows

CSV_TEXT = (
    "Id,TimeCreated,Payload\n"
    '1,2020-11-14T04:49:43Z,"line one\nline two\nline three"\n'
    "2,2020-11-14T05:00:00Z,plain\n"
)


def _case(tmp_path: Path) -> Path:
    ext = tmp_path / "extractions" / "wxtcmd"
    ext.mkdir(parents=True)
    (ext / "Activity.csv").write_text(CSV_TEXT, encoding="utf-8")
    (tmp_path / "CASE.yaml").write_text("intake:\n  question: csr\n", encoding="utf-8")
    return tmp_path


def test_quoted_newline_cell_is_one_doc(tmp_path):
    case = _case(tmp_path)
    docs = iter_index_docs(case)
    assert len(docs) == 2, [d["text"] for d in docs]  # header + 2 records, not 4 lines
    multi = docs[0]
    assert multi["line"] == 2  # the record's STARTING physical line
    assert "line one" in multi["text"] and "line three" in multi["text"]
    assert multi["fields"]["Id"] == "1"
    assert multi.get("ts"), f"TimeCreated must feed ts: {multi}"


def test_record_iterator_reports_start_lines(tmp_path):
    case = _case(tmp_path)
    p = case / "extractions" / "wxtcmd" / "Activity.csv"
    with p.open(encoding="utf-8") as fh:
        rows = list(iter_record_rows(fh))
    assert [r[0] for r in rows] == [1, 2, 5]  # header; record1 spans 2-4; record2 = 5


def test_csv_search_paths_report_the_record_line(tmp_path):
    case = _case(tmp_path)
    from nexus.langgraph.query_pack import iter_all_hits, n4_hits

    hits, _backend = n4_hits(case, ["line three"], (None, None), backend="csv")
    assert hits, "the multi-line record must match as one row"
    assert hits[0]["line"] == "2"
    assert hits[0]["file"].endswith("wxtcmd/Activity.csv")
    assert "line three" in hits[0]["text"]

    streamed = list(iter_all_hits(case, ["line three"], (None, None), backend="csv"))
    assert [h["line"] for h in streamed] == ["2"], streamed


def test_reconciliation_matches_for_multiline_records(tmp_path):
    from nexus.analysis.reconciliation import reconcile_case

    case = _case(tmp_path)
    docs = iter_index_docs(case)
    counts: dict[str, dict[str, int]] = {}
    for d in docs:
        counts.setdefault(d["file"], {"docs": 0, "deduped": 0})["docs"] += 1
    (case / "analysis").mkdir(exist_ok=True)
    (case / "analysis" / "es_index.json").write_text(
        json.dumps({"docs": len(docs), "file_counts": counts}), encoding="utf-8"
    )
    rec = reconcile_case(case)
    row = next(f for f in rec["files"] if "Activity" in f["file"])
    assert row["source_records"] == 2
    assert row["docs"] == 2
    assert row["status"] == "match", row
