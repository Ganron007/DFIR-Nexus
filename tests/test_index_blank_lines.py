"""D56: blank physical lines are not documents.

The indexer used to emit one doc per physical line of a text file, including
blank ones. Reconciliation counts non-blank source lines, so every
blank-line-rich file surfaced as a mismatch (regripper-software: 45,254 docs
vs 31,258 records; the sweep's rdp/activitiescache recon rows showed the same
shape). Both halves of the contract are pinned here: the indexer skips blank
lines, and a blank-line-rich file then reconciles clean.
"""
from __future__ import annotations

import json

from nexus.analysis.reconciliation import reconcile_case, source_record_count
from nexus.langgraph.case_index import iter_index_doc_batches

BLANK_RICH = "alpha line\n\nbeta line\n   \n\t\ngamma line\n\n"


def _case(tmp_path):
    ext = tmp_path / "extractions" / "regripper"
    ext.mkdir(parents=True)
    (ext / "software-blank-rich.txt").write_text(BLANK_RICH, encoding="utf-8")
    (tmp_path / "CASE.yaml").write_text(
        "intake:\n  question: d56 blank lines\n", encoding="utf-8"
    )
    return tmp_path


def test_blank_lines_are_not_indexed(tmp_path):
    case = _case(tmp_path)
    docs = [d for batch in iter_index_doc_batches(case) for d in batch]
    assert [d["text"] for d in docs] == ["alpha line", "beta line", "gamma line"]
    assert all(d["text"].strip() for d in docs), "no blank doc may enter the index"


def test_blank_line_file_reconciles_after_the_fix(tmp_path):
    case = _case(tmp_path)
    src = case / "extractions" / "regripper" / "software-blank-rich.txt"
    assert source_record_count(src) == 3, "reconciliation counts non-blank lines"

    docs = [d for batch in iter_index_doc_batches(case) for d in batch]
    counts: dict[str, dict[str, int]] = {}
    for d in docs:
        rec = counts.setdefault(d["file"], {"docs": 0, "deduped": 0})
        rec["docs"] += 1
    analysis = case / "analysis"
    analysis.mkdir(exist_ok=True)
    (analysis / "es_index.json").write_text(
        json.dumps({"docs": len(docs), "file_counts": counts}), encoding="utf-8"
    )

    rec = reconcile_case(case)
    row = next(f for f in rec["files"] if "blank-rich" in f["file"])
    assert row["source_records"] == 3
    assert row["docs"] == 3
    assert row["status"] == "match", row
    assert rec["totals"]["mismatch"] == 0
