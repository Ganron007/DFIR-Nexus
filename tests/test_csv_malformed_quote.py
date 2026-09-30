"""WO-22: one unterminated quote must not swallow (or OOM) a CSV.

Before the fix, a single unclosed `"` made the csv reader consume the rest of
the file as one record (memory ~8x the file) and reconciliation counted the
same way, so the loss reported as `match`.
"""
from __future__ import annotations

import json
import tracemalloc

NORMAL = 200_000


def _case(tmp_path, *, bad_row: bool = True, normal: int = NORMAL):
    ext = tmp_path / "extractions" / "wxtcmd"
    ext.mkdir(parents=True)
    p = ext / "Big.csv"
    with p.open("w", encoding="utf-8") as fh:
        fh.write("Id,Payload\n")
        if bad_row:
            fh.write('1,"never closed\n')
        for i in range(normal):
            fh.write(f"{i},row {i}\n")
    (tmp_path / "CASE.yaml").write_text("intake:\n  question: q\n", encoding="utf-8")
    return tmp_path, p


def test_unterminated_quote_falls_back_to_lines(tmp_path, monkeypatch):
    from nexus.langgraph.case_index import iter_indexable_rows

    monkeypatch.setenv("NEXUS_CSV_MAX_RECORD_LINES", "5")
    case, p = _case(tmp_path, normal=20)
    with p.open(encoding="utf-8") as fh:
        rows = list(iter_indexable_rows(p, fh, ["Id", "Payload"]))
    assert len(rows) == 21, [r[0] for r in rows]  # the bad row's line + 20 normal
    assert rows[0][0] == 2 and rows[-1][0] == 22
    assert rows[0][1].startswith('1,"never closed')


def test_fallback_is_memory_bounded(tmp_path):
    from nexus.langgraph.case_index import iter_indexable_rows

    case, p = _case(tmp_path)  # 200k rows, ~15.7 MB
    tracemalloc.start()
    with p.open(encoding="utf-8") as fh:
        n = sum(1 for _ in iter_indexable_rows(p, fh, ["Id", "Payload"]))
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert n == NORMAL + 1
    assert peak < 5 * 1024 * 1024, f"peak {peak} bytes - a record is buffering"


def test_csv_error_falls_back(tmp_path, monkeypatch):
    import csv as csv_mod

    from nexus.langgraph.case_index import iter_indexable_rows

    case, p = _case(tmp_path, bad_row=False, normal=5)
    real_reader = csv_mod.reader

    def flaky(*a, **k):
        r = real_reader(*a, **k)

        def gen():
            yield next(r)  # the header record reads fine
            raise csv_mod.Error("simulated malformed quoting")

        return gen()

    monkeypatch.setattr(csv_mod, "reader", flaky)
    with p.open(encoding="utf-8") as fh:
        rows = list(iter_indexable_rows(p, fh, ["Id", "Payload"]))
    monkeypatch.undo()
    assert [r[0] for r in rows] == [2, 3, 4, 5, 6]


def test_index_stats_record_the_fallback(tmp_path, monkeypatch):
    from nexus.langgraph.case_index import iter_index_doc_batches

    monkeypatch.setenv("NEXUS_CSV_MAX_RECORD_LINES", "5")
    case, p = _case(tmp_path, normal=10)
    stats: dict = {}
    list(iter_index_doc_batches(case, stats=stats))
    fb = stats.get("csv_fallback")
    assert fb and fb[0]["line"] == 2, stats
    assert fb[0]["file"].endswith("wxtcmd/Big.csv")


def test_reconciliation_marks_malformed_quoting(tmp_path, monkeypatch):
    from nexus.analysis.reconciliation import reconcile_case
    from nexus.langgraph.case_index import iter_index_docs

    monkeypatch.setenv("NEXUS_CSV_MAX_RECORD_LINES", "5")
    case, p = _case(tmp_path, normal=100)
    docs = iter_index_docs(case)
    counts: dict[str, dict[str, int]] = {}
    for d in docs:
        counts.setdefault(d["file"], {"docs": 0, "deduped": 0})["docs"] += 1
    (case / "analysis").mkdir(exist_ok=True)
    (case / "analysis" / "es_index.json").write_text(
        json.dumps({"docs": len(docs), "file_counts": counts}), encoding="utf-8"
    )
    rec = reconcile_case(case)
    row = next(f for f in rec["files"] if "Big.csv" in f["file"])
    assert row["status"] == "malformed_quoting", row
    assert "line 2" in row["note"]
    assert rec["totals"]["malformed_quoting"] == 1


def test_search_readers_agree_on_the_fallback_file(tmp_path):
    from nexus.langgraph.query_pack import iter_all_hits, n4_hits

    case, p = _case(tmp_path, normal=50)
    hits, _ = n4_hits(case, ["row 49"], (None, None), backend="csv")
    streamed = list(iter_all_hits(case, ["row 49"], (None, None), backend="csv"))
    assert hits and streamed
    assert [h["line"] for h in hits] == [h["line"] for h in streamed]
