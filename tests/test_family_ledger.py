"""WO-1C item 7 — the per-run family coverage ledger (KR4 / D58).

"No run accounts for every indexed family." The old code credited a layer as
having run because it was merely *available*, so a run could settle having
never queried the family that held the evidence.

The contract asserted here:
* the ledger is built from **execution records only** — a planned-but-unrun
  query is never credited;
* a family with rows and no successful query is named, and blocks settlement;
* a family whose only queries failed is *not* observed (an errored query saw
  nothing);
* a family's documents are the index's own count, and an index that cannot be
  measured is said, never read as an index with no families (D462);
* the briefing keyword scan examines no family (Part 12 FM-10), and its rows
  from before FM-10 credit no run (D462).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus.analysis.family_ledger import (
    build_family_ledger,
    record_query,
    settle_blockers,
    unexamined_families,
)

# T22 (CASE-4387EB47) answered this to the family aggregation `es_native._family_doc_counts` sends, captured
# verbatim from its index on 2026-10-28 ("took" dropped).
T22_FAMILY_AGGREGATION = {
    "timed_out": False,
    "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
    "hits": {"total": {"value": 1737335, "relation": "eq"}, "max_score": None, "hits": []},
    "aggregations": {"families": {"doc_count_error_upper_bound": 0, "sum_other_doc_count": 0, "buckets": [
        {"key": "memprocfs", "doc_count": 1736903}, {"key": "vol", "doc_count": 432}]}},
}
# T22's case_digest.json inventory as the briefing wrote it: extraction file lines, not documents.
T22_DIGEST_INVENTORY = {"memprocfs": {"files": 84, "rows": 1737567}, "vol": {"files": 15, "rows": 432}}
# Rows T22's analysis/family_queries.jsonl holds from the briefing keyword scan before Part 12 FM-10.
T22_RUNLESS_ROW = {"run_id": "", "query": {"term": {"family": "memprocfs"}}, "status": "OK", "rows": 0, "audit_id": ""}


@pytest.fixture
def index_holds(monkeypatch):
    """The index's family counts, at the one place the ledger reads them."""
    from nexus.langgraph import es_native

    def hold(counts: dict[str, int]) -> None:
        monkeypatch.setattr(es_native, "family_doc_counts", lambda _case_id: dict(counts))

    return hold


def _read_ledger_rows(case_dir: Path) -> list[dict]:
    path = case_dir / "analysis" / "family_queries.jsonl"
    if not path.is_file():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


class _Resp:
    def __init__(self, code: int, payload: dict):
        self.status_code = code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class _T22Index:
    """An Elasticsearch client that answers as T22's index did."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def head(self, path):
        return _Resp(200, {})

    def post(self, path, json=None):
        assert path.endswith("/_search") and json["aggs"]["families"]["terms"]["field"] == "family"
        return _Resp(200, T22_FAMILY_AGGREGATION)


# ---------------------------------------------------------------------------
# The documents a family holds are the index's own count (D462)
# ---------------------------------------------------------------------------

def test_t22_family_counts_come_from_the_index_not_the_digest_inventory(tmp_path: Path, monkeypatch):
    """T22-R1z3d Mode 2 recorded memprocfs and vol as "queried but not in the index" with 0 documents: the
    ledger read the digest inventory's {"files", "rows"} entries for a ``docs`` key, then imported a function
    that never existed and swallowed the error. The counts are now the index's own."""
    from nexus.langgraph import case_index

    monkeypatch.setattr(case_index, "_client", lambda: _T22Index())
    monkeypatch.setattr(case_index, "es_available", lambda: True)
    case = tmp_path / "CASE-4387EB47"
    (case / "analysis").mkdir(parents=True)
    (case / "analysis" / "case_digest.json").write_text(
        json.dumps({"inventory": T22_DIGEST_INVENTORY}), encoding="utf-8")
    record_query(case, {"term": {"family": "memprocfs"}}, status="OK", rows=98,
                 audit_id="nexus-claudebot-20261028-088", run_id="M2-20261028T142946-d9ca87")
    ledger = build_family_ledger(case, run_id="M2-20261028T142946-d9ca87")
    rows = {row["family"]: row for row in ledger["families"]}
    assert (rows["memprocfs"]["docs"], rows["vol"]["docs"]) == (1736903, 432)
    assert rows["memprocfs"]["examined"] is True and rows["memprocfs"]["reason"] == ""
    assert rows["vol"]["reason"] == "no query was run against this family"
    assert ledger["families_indexed"] == 2 and ledger["index_error"] == ""
    assert ledger["summary"] == "1/2 indexed families examined"


T22_CALLS = json.loads((Path(__file__).parent / "fixtures" / "t22_ledger_calls.json").read_text(encoding="utf-8"))


def test_t22_mode1_examined_the_families_its_rows_came_from(tmp_path: Path, index_holds):
    """T22-R1z3d Mode 1 read 154 memprocfs/vol rows with queries that name no family (text wildcards, file and
    line filters), and its ledger said "0/2 indexed families examined". The rows a query returned name the
    families it examined."""
    from nexus.langgraph.interpret_loop import _record_loop_query

    index_holds({"memprocfs": 1736903, "vol": 432})
    entry = T22_CALLS["mode1_verify_entry"]
    run = "RUN-20261028T141233333689Z-interpret-a6e7c6d5"
    _record_loop_query(tmp_path, run, "es_search", entry["params"], {}, entry)
    ledger = build_family_ledger(tmp_path, run_id=run)
    rows = {row["family"]: row for row in ledger["families"]}
    assert rows["memprocfs"]["examined"] is True and rows["memprocfs"]["rows_read"] == 5
    assert rows["vol"]["examined"] is False and ledger["queries_unattributed"] == 0
    assert ledger["summary"] == "1/2 indexed families examined"


def test_t22_mode2_seat_calls_credit_the_families_they_read(tmp_path: Path, index_holds):
    """The Mode 2/3 worker writer (`_record_order_family_queries`) records the same: a match_all search that
    returned ten memprocfs rows examined memprocfs and read ten of its rows."""
    from nexus.modes.multi_role import _record_order_family_queries

    index_holds({"memprocfs": 1736903, "vol": 432})
    run = "M2-20261028T142946-d9ca87"
    _record_order_family_queries(tmp_path, run, [T22_CALLS["mode2_tool_call"]])
    ledger = build_family_ledger(tmp_path, run_id=run)
    rows = {row["family"]: row for row in ledger["families"]}
    assert rows["memprocfs"]["examined"] is True and rows["memprocfs"]["rows_read"] == 10
    assert rows["memprocfs"]["queries"][0]["rows"] == 1737335  # the call's own hit total, kept on the query


def test_an_index_that_cannot_be_measured_is_said(tmp_path: Path, monkeypatch):
    from nexus.langgraph import es_native

    def unreachable(_case_id):
        raise es_native.ESQueryError("Elasticsearch unavailable")

    monkeypatch.setattr(es_native, "family_doc_counts", unreachable)
    record_query(tmp_path, {"term": {"family": "vol"}}, status="OK", rows=3, run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    assert ledger["index_error"] == "ESQueryError: Elasticsearch unavailable"
    assert ledger["summary"].startswith("the index could not be measured")
    row = ledger["families"][0]
    assert row["examined"] is True and row["reason"].startswith("the index could not be measured")
    assert settle_blockers(ledger) == []


def test_rows_with_no_run_credit_no_run(tmp_path: Path, index_holds):
    """T22's keyword-scan rows from before FM-10 carry no run id; they made every family read as examined."""
    index_holds({"memprocfs": 1736903})
    path = tmp_path / "analysis" / "family_queries.jsonl"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(T22_RUNLESS_ROW) + "\n", encoding="utf-8")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    assert ledger["families_examined"] == 0 and ledger["queries_total"] == 0


# ---------------------------------------------------------------------------
# The ledger is built from execution records only
# ---------------------------------------------------------------------------

def test_a_planned_but_unexecuted_query_is_never_credited(tmp_path: Path, index_holds):
    """The ledger reads what RAN. A stored plan item with no execution record
    for this run contributes nothing — that is the KR4 rule."""
    index_holds({"evtxecmd": 100})
    # Nothing executed for this run.
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    assert ledger["families_examined"] == 0
    assert ledger["families_not_examined"] == ["evtxecmd"]
    assert unexamined_families(ledger) == ["evtxecmd"]


def test_an_executed_query_examines_its_family(tmp_path: Path, index_holds):
    index_holds({"evtxecmd": 100})
    record_query(tmp_path, {"term": {"family": "evtxecmd"}},
                 status="OK", rows=7, audit_id="a1", run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    row = ledger["families"][0]
    assert row["examined"] is True
    assert row["queries_ok"] == 1
    assert row["rows_read"] == 0  # the call recorded no rows it returned
    assert ledger["families_not_examined"] == []


def test_a_failed_query_does_not_examine_the_family(tmp_path: Path, index_holds):
    """An errored query observed nothing. It is reported with the failure, not
    counted as coverage."""
    index_holds({"vol": 500})
    record_query(tmp_path, {"term": {"family": "vol"}},
                 status="FAIL", rows=0, audit_id="a1", run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    row = ledger["families"][0]
    assert row["examined"] is False
    assert row["queries_failed"] == 1
    assert "failed" in row["reason"]
    assert unexamined_families(ledger) == ["vol"]


def test_a_run_sees_only_its_own_queries(tmp_path: Path, index_holds):
    """Another run's work does not credit this one."""
    index_holds({"evtxecmd": 100, "vol": 50})
    record_query(tmp_path, {"term": {"family": "evtxecmd"}},
                 status="OK", rows=3, run_id="M2-other")
    mine = build_family_ledger(tmp_path, run_id="M2-mine")
    assert mine["families_examined"] == 0
    # Unscoped, the same records show the family was examined by someone.
    both = build_family_ledger(tmp_path)
    assert both["families_examined"] == 1


def test_a_query_that_names_no_family_is_not_guessed(tmp_path: Path, index_holds):
    """A stored query that does not name a family is not attributed to one:
    guessing would credit a family with a query that never touched it."""
    index_holds({"evtxecmd": 100})
    record_query(tmp_path, {"bool": {"must": [{"match_all": {}}]}},
                 status="OK", rows=42, run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    assert ledger["queries_unattributed"] == 1
    assert ledger["families_examined"] == 0


def test_the_ecs_family_spelling_is_read(tmp_path: Path, index_holds):
    """The index writes the family on `family` and `event.dataset`; both are read."""
    index_holds({"evtxecmd": 100})
    record_query(tmp_path, {"term": {"event.dataset": "evtxecmd"}},
                 status="OK", rows=5, run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    assert ledger["families"][0]["examined"] is True


def test_a_queried_family_absent_from_the_index_is_named(tmp_path: Path, index_holds):
    """A query against a family the index does not hold is recorded, not dropped."""
    index_holds({"evtxecmd": 100})
    record_query(tmp_path, {"term": {"family": "ghostfamily"}},
                 status="OK", rows=0, run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    row = next(r for r in ledger["families"] if r["family"] == "ghostfamily")
    assert row["reason"] == "queried but not in the index"
    assert row["docs"] == 0


# ---------------------------------------------------------------------------
# Settlement
# ---------------------------------------------------------------------------

def test_settle_blockers_names_every_unexamined_populated_family(tmp_path: Path, index_holds):
    index_holds({"evtxecmd": 100, "vol": 500, "pecmd": 0})
    record_query(tmp_path, {"term": {"family": "evtxecmd"}},
                 status="OK", rows=1, run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    blockers = settle_blockers(ledger)
    assert "vol" in blockers
    assert "evtxecmd" not in blockers
    # An empty family is not a blocker: the ledger accounts for what is there.
    assert "pecmd" not in blockers


def test_an_empty_index_does_not_block_settlement(tmp_path: Path, index_holds):
    index_holds({})
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    assert settle_blockers(ledger) == []
    assert ledger["families_indexed"] == 0


# ---------------------------------------------------------------------------
# The briefing keyword scan is not an examination (Part 12 FM-10)
# ---------------------------------------------------------------------------

def test_the_briefing_does_not_credit_families_as_examined(tmp_path: Path, index_holds):
    """A keyword matched across the index examines no family: the briefing records no query for one."""
    from nexus.langgraph.briefing import case_briefing

    index_holds({"evtxecmd": 100})
    case_briefing(tmp_path)
    assert _read_ledger_rows(tmp_path) == []

def test_the_ledger_renders_a_markdown_table_for_the_report(tmp_path: Path, index_holds):
    from nexus.analysis.family_ledger import render_family_ledger_markdown

    index_holds({"evtxecmd": 100, "vol": 500})
    record_query(tmp_path, {"term": {"family": "evtxecmd"}},
                 status="OK", rows=3, run_id="M2-test")
    text = render_family_ledger_markdown(
        build_family_ledger(tmp_path, run_id="M2-test"))
    assert "## Family coverage ledger" in text
    assert "1/2 indexed families examined" in text
    assert "Rows read" in text
    assert "Not examined" in text
    assert "vol" in text


@pytest.mark.parametrize("status,examined", [
    ("OK", True), ("SUCCESS", True), ("COMPLETED", True), ("DONE", True),
    ("FAIL", False), ("ERROR", False), ("TIMEOUT", False), ("", False),
])
def test_status_spellings_are_classified(tmp_path: Path, index_holds, status, examined):
    """The run paths record the status in their own vocabulary; all are read."""
    index_holds({"evtxecmd": 100})
    record_query(tmp_path, {"term": {"family": "evtxecmd"}},
                 status=status, rows=1 if examined else 0, run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    assert ledger["families"][0]["examined"] is examined


def test_queried_families_the_index_does_not_hold_are_named_apart(tmp_path, index_holds):
    """D466: T22-R1z3d Mode 3's ledger read "4/2 indexed families examined": two queried families the index does not
    hold ("triage baseline", "eventlog") were counted over the two it does."""
    index_holds({"memprocfs": 1736903, "vol": 432})
    run = "M3-20261028T170325-969bbd"
    for family in ("memprocfs", "vol", "triage baseline", "eventlog"):
        record_query(tmp_path, {"term": {"family": family}}, status="OK", rows=1, run_id=run)
    ledger = build_family_ledger(tmp_path, run_id=run)
    assert ledger["summary"] == ("2/2 indexed families examined; queried but not in the index: "
                                 "eventlog, triage baseline")
    assert ledger["families_examined"] == 2 and ledger["families_indexed"] == 2
    assert ledger["families_not_in_index"] == ["eventlog", "triage baseline"]
    assert ledger["families_not_examined"] == []
