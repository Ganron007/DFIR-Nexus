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
* the briefing needle scan is an execution record and credits the families it
  scanned, so "no query was run against this family" is only said when that is
  true.
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


def _write_digest(case_dir: Path, inventory: dict[str, int]) -> None:
    """The digest's inventory is the indexed-family census (docs per family)."""
    analysis = case_dir / "analysis"
    analysis.mkdir(parents=True, exist_ok=True)
    (analysis / "case_digest.json").write_text(
        json.dumps({"inventory": inventory}), encoding="utf-8")


def _read_ledger_rows(case_dir: Path) -> list[dict]:
    path = case_dir / "analysis" / "family_queries.jsonl"
    if not path.is_file():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


# ---------------------------------------------------------------------------
# The ledger is built from execution records only
# ---------------------------------------------------------------------------

def test_a_planned_but_unexecuted_query_is_never_credited(tmp_path: Path):
    """The ledger reads what RAN. A stored plan item with no execution record
    for this run contributes nothing — that is the KR4 rule."""
    _write_digest(tmp_path, {"evtxecmd": 100})
    # Nothing executed for this run.
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    assert ledger["families_examined"] == 0
    assert ledger["families_not_examined"] == ["evtxecmd"]
    assert unexamined_families(ledger) == ["evtxecmd"]


def test_an_executed_query_examines_its_family(tmp_path: Path):
    _write_digest(tmp_path, {"evtxecmd": 100})
    record_query(tmp_path, {"term": {"family": "evtxecmd"}},
                 status="OK", rows=7, audit_id="a1", run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    row = ledger["families"][0]
    assert row["examined"] is True
    assert row["queries_ok"] == 1
    assert row["rows_returned"] == 7
    assert ledger["families_not_examined"] == []


def test_a_failed_query_does_not_examine_the_family(tmp_path: Path):
    """An errored query observed nothing. It is reported with the failure, not
    counted as coverage."""
    _write_digest(tmp_path, {"vol": 500})
    record_query(tmp_path, {"term": {"family": "vol"}},
                 status="FAIL", rows=0, audit_id="a1", run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    row = ledger["families"][0]
    assert row["examined"] is False
    assert row["queries_failed"] == 1
    assert "failed" in row["reason"]
    assert unexamined_families(ledger) == ["vol"]


def test_a_run_sees_only_its_own_queries(tmp_path: Path):
    """Another run's work does not credit this one."""
    _write_digest(tmp_path, {"evtxecmd": 100, "vol": 50})
    record_query(tmp_path, {"term": {"family": "evtxecmd"}},
                 status="OK", rows=3, run_id="M2-other")
    mine = build_family_ledger(tmp_path, run_id="M2-mine")
    assert mine["families_examined"] == 0
    # Unscoped, the same records show the family was examined by someone.
    both = build_family_ledger(tmp_path)
    assert both["families_examined"] == 1


def test_a_query_that_names_no_family_is_not_guessed(tmp_path: Path):
    """A stored query that does not name a family is not attributed to one:
    guessing would credit a family with a query that never touched it."""
    _write_digest(tmp_path, {"evtxecmd": 100})
    record_query(tmp_path, {"bool": {"must": [{"match_all": {}}]}},
                 status="OK", rows=42, run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    assert ledger["queries_unattributed"] == 1
    assert ledger["families_examined"] == 0


def test_the_ecs_family_spelling_is_read(tmp_path: Path):
    """The index writes the family on `family` and `event.dataset`; both are read."""
    _write_digest(tmp_path, {"evtxecmd": 100})
    record_query(tmp_path, {"term": {"event.dataset": "evtxecmd"}},
                 status="OK", rows=5, run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    assert ledger["families"][0]["examined"] is True


def test_a_queried_family_absent_from_the_index_is_named(tmp_path: Path):
    """A query against a family the index does not hold is recorded, not dropped."""
    _write_digest(tmp_path, {"evtxecmd": 100})
    record_query(tmp_path, {"term": {"family": "ghostfamily"}},
                 status="OK", rows=0, run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    row = next(r for r in ledger["families"] if r["family"] == "ghostfamily")
    assert row["reason"] == "queried but not in the index"
    assert row["docs"] == 0


# ---------------------------------------------------------------------------
# Settlement
# ---------------------------------------------------------------------------

def test_settle_blockers_names_every_unexamined_populated_family(tmp_path: Path):
    _write_digest(tmp_path, {"evtxecmd": 100, "vol": 500, "pecmd": 0})
    record_query(tmp_path, {"term": {"family": "evtxecmd"}},
                 status="OK", rows=1, run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    blockers = settle_blockers(ledger)
    assert "vol" in blockers
    assert "evtxecmd" not in blockers
    # An empty family is not a blocker: the ledger accounts for what is there.
    assert "pecmd" not in blockers


def test_an_empty_ledger_does_not_block_settlement(tmp_path: Path):
    """No digest, no index reachable: the ledger has nothing to account for, so
    it must not block every run on a CSV-only case."""
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    assert settle_blockers(ledger) == []
    assert ledger["families_indexed"] == 0


# ---------------------------------------------------------------------------
# The briefing keyword scan is not an examination (Part 12 FM-10)
# ---------------------------------------------------------------------------

def test_the_briefing_does_not_credit_families_as_examined(tmp_path: Path, monkeypatch):
    """A keyword matched across the index examines no family: the briefing records no query for one."""
    from nexus.langgraph.briefing import case_briefing

    _write_digest(tmp_path, {"evtxecmd": 100})
    case_briefing(tmp_path)
    assert _read_ledger_rows(tmp_path) == []

def test_the_ledger_renders_a_markdown_table_for_the_report(tmp_path: Path):
    from nexus.analysis.family_ledger import render_family_ledger_markdown

    _write_digest(tmp_path, {"evtxecmd": 100, "vol": 500})
    record_query(tmp_path, {"term": {"family": "evtxecmd"}},
                 status="OK", rows=3, run_id="M2-test")
    text = render_family_ledger_markdown(
        build_family_ledger(tmp_path, run_id="M2-test"))
    assert "## Family coverage ledger" in text
    assert "1/2 indexed families examined" in text
    assert "Not examined" in text
    assert "vol" in text


@pytest.mark.parametrize("status,examined", [
    ("OK", True), ("SUCCESS", True), ("COMPLETED", True), ("DONE", True),
    ("FAIL", False), ("ERROR", False), ("TIMEOUT", False), ("", False),
])
def test_status_spellings_are_classified(tmp_path: Path, status, examined):
    """The run paths record the status in their own vocabulary; all are read."""
    _write_digest(tmp_path, {"evtxecmd": 100})
    record_query(tmp_path, {"term": {"family": "evtxecmd"}},
                 status=status, rows=1 if examined else 0, run_id="M2-test")
    ledger = build_family_ledger(tmp_path, run_id="M2-test")
    assert ledger["families"][0]["examined"] is examined
