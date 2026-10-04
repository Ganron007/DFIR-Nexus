"""WO-K5 — lead-driven orders and per-family coverage.

The work order's two tests, made real:

* a fixture where `$MFT` has a million rows and prefetch holds the one lead puts
  **the prefetch lead in the first order**;
* **every family has a coverage line**.

Plus the properties that make those meaningful: volume must not influence the
ranking at all, and an order must name its benign alternative and its refutation
rather than only what to look at.
"""
from __future__ import annotations

from pathlib import Path

from nexus.analysis.work_orders import (
    BASELINE_FAMILIES,
    RULE_ENGINE_FAMILIES,
    VALUE_BUCKETS,
    bucket_of,
    coverage_lines,
    coverage_summary,
    family_value,
    orders_from_leads,
    rank_families,
)

# ---------------------------------------------------------------------------
# volume must not drive the order
# ---------------------------------------------------------------------------

def test_artifact_value_order_is_the_work_orders():
    """execution -> persistence -> logon/credential -> lateral -> network -> bulk."""
    assert VALUE_BUCKETS == (
        "execution", "persistence", "logon_credential", "lateral", "network",
        "bulk_filesystem",
    )
    assert family_value("pecmd") < family_value("recmd") < family_value("ingest-zeek")
    assert family_value("ingest-zeek") < family_value("mftecmd")


def test_rank_families_takes_no_row_counts():
    """The signature is the guard: there is nowhere to pass a volume."""
    import inspect

    params = list(inspect.signature(rank_families).parameters)
    assert params == ["families"], params


def test_the_prefetch_lead_is_first_even_when_mft_has_a_million_rows(tmp_path: Path):
    """The work order's fixture.

    `$MFT` holds a million rows and no lead; prefetch holds one lead. Ranking by
    volume would open with `$MFT`. Ranking by artifact value opens with prefetch.
    """
    mft_rows = 1_000_000
    family_rows = {"mftecmd": mft_rows, "pecmd": 1}
    assert family_rows["mftecmd"] > family_rows["pecmd"]  # the trap

    prefetch_lead = {
        "kind": "rarity",
        "subject": "evil_svc.exe",
        "family": "pecmd",
        "detail": "process 'evil_svc.exe' appears once in the index",
        "rows": [{"field": "Process Name", "value": "evil_svc.exe", "count": 1}],
        "audit_ids": ["nexus-lead-1"],
        "score": 0.9,
    }
    orders = orders_from_leads(
        tmp_path, "Investigate this host",
        families=list(family_rows), leads=[prefetch_lead], max_orders=4,
    )
    assert orders, "the director produced no orders"
    assert orders[0]["family"] == "pecmd", orders[0]
    assert orders[0]["lead_kind"] == "rarity"
    assert "evil_svc.exe" in orders[0]["hypothesis"]
    # And $MFT is not ahead of it.
    assert orders[0]["family"] != "mftecmd"


def test_rank_ignores_an_unranked_family_only_by_putting_it_last():
    ranked = rank_families(["mftecmd", "some-new-family", "pecmd"])
    assert ranked[0] == "pecmd"
    assert ranked[-1] == "some-new-family", "an unranked family must not be dropped"
    assert bucket_of("some-new-family") == ""


# ---------------------------------------------------------------------------
# an order states what would settle it
# ---------------------------------------------------------------------------

def test_every_order_names_a_benign_alternative_and_a_refutation(tmp_path: Path):
    leads = [
        {"kind": "rule_engine", "subject": "Log Cleared", "family": "hayabusa",
         "detail": "Hayabusa high detection [x]: Log Cleared", "rows": [{"rule_id": "x"}],
         "audit_ids": [], "score": 0.9, "extra": {"engine": "hayabusa", "level": "high"}},
        {"kind": "ancestry", "subject": "lsass.exe", "family": "pecmd",
         "detail": "parent disagrees with baseline", "rows": [{"verdict": "SUSPICIOUS"}],
         "audit_ids": ["a1"], "score": 0.9},
        {"kind": "burst", "subject": "2026-01-01T03", "family": "evtxecmd",
         "detail": "4000 rows in one bucket", "rows": [{"count": 4000}],
         "audit_ids": ["a2"], "score": 0.8},
    ]
    orders = orders_from_leads(tmp_path, "q", families=["hayabusa", "pecmd", "evtxecmd"],
                               leads=leads, max_orders=3)
    assert len(orders) == 3
    for order in orders:
        assert order["hypothesis"], order
        assert order["benign_alternative"], order
        assert order["refutation"], order
        assert order["task"].startswith("Test this hypothesis")


def test_a_rule_engine_order_carries_the_rule_id_and_rows(tmp_path: Path):
    lead = {
        "kind": "rule_engine", "subject": "Log Cleared", "family": "hayabusa",
        "detail": "Hayabusa high detection [8a1ff]: Log Cleared",
        "rows": [{"rule_id": "8a1ff", "level": "high", "event_id": "1102"}],
        "audit_ids": [], "score": 0.9, "extra": {"engine": "hayabusa"},
    }
    order = orders_from_leads(tmp_path, "q", families=["hayabusa"], leads=[lead],
                              max_orders=1)[0]
    assert order["family"] == "hayabusa"
    assert order["evidence_rows"][0]["rule_id"] == "8a1ff"
    assert "Log Cleared" in order["hypothesis"]


def test_orders_fill_the_remainder_from_artifact_value(tmp_path: Path):
    """With one lead and four orders, the rest still cover the host by value."""
    orders = orders_from_leads(
        tmp_path, "q", families=["mftecmd", "tasks", "pecmd", "ingest-zeek"],
        leads=[{"kind": "burst", "subject": "b", "family": "pecmd", "detail": "d",
                "rows": [], "audit_ids": [], "score": 0.5}],
        max_orders=4,
    )
    families = [o["family"] for o in orders]
    assert families[0] == "pecmd"
    # The remainder follows artifact value, so persistence precedes bulk.
    assert families.index("tasks") < families.index("mftecmd")
    assert all(o["lead_kind"] == "coverage" for o in orders[1:])
    assert "8a1ff" not in str(orders[1:])


def test_max_orders_is_respected(tmp_path: Path):
    orders = orders_from_leads(tmp_path, "q", families=["a", "b", "c", "d"],
                               leads=[], max_orders=2)
    assert len(orders) == 2


# ---------------------------------------------------------------------------
# coverage: every family accounted for
# ---------------------------------------------------------------------------

def test_every_family_has_a_coverage_line(tmp_path: Path):
    """The work order's second test."""
    families = ["hayabusa", "pecmd", "recmd", "tasks", "ingest-zeek", "nfdump",
                "mftecmd", "some-unknown-family"]
    lines = coverage_lines(tmp_path, families, leads=[], rules_note={})
    assert [line["family"] for line in lines] == rank_families(families)
    for line in lines:
        assert line["summary"], line
        assert isinstance(line["examined_by"], list), line
        assert "examined" in line["summary"], line


def test_a_coverage_line_names_the_sources_or_the_reason(tmp_path: Path):
    lines = coverage_lines(tmp_path, ["hayabusa", "mftecmd"], leads=[], rules_note={})
    by_family = {line["family"]: line for line in lines}

    # An event-log family can be read by the rule engines; mftecmd cannot.
    assert "needles" in by_family["hayabusa"]["examined_by"]
    assert by_family["hayabusa"]["examined"] is True

    # The bulk filesystem family is not an event log, so the reason is recorded.
    reasons = " ".join(by_family["mftecmd"]["not_examined"])
    assert "rule engines do not read this family" in reasons


def test_rule_engines_never_claim_a_family_they_do_not_read(tmp_path: Path):
    """A false coverage line is worse than an honest 'not examined'."""
    for family in ("mftecmd", "nfdump", "ingest-suricata", "plaso"):
        assert family not in RULE_ENGINE_FAMILIES, family
        lines = coverage_lines(tmp_path, [family], leads=[], rules_note={})
        assert "rule engines" not in lines[0]["examined_by"], family


def test_coverage_reports_rule_engine_activity_when_it_exists(tmp_path: Path):
    leads = [{"kind": "rule_engine", "subject": "Log Cleared", "family": "hayabusa",
              "detail": "d", "rows": [], "audit_ids": [], "score": 0.9,
              "extra": {"engine": "hayabusa"}}]
    lines = coverage_lines(tmp_path, ["hayabusa", "chainsaw"], leads=leads,
                           rules_note={"detections": 1})
    by_family = {line["family"]: line for line in lines}
    assert "rule engines" in by_family["hayabusa"]["examined_by"]
    # Chainsaw produced nothing, so it is not claimed.
    assert "rule engines" not in by_family["chainsaw"]["examined_by"]
    assert any("no detection" in r for r in by_family["chainsaw"]["not_examined"])


def test_coverage_summary_counts_and_lists_sources(tmp_path: Path):
    lines = coverage_lines(tmp_path, ["hayabusa", "pecmd", "mftecmd"],
                           leads=[], rules_note={})
    summary = coverage_summary(lines)
    assert summary["families"] == 3
    assert summary["examined"] + summary["not_examined"] == 3
    assert "needles" in summary["sources_used"]


def test_a_baseline_family_is_marked_examined_by_baselines(tmp_path: Path):
    assert "pecmd" in BASELINE_FAMILIES
    line = coverage_lines(tmp_path, ["pecmd"], leads=[], rules_note={})[0]
    assert "baselines" in line["examined_by"]


def test_coverage_lines_are_ordered_by_artifact_value(tmp_path: Path):
    lines = coverage_lines(tmp_path, ["mftecmd", "hayabusa", "tasks"],
                           leads=[], rules_note={})
    assert [line["family"] for line in lines] == ["hayabusa", "tasks", "mftecmd"]
    assert [line["bucket"] for line in lines] == [
        "execution", "persistence", "bulk_filesystem",
    ]
