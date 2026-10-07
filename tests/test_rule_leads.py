"""WO-K4 part 1 — rule-engine detections as leads.

The work order: "Their detections enter `leads.jsonl` with the rule id, level and
rows." These tests pin that, and pin the two ways the wiring can silently do
nothing:

* a missing import dropped 656 real leads behind a WARNING (measured
  2026-10-04), and
* Hayabusa spells its middle level `med`, not `medium`, so a level map without it
  scores every medium detection as low.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

from nexus.analysis.leads import build_errors, build_leads
from nexus.analysis.rule_leads import (
    chainsaw_leads,
    hayabusa_leads,
    rule_engine_leads,
    ruleset_note,
)

HAYABUSA_HEADER = [
    "Timestamp", "RuleTitle", "Level", "Computer", "Channel", "EventID",
    "RecordID", "Details", "ExtraFieldInfo", "RuleID",
]
CHAINSAW_HEADER = [
    "timestamp", "detections", "path", "count",
    "Event.System.Provider", "Event ID", "Record ID", "Computer", "Event Data",
]


def _case_with_rule_output(tmp_path: Path) -> Path:
    """A case whose newest run holds real hayabusa + chainsaw CSVs."""
    case = tmp_path / "CASE-RULES"
    ext = case / "runs" / "RUN-1" / "extractions"
    (ext / "hayabusa").mkdir(parents=True)
    (ext / "chainsaw").mkdir(parents=True)

    with (ext / "hayabusa" / "evtx-timeline.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(HAYABUSA_HEADER)
        writer.writerow(["2026-01-01 00:00:00", "Log Cleared", "high", "WS01", "Security",
                         1102, 1, "Security log cleared", "", "abc-clear"])
        writer.writerow(["2026-01-01 00:01:00", "Non Interactive PowerShell", "med", "WS01",
                         "Sysmon", 1, 2, "powershell -nop", "", "def-ps"])
        writer.writerow(["2026-01-01 00:02:00", "Some Noise", "info", "WS01", "System",
                         1, 3, "routine", "", "ghi-noise"])
    with (ext / "chainsaw" / "sigma.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CHAINSAW_HEADER)
        writer.writerow(["2026-01-01T00:00:00Z", "Base64 MZ Header In CommandLine",
                         "C:/evtx/a.evtx", 1, "Microsoft-Windows-Sysmon", 1, 9, "WS01",
                         "TargetDomainName: '-'"])
    return case


def test_hayabusa_detections_carry_rule_id_level_and_rows(tmp_path):
    case = _case_with_rule_output(tmp_path)
    leads = hayabusa_leads(case)
    assert len(leads) == 3, [lead.subject for lead in leads]

    cleared = next(lead for lead in leads if lead.subject == "Log Cleared")
    assert cleared.kind == "rule_engine"
    assert cleared.family == "hayabusa"
    assert cleared.extra["rule_id"] == "abc-clear"
    assert cleared.extra["level"] == "high"
    row = cleared.rows[0]
    assert row["rule_id"] == "abc-clear"
    assert row["level"] == "high"
    assert row["event_id"] == "1102"
    assert row["computer"] == "WS01"


def test_hayabusa_med_scores_as_medium(tmp_path):
    """`med` is Hayabusa's own spelling; without it a medium hit scores as low."""
    case = _case_with_rule_output(tmp_path)
    ps = next(lead for lead in hayabusa_leads(case) if lead.subject == "Non Interactive PowerShell")
    assert ps.extra["level"] == "med"
    assert ps.score == 0.6, ps.score
    high = next(lead for lead in hayabusa_leads(case) if lead.subject == "Log Cleared")
    assert high.score > ps.score


def test_chainsaw_detections_are_leads_without_a_fabricated_level(tmp_path):
    case = _case_with_rule_output(tmp_path)
    leads = chainsaw_leads(case)
    assert len(leads) == 1
    lead = leads[0]
    assert lead.family == "chainsaw"
    assert lead.subject == "Base64 MZ Header In CommandLine"
    assert lead.extra["level"] == "", "chainsaw reports no level; one must not be invented"
    assert "no level reported" in lead.detail
    assert lead.rows[0]["event_id"] == "1"


def test_both_engines_combine_and_rank_strongest_first(tmp_path):
    case = _case_with_rule_output(tmp_path)
    leads = rule_engine_leads(case)
    assert len(leads) == 4
    assert leads[0].score >= leads[-1].score
    assert {lead.family for lead in leads} == {"hayabusa", "chainsaw"}


def test_hayabusa_crit_scores_top_and_is_aggregated_per_rule(tmp_path: Path):
    """WO-R1F item 1 — the root cause of the Mode 2/3 miss.

    Hayabusa spells its top level `crit`; it was absent from the score map, so
    every critical detection scored like an unknown level. And one lead was
    emitted per ROW, so a rule firing 27 times flooded the list. Both together
    meant a run with 27 crit detections had none of them lead.
    """
    from nexus.analysis.rule_leads import hayabusa_leads

    case = tmp_path / "CASE-CRIT"
    ext = case / "runs" / "RUN-1" / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    with (ext / "evtx-timeline.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(HAYABUSA_HEADER)
        # One rule, five rows, spelled `crit`; and one lower rule.
        for i in range(5):
            writer.writerow([f"2026-01-01 00:0{i}:00", "Defender Alert (Severe)", "crit",
                             "WS01", "Defender", 1116, i, "Behavior:Win32/CobaltStrike.E!sms",
                             "", "crit-rule"])
        writer.writerow(["2026-01-01 00:10:00", "Some Noise", "info", "WS01", "System",
                         1, 9, "routine", "", "noise"])

    leads = hayabusa_leads(case)
    assert len(leads) == 2, [lead.subject for lead in leads]   # one per RULE
    top = leads[0]
    assert top.subject == "Defender Alert (Severe)"
    assert top.score == 1.0, top.score                          # `crit` is the top level
    assert top.extra["level"] == "crit"
    assert top.extra["count"] == 5                              # rows aggregated
    assert top.extra["crit_high"] is True
    assert len(top.rows) <= 5                                   # capped samples
    assert top.rows[0]["file"].endswith("evtx-timeline.csv")


def test_unknown_level_is_scored_low_and_reported_once(tmp_path: Path, caplog):
    """A new spelling must be visible, not silently scored at the bottom."""
    import logging

    from nexus.analysis import rule_leads as rl

    rl._UNKNOWN_LEVELS_SEEN.clear()
    case = tmp_path / "CASE-UNK"
    ext = case / "runs" / "RUN-1" / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    with (ext / "evtx-timeline.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(HAYABUSA_HEADER)
        for i in range(3):
            writer.writerow([f"2026-01-01 00:0{i}:00", "Odd Rule", "weird", "WS01",
                             "System", 1, i, "x", "", "odd"])
    with caplog.at_level(logging.WARNING, logger="nexus.analysis.rule_leads"):
        leads = rl.hayabusa_leads(case)
    assert leads[0].score == 0.3                     # scored low, not crashed
    mentions = [r for r in caplog.records if "weird" in r.getMessage()]
    assert len(mentions) == 1, "an unknown level is reported once, by name"


def test_rule_engine_leads_merge_the_same_rule_across_engines(tmp_path: Path):
    """The same Sigma rule fires in both engines — that is one lead, not two."""
    case = tmp_path / "CASE-MERGE"
    ext = case / "runs" / "RUN-1" / "extractions"
    (ext / "hayabusa").mkdir(parents=True)
    (ext / "chainsaw").mkdir(parents=True)
    with (ext / "hayabusa" / "evtx-timeline.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(HAYABUSA_HEADER)
        writer.writerow(["2026-01-01 00:00:00", "DPAPI Domain Master Key Backup Attempt",
                         "med", "WS01", "Security", 4692, 1, "backup", "", "d-1"])
    with (ext / "chainsaw" / "sigma.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(CHAINSAW_HEADER)
        writer.writerow(["2026-01-01T00:00:00Z", "DPAPI Domain Master Key Backup Attempt",
                         "C:/evtx/a.evtx", 1, "Microsoft-Windows-Security", 4692, 1,
                         "WS01", "x"])

    leads = rule_engine_leads(case)
    assert len(leads) == 1, [lead.subject for lead in leads]
    lead = leads[0]
    assert lead.extra["level"] == "med"                 # the strongest level wins
    assert set(lead.extra["engines"]) == {"hayabusa", "chainsaw"}
    assert lead.extra["count"] == 1                     # max, not the sum (double-count)
    assert "seen by" in lead.detail


def test_all_crit_rules_outrank_every_other_lead_kind(tmp_path: Path):
    """A crit detection must never be outranked by a heuristic lead."""
    from nexus.analysis.leads import build_leads

    case = tmp_path / "CASE-RANK"
    ext = case / "runs" / "RUN-1" / "extractions" / "hayabusa"
    (ext / "hayabusa").mkdir(parents=True)
    with (ext / "evtx-timeline.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(HAYABUSA_HEADER)
        writer.writerow(["2026-01-01 00:00:00", "Defender Alert (Severe)", "crit",
                         "WS01", "Defender", 1116, 1, "CobaltStrike", "", "c-1"])
    (case / "analysis").mkdir(parents=True, exist_ok=True)

    class _Probe:
        def aggregate(self, **_kw):
            return {"top": [{"value": "System\\reg.exe", "count": 1}]}

        def observed_calls(self, **_kw):
            return []

        def process_check(self, **_kw):
            return {}

    leads = build_leads(case, probe=_Probe(), known_fields={"Executable"},
                        write=False)
    kinds = [lead.kind for lead in leads]
    assert kinds and kinds[0] == "rule_engine", kinds
    assert leads[0].score == 1.0
    # A rarity lead (score 1.0 on a single occurrence) must still sort after it.
    rarity = [lead for lead in leads if lead.kind == "rarity"]
    assert rarity, kinds
    assert rarity[0].score == 1.0, rarity[0].score


def test_ruleset_note_counts_crit_high(tmp_path: Path):
    from nexus.analysis.rule_leads import ruleset_note

    case = _case_with_rule_output(tmp_path)
    note = ruleset_note(case)
    assert note["rules"] == note["detections"]
    assert note["crit_high_rules"] == 1          # Log Cleared (high)


def test_ruleset_note_reports_what_actually_ran(tmp_path):
    case = _case_with_rule_output(tmp_path)
    note = ruleset_note(case)
    assert note["detections"] == 4
    assert note["by_engine"] == {"hayabusa": 3, "chainsaw": 1}
    assert note["by_level"]["high"] == 1 and note["by_level"]["med"] == 1
    assert "all" in note["levels_included"]


# ---------------------------------------------------------------------------
# the regression that actually happened
# ---------------------------------------------------------------------------

def test_build_leads_includes_rule_engine_detections(tmp_path, monkeypatch):
    """A real case with rule CSVs must yield rule_engine leads through build_leads.

    This is the check that would have caught the missing import: the builder
    raised `NameError`, `build_leads` swallowed it, and 656 detections vanished.
    """
    case = _case_with_rule_output(tmp_path)
    leads = build_leads(case, known_fields={"Service Name"})
    kinds = {lead.kind for lead in leads}
    assert "rule_engine" in kinds, kinds
    assert len([lead for lead in leads if lead.kind == "rule_engine"]) == 4


def test_a_failing_builder_is_recorded_not_merely_logged(tmp_path, monkeypatch):
    """A builder that raises must leave a mark in the case, not just a log line."""
    case = _case_with_rule_output(tmp_path)
    (case / "analysis").mkdir(exist_ok=True)

    import nexus.analysis.leads as module

    def _boom(_case_dir):
        raise RuntimeError("simulated builder failure")

    monkeypatch.setattr(module, "_rule_engine_leads", _boom)
    module.build_leads(case, known_fields={"Service Name"})

    errors = build_errors(case)
    assert errors and "simulated builder failure" in errors[0], errors
    assert "RuntimeError" in errors[0]


def test_a_clean_build_leaves_no_error_record(tmp_path):
    case = _case_with_rule_output(tmp_path)
    (case / "analysis").mkdir(exist_ok=True)
    build_leads(case, known_fields={"Service Name"})
    assert build_errors(case) == []


def test_an_empty_case_yields_no_rule_leads_and_does_not_raise(tmp_path):
    empty = tmp_path / "CASE-EMPTY"
    empty.mkdir()
    assert rule_engine_leads(empty) == []
    assert hayabusa_leads(empty) == []
    assert chainsaw_leads(empty) == []
    assert ruleset_note(empty)["detections"] == 0


def test_a_truncated_csv_does_not_lose_the_rest(tmp_path):
    """One malformed CSV must not take the whole engine's output with it."""
    case = tmp_path / "CASE-PARTIAL"
    ext = case / "runs" / "RUN-1" / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    (ext / "broken.csv").write_text('RuleID,RuleTitle,Level\n"unterminated', encoding="utf-8")
    (ext / "good.csv").write_text(
        "RuleID,RuleTitle,Level,Computer,EventID,Timestamp,Details\n"
        "x1,Log Cleared,high,WS01,1102,2026-01-01,cleared\n",
        encoding="utf-8",
    )
    leads = hayabusa_leads(case)
    assert [lead.subject for lead in leads] == ["Log Cleared"], leads


def test_the_written_leads_file_contains_rule_detections(tmp_path):
    case = _case_with_rule_output(tmp_path)
    build_leads(case, known_fields={"Service Name"})
    written = [
        json.loads(line)
        for line in (case / "analysis" / "leads.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    kinds = {row["kind"] for row in written}
    assert "rule_engine" in kinds
    engine_rows = [row for row in written if row["kind"] == "rule_engine"]
    assert engine_rows
    # Hayabusa carries a level per detection; chainsaw reports none, and says so
    # rather than having one invented for it.
    hayabusa = [r for r in engine_rows if r["family"] == "hayabusa"]
    chainsaw = [r for r in engine_rows if r["family"] == "chainsaw"]
    assert hayabusa and all(r["rows"] and "level" in r["rows"][0] for r in hayabusa)
    assert chainsaw and all(r["extra"]["level"] == "" for r in chainsaw)
