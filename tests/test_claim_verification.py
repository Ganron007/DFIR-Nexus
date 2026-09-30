"""Level 1 - mechanical claim verification.

The gate asks "is every claim true", not "did the pipeline finish". These
tests pin the part that matters most: a check that could not be run must report
UNVERIFIABLE, never a pass. Collapsing "I could not check this" into "checked
and clean" is how a pipeline that parsed nothing ends up graded complete.
"""
from __future__ import annotations

import json

from nexus.analysis.claim_verification import (
    VERDICTS,
    render_ledger_markdown,
    verify_case,
    verify_claim,
    write_ledger,
)

AUDIT = {"nx-audit-0001", "nx-audit-0002"}


def _f(**extra):
    f = {
        "id": "F1",
        "title": "powershell.exe executed from a temp directory",
        "status": "APPROVED",
        "artifacts": [{"audit_id": "nx-audit-0001"}],
    }
    f.update(extra)
    return f


def _good(**extra):
    kw = {
        "known_ids": AUDIT,
        "indexed_text": "powershell.exe C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe",
        "technique_ids": {"T1059.001"},
        "coverage": {"overall": "ok", "sections": {}},
        "cross_mode": {"contradictions": [], "row_contradictions": []},
    }
    kw.update(extra)
    return kw


def _sealed(f: dict) -> dict:
    """The staging seal, exactly as CaseManager.record_finding writes it.

    WO-23: a finding with no seal can never be PROVEN (L1.6 unverifiable), so
    tests that expect PROVEN must use a sealed finding.
    """
    from nexus.analysis.integrity import SEAL_ALGO, seal_digest

    f = dict(f)
    f["seal"] = {
        "algo": SEAL_ALGO,
        "digest": seal_digest(f),
        "sealed_at": "2026-09-30T00:00:00+00:00",
        "revision": 1,
    }
    return f


# --------------------------------------------------------------------------
# the central property
# --------------------------------------------------------------------------

def test_all_checks_unavailable_is_unverifiable_not_proven():
    v = verify_claim(_f(), known_ids=None, indexed_text=None, technique_ids=None,
                     coverage=None, cross_mode=None)
    assert v["verdict"] == "UNVERIFIABLE", v["verdict"]
    assert v["verdict"] != "PROVEN"


def test_missing_audit_log_makes_l1_1_unverifiable():
    v = verify_claim(_f(), known_ids=None, **{
        "indexed_text": "powershell.exe", "technique_ids": set(), "coverage": None,
        "cross_mode": None})
    assert v["checks"]["L1.1"]["status"] == "unverifiable"
    assert v["verdict"] == "UNVERIFIABLE"


def test_coverage_unknown_is_not_a_pass(tmp_path):
    """Coverage is a fact about the case, so it is reported once at case level.

    It still must not read as a pass - an unknown coverage audit means coverage
    could not be proven - but folding it into every claim would mark all of them
    UNSUPPORTED and bury the per-claim signal.
    """
    v = verify_claim(_sealed(_f()), **_good(coverage={"overall": "unknown", "sections": {}}))
    assert v["checks"]["L1.9"]["status"] == "unverifiable"
    assert v["verdict"] == "PROVEN", "a case-level check must not colour the claim"

    led = verify_case(tmp_path)
    assert led["case_level"]["L1.9"]["status"] in {"unverifiable", "fail"}


def test_a_coverage_gap_does_not_drive_every_claim_to_unsupported():
    """The signal this keeps: one coverage gap must not mark all N claims.

    A claim whose only failing check is the case-level L1.9 is not itself
    unsupported - it has an artifact, resolves, and corroborates. Burying that
    under a case-wide gap is how a reviewer stops reading the column.
    """
    gap = {"overall": "gaps", "sections": {"tools": {"status": "gaps"}}}
    v = verify_claim(_sealed(_f()), **_good(coverage=gap))
    assert v["checks"]["L1.9"]["status"] == "fail"
    assert v["verdict"] == "PROVEN"

    # A genuine per-claim failure still shows through.
    v2 = verify_claim(_f(artifacts=[{"audit_id": "nx-invented"}]), **_good(coverage=gap))
    assert v2["verdict"] == "UNSUPPORTED"


def test_l1_9_names_the_gap_when_sections_key_is_absent():
    """An audit written before the sections mirror still names its gap.

    L1.9 read `coverage["sections"]`, but the persisted audit spread the section
    dicts at the top level instead - so the case-level gap line read
    "coverage reports gaps in: unknown" on a case whose sources section was the
    one reporting gaps.
    """
    legacy = {"overall": "gaps",
              "tools": {"status": "ok"},
              "sources": {"status": "gaps"},
              "needles": {"status": "ok"}}
    v = verify_claim(_f(), **_good(coverage=legacy))
    assert v["checks"]["L1.9"]["status"] == "fail"
    assert "sources" in v["checks"]["L1.9"]["detail"]
    assert "unknown" not in v["checks"]["L1.9"]["detail"]


def test_a_fully_checked_claim_is_proven():
    v = verify_claim(_sealed(_f()), **_good())
    assert v["verdict"] == "PROVEN", {k: r["status"] for k, r in v["checks"].items()}
    assert all(r["status"] in {"pass", "skipped"} for r in v["checks"].values())


# --------------------------------------------------------------------------
# individual checks
# --------------------------------------------------------------------------

def test_l1_1_missing_audit_id_fails():
    v = verify_claim(_f(), **_good(known_ids=set()))
    assert v["checks"]["L1.1"]["status"] == "fail"
    assert v["verdict"] == "UNSUPPORTED"


def test_l1_1_no_citation_fails():
    v = verify_claim({"id": "F", "title": "x happened"}, **_good())
    assert v["checks"]["L1.1"]["status"] == "fail"
    assert "FD-001" in v["checks"]["L1.1"]["detail"]


def test_l1_2_out_of_range_line_fails(tmp_path):
    csv = tmp_path / "rows.csv"
    csv.write_text("a\nb\n", encoding="utf-8")
    f = _f(description=f"see {csv}:999 for the row")
    v = verify_claim(f, **_good(case_dir=tmp_path))
    assert v["checks"]["L1.2"]["status"] == "fail"
    assert "out of range" in v["checks"]["L1.2"]["detail"]


def test_l1_2_valid_line_passes(tmp_path):
    csv = tmp_path / "rows.csv"
    csv.write_text("a\nb\nc\n", encoding="utf-8")
    f = _f(description=f"see {csv}:2 for the row")
    v = verify_claim(f, **_good(case_dir=tmp_path))
    assert v["checks"]["L1.2"]["status"] == "pass"


def test_l1_3_invented_entity_fails():
    f = _f(title="neverdropped.exe executed from a temp directory")
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.3"]["status"] == "fail"
    assert "neverdropped.exe" in v["checks"]["L1.3"]["detail"]
    assert v["verdict"] == "UNSUPPORTED"


def test_l1_4_unknown_technique_fails():
    f = _f(technique_ids=["T9999.999"], title="powershell.exe executed")
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.4"]["status"] == "fail"
    assert "T9999.999" in v["checks"]["L1.4"]["detail"]


def test_l1_4_known_technique_passes():
    f = _f(technique_ids=["T1059.001"], title="powershell.exe executed")
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.4"]["status"] == "pass"


def test_l1_5_implausible_timestamp_fails():
    f = _f(timestamp="1601-01-01T00:00:00Z")
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.5"]["status"] == "fail"
    assert v["verdict"] == "UNSUPPORTED"


def test_l1_5_plausible_timestamp_passes():
    f = _f(timestamp="2026-03-04T11:22:33Z")
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.5"]["status"] == "pass"


def test_l1_5_catches_a_timestamp_under_any_parsable_name():
    """The integrity validator used to know five field names.

    start_time / end_time / entry_ts / date_added / mtime all carry times the
    parsers write, and a FILETIME epoch in any of them escaped validation. The
    check now matches on the field name, so a new field is covered the day it
    is written.
    """
    for field in ("start_time", "end_time", "entry_ts", "date_added", "mtime",
                  "first_seen", "last_seen", "created_at", "last_used_at"):
        f = _f(**{field: "1601-01-01T00:00:00Z"})
        v = verify_claim(f, **_good())
        assert v["checks"]["L1.5"]["status"] == "fail", (
            f"{field} escaped timestamp validation"
        )
        assert v["verdict"] == "UNSUPPORTED", field


def test_l1_5_reaches_a_timestamp_nested_in_an_artifact():
    f = _f(artifacts=[{"audit_id": "nx-audit-0001", "last_seen": "1601-01-01T00:00:00Z"}])
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.5"]["status"] == "fail"
    assert "artifacts[0]" in v["checks"]["L1.5"]["detail"]


def test_l1_6_broken_seal_fails():
    from nexus.analysis.integrity import seal_digest

    f = _f()
    f["seal"] = {"digest": seal_digest(f)}
    f["severity"] = "critical"  # tampered after sealing
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.6"]["status"] == "fail"
    assert v["verdict"] == "UNSUPPORTED"


def test_l1_6_intact_seal_passes():
    from nexus.analysis.integrity import seal_digest

    f = _f()
    f["seal"] = {"digest": seal_digest(f)}
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.6"]["status"] == "pass"


def _replayer(counts: dict[str, int]):
    """A replay hook with the family_count attribute L1.7 requires."""
    def family_count(family: str):
        return counts.get((family or "").lower())
    return family_count


def test_l1_7_count_above_the_index_fails():
    f = _f(title="powershell.exe in 4321 hit(s) across evtxecmd")
    v = verify_claim(f, **_good(family_count=_replayer({"evtxecmd": 10})))
    assert v["checks"]["L1.7"]["status"] == "fail", v["checks"]["L1.7"]
    assert "4321" in v["checks"]["L1.7"]["detail"]
    assert v["verdict"] == "UNSUPPORTED"


def test_l1_7_matching_count_passes():
    f = _f(title="powershell.exe in 10 hit(s) across evtxecmd")
    v = verify_claim(f, **_good(family_count=_replayer({"evtxecmd": 10})))
    assert v["checks"]["L1.7"]["status"] == "pass", v["checks"]["L1.7"]


def test_l1_7_a_lower_bound_may_sit_under_the_real_number():
    """A truncated scan says "46+", so under-counting is not a discrepancy."""
    f = _f(title="onedrive appears in 46+ hit(s) across evtxecmd")
    v = verify_claim(f, **_good(family_count=_replayer({"evtxecmd": 120})))
    assert v["checks"]["L1.7"]["status"] == "pass", v["checks"]["L1.7"]


def test_l1_7_a_lower_bound_may_not_overstate():
    f = _f(title="onedrive appears in 500+ hit(s) across evtxecmd")
    v = verify_claim(f, **_good(family_count=_replayer({"evtxecmd": 10})))
    assert v["checks"]["L1.7"]["status"] == "fail"


def test_l1_7_a_count_with_no_family_cannot_be_replayed_so_is_skipped():
    """An uncheckable number is the one a reader should be told about."""
    f = _f(title="powershell.exe executed; 25 events were seen")
    v = verify_claim(f, **_good(family_count=_replayer({})))
    assert v["checks"]["L1.7"]["status"] == "skipped", v["checks"]["L1.7"]


def test_l1_7_an_unknown_family_is_unverifiable_not_passed():
    f = _f(title="powershell.exe in 10 hit(s) across nosuchfamily")
    v = verify_claim(f, **_good(family_count=_replayer({})))
    assert v["checks"]["L1.7"]["status"] == "unverifiable", v["checks"]["L1.7"]
    assert v["verdict"] == "UNVERIFIABLE"


def test_l1_7_no_family_count_hook_is_unverifiable():
    f = _f(title="powershell.exe in 10 hit(s) across evtxecmd")
    v = verify_claim(f, **_good())  # no hook wired at all
    assert v["checks"]["L1.7"]["status"] == "unverifiable"
    assert "index not queryable" in v["checks"]["L1.7"]["detail"]


def test_l1_8_cross_mode_denial_is_contradicted():
    f = _f(title="powershell.exe executed")
    cross = {"contradictions": [{"key": {"entity_type": "process",
                                         "entity_value": "powershell.exe",
                                         "claim_kind": "observation"}}],
             "row_contradictions": []}
    v = verify_claim(f, **_good(cross_mode=cross))
    assert v["checks"]["L1.8"]["status"] == "fail"
    assert v["verdict"] == "CONTRADICTED", v["verdict"]


def test_l1_9_coverage_gaps_fail():
    cov = {"overall": "gaps", "sections": {"tools": {"status": "gaps"}}}
    v = verify_claim(_f(), **_good(coverage=cov))
    assert v["checks"]["L1.9"]["status"] == "fail"
    assert "tools" in v["checks"]["L1.9"]["detail"]


def test_inapplicable_checks_are_skipped_not_passed():
    v = verify_claim(_f(title="something happened"), **_good())
    # No techniques, no timestamps, no counts: skipped. A missing submission
    # seal is NOT skipped - WO-23 makes it unverifiable (never a pass) and the
    # verdict UNVERIFIABLE, which requires an override reason to approve.
    for key in ("L1.4", "L1.5", "L1.7"):
        assert v["checks"][key]["status"] == "skipped", key
    assert v["checks"]["L1.6"]["status"] == "unverifiable"
    assert v["counts"]["skipped"] >= 3
    assert v["verdict"] == "UNVERIFIABLE"


# --------------------------------------------------------------------------
# ledger
# --------------------------------------------------------------------------

def test_ledger_counts_and_overall(tmp_path):
    (tmp_path / "findings.json").write_text(json.dumps([
        _f(id="F1", title="powershell.exe executed"),
        {"id": "F2", "title": "invented", "artifacts": [{"audit_id": "nx-nope"}]},
    ]), encoding="utf-8")
    led = verify_case(tmp_path)
    assert len(led["claims"]) == 2
    assert sum(led["verdict_counts"].values()) == 2
    assert led["overall"] == "MIXED"
    p = write_ledger(tmp_path, led)
    assert json.loads(p.read_text(encoding="utf-8"))["case_id"] == tmp_path.name


def test_empty_case_is_not_proven(tmp_path):
    led = verify_case(tmp_path)
    assert led["claims"] == []
    assert led["overall"] == "UNVERIFIABLE"


def test_markdown_separates_failures_from_could_not_verify(tmp_path):
    led = {
        "verdict_counts": {"PROVEN": 1, "UNSUPPORTED": 1, "CONTRADICTED": 0, "UNVERIFIABLE": 0},
        "claims": [
            {"id": "F1", "title": "a", "verdict": "PROVEN", "checks": {}},
            {"id": "F2", "title": "b", "verdict": "UNSUPPORTED",
             "checks": {"L1.3": {"status": "fail", "detail": "absent from the rows"},
                        "L1.9": {"status": "unverifiable", "detail": "coverage not run"}}},
        ],
    }
    md = render_ledger_markdown(led)
    assert "**Could not verify**" in md
    assert "L1.9" in md and "L1.3" in md
    assert md.index("**Details**") < md.index("**Could not verify**")


def test_l1_10_mention_in_a_data_blob_is_not_corroboration():
    """The real case: a `sdelete` needle matched a System Restore event.

    EventID 8194 "Restore point created successfully" whose Data field merely
    lists sdelete among the applications registered for the restore point. The
    row mentions the entity; it does not evidence it, and "Signal: sdelete -
    1 hit(s)" reads as though it did. A needle matches a substring anywhere in
    a row, so nothing upstream will catch this on its own.
    """
    f = _f(
        title="Signal: sdelete - 1 hit(s) across evtxecmd",
        evidence=[{
            "time": "2020-11-14T13:48:07",
            "source": "evtxecmd/EvtxECmd_Output.csv",
            "artifact": "evtxecmd/EvtxECmd_Output.csv",
            "detail": "MapDescription: Restore point created successfully",
            "loc": "evtxecmd/EvtxECmd_Output.csv:2272",
            "fields": {"EventId": "8194", "Provider": "System Restore",
                       "Data": 'systempropertiesprotection.exe, sdelete'},
        }],
    )
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.10"]["status"] == "fail", v["checks"]["L1.10"]
    assert "mention, not an instance" in v["checks"]["L1.10"]["detail"]
    assert v["verdict"] == "UNSUPPORTED"


def test_l1_10_a_row_that_names_the_entity_passes():
    f = _f(
        title="Signal: powershell.exe - 11 hit(s) across hayabusa",
        evidence=[{
            "time": "2020-11-02T18:38:46",
            "source": "hayabusa/evtx-timeline.csv",
            "artifact": "hayabusa/evtx-timeline.csv",
            "detail": "powershell.exe launched an encoded command from temp",
            "loc": "hayabusa/evtx-timeline.csv:41",
            "fields": {"EventId": "4104", "Provider": "Microsoft-Windows-PowerShell"},
        }],
    )
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.10"]["status"] == "pass", v["checks"]["L1.10"]


def test_l1_10_skipped_when_there_are_no_evidence_rows():
    v = verify_claim(_f(), **_good())
    assert v["checks"]["L1.10"]["status"] == "skipped"


def test_l1_10_skipped_when_the_claim_names_no_subject():
    """No needle and no entity means there is nothing a row could corroborate."""
    f = _f(title="An unexplained event occurred on the host",
           evidence=[{"detail": "something happened", "source": "x.csv"}])
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.10"]["status"] == "skipped", v["checks"]["L1.10"]


def test_l1_10_the_needle_is_the_claim_subject():
    """A bare needle is the subject even when the entity extractor sees nothing.

    `sdelete` and `pid_` are bare terms - no `.exe`, no path, no domain - so
    without lifting the needle from the title this check would have nothing to
    test and would pass the exact case it exists to catch.
    """
    from nexus.analysis.claim_verification import _claim_subjects

    assert "sdelete" in _claim_subjects({"title": "Signal: sdelete - 1 hit(s) across evtxecmd"})
    assert "pid_" in _claim_subjects({"title": "Signal: pid_ - 2+ hit(s) across hayabusa"})
    assert _claim_subjects({"title": "An unexplained event occurred"}) == []


def test_l1_10_a_blank_descriptor_is_not_held_against_the_finding():
    """A row with no descriptor fields at all cannot corroborate, but it also
    cannot be shown to be a false citation - it stays skipped, not failed."""
    f = _f(title="Signal: powershell.exe - 1 hit(s)",
           evidence=[{"loc": "x.csv:9"}])
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.10"]["status"] == "skipped"


def test_l1_5_an_absent_timestamp_is_not_a_fabricated_one():
    """An empty field claims nothing about time, so there is nothing to check.

    Mode 2 and Mode 3 both stage findings with `event_timestamp=""`. Failing
    those as "placeholder" repeats the error this module exists to avoid - a
    check with nothing to check read as a check that failed - and it marked all
    56 real claims UNSUPPORTED before any real failure could be read.
    """
    v = verify_claim(_f(timestamp=""), **_good())
    assert v["checks"]["L1.5"]["status"] == "skipped", v["checks"]["L1.5"]
    assert "no time claimed" in v["checks"]["L1.5"]["detail"]


def test_l1_5_a_nullified_timestamp_alongside_a_real_one():
    """One real time and one empty field: the real time is what gets judged."""
    f = _f(timestamp="2026-03-04T11:22:33Z", last_seen="")
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.5"]["status"] == "pass", v["checks"]["L1.5"]


def test_l1_5_all_empty_fields_skips_rather_than_fails():
    f = _f(timestamp="", first_seen="", last_seen="")
    v = verify_claim(f, **_good())
    assert v["checks"]["L1.5"]["status"] == "skipped"
    assert "3 timestamp field(s)" in v["checks"]["L1.5"]["detail"]


def test_verdict_vocabulary_is_fixed():
    assert set(VERDICTS) == {"PROVEN", "UNSUPPORTED", "CONTRADICTED", "UNVERIFIABLE"}
