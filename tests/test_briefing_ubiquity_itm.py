"""F1 ubiquity demotion + F3 ITM coverage in the briefing.

Ubiquitous terms (matching a large share of the case) are background: ranked
last, excluded from the guided walkthrough, and never staged by the Mode 1
full run. ITM coverage lists relevant needle packs with hit counts - 0 hits is
negative evidence for those artifacts, not absence of risk.
"""

from __future__ import annotations

from pathlib import Path

HEADER = "Timestamp,RuleTitle,Level,Computer,Channel,EventID,Details"


def _case_with_rows(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-UBIQ"
    ext = case / "extractions" / "hayabusa"
    ext.mkdir(parents=True)
    rows = [HEADER]
    # Standout row FIRST (per-file collect caps must not starve it) ...
    rows.append(
        "2023-06-12 10:00:00,Suspicious,high,WS01,Sec,4688,"
        "net use \\\\fileserver\\share and usbstor device mounted"
    )
    # ... then 120 rows full of "cipher" (ubiquitous).
    for i in range(120):
        rows.append(
            f"2023-06-12 10:01:{i % 60:02d},Misc,info,WS01,Sec,4688,"
            f"routine cipher maintenance line {i}"
        )
    (ext / "evtx-timeline.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    (case / "CASE.yaml").write_text(
        "intake:\n  question: was data staged\n  query_extra: cipher\\nnet use\n",
        encoding="utf-8",
    )
    return case


def test_ubiquity_demotion_marks_and_excludes(tmp_path):
    from nexus.langgraph.briefing import case_briefing

    brief = case_briefing(_case_with_rows(tmp_path))
    scan = {s["needle"]: s for s in brief["needle_scan"]}
    # Hit counts are lower bounds (per-file collect cap); the demotion compares
    # the recorded count against the reported floor.
    assert scan["cipher"]["hits"] >= brief["ubiquity_floor"]
    assert scan["cipher"]["ubiquitous"] is True
    assert scan.get("net use", {}).get("ubiquitous") is False

    # Signal terms sort before background terms.
    needles = [s["needle"] for s in brief["needle_scan"]]
    assert needles.index("net use") < needles.index("cipher")

    # The guided walkthrough's signal step never promotes the background term.
    walk = brief["walkthrough"]
    signals = next(step for step in walk if step["key"] == "signals")
    labels = [str(a.get("needle") or "").lower() for a in signals["actions"]]
    assert "cipher" not in labels
    assert "net use" in labels

    # ubiquity threshold is reported for the UI/markdown.
    assert brief["ubiquity_floor"] >= 25


def test_itm_coverage_panel(tmp_path):
    from nexus.langgraph.briefing import briefing_to_markdown, case_briefing

    case = _case_with_rows(tmp_path)
    brief = case_briefing(case)
    coverage = brief.get("itm_coverage") or []
    assert coverage, "ITM coverage missing for hayabusa family"
    by_itm = {row["itm"]: row for row in coverage}
    # "usbstor" is a strong needle of AR3/PR002 -> that pack must show a hit.
    assert "AR3/PR002" in by_itm, sorted(by_itm)
    assert by_itm["AR3/PR002"]["strong_hits"] >= 1
    # Packs with no hits stay listed (negative evidence).
    assert any(row["hits"] == 0 for row in coverage)

    md = briefing_to_markdown(brief)
    assert "Insider Threat Matrix coverage" in md
    assert "AR3/PR002" in md
    assert "Background terms (ubiquitous" in md
