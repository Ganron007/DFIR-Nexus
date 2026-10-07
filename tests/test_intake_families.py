"""WO-R1F item 6 — Mode 1 works on "Compromise suspected." alone.

With no playbooks, the needle packs must be chosen from the case's own evidence
families, and the intake must record **who set it** (`set_by: operator | agent`)
— an intake the agent inferred is not the same evidence as one the examiner
wrote.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml


def _case_with_ledger(tmp_path: Path, tools: list[str]) -> Path:
    case = tmp_path / "CASE-INT00001"
    ext = case / "runs" / "RUN-1" / "extractions"
    ext.mkdir(parents=True)
    rows = [
        {"tool": tool, "status": "OK", "audit_id": f"nexus-gate-bot-20260101-{i:03d}"}
        for i, tool in enumerate(tools, start=1)
    ]
    (ext / "_tool_lane_ledger.json").write_text(json.dumps(rows), encoding="utf-8")
    (ext / "output.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    (case / "CASE.yaml").write_text(
        yaml.safe_dump({"case_id": case.name, "status": "created"}), encoding="utf-8"
    )
    return case


def test_present_families_reads_the_ledger(tmp_path: Path):
    from nexus.langgraph.query_pack import _present_families

    case = _case_with_ledger(tmp_path, ["hayabusa", "evtxecmd", "hayabusa"])
    assert _present_families(case) == ["hayabusa", "evtxecmd"]


def test_present_families_ignores_non_ok_rows(tmp_path: Path):
    from nexus.langgraph.query_pack import _present_families

    case = _case_with_ledger(tmp_path, ["hayabusa"])
    path = case / "runs" / "RUN-1" / "extractions" / "_tool_lane_ledger.json"
    rows = json.loads(path.read_text(encoding="utf-8"))
    rows.append({"tool": "lecmd", "status": "FAIL"})
    path.write_text(json.dumps(rows), encoding="utf-8")
    assert "lecmd" not in _present_families(case)


def test_needle_terms_are_derived_from_the_families(tmp_path: Path):
    """The whole point of item 6: "Compromise suspected." with no playbooks."""
    from nexus.langgraph.query_pack import (
        _present_families,
        playbook_strong_terms_for_families,
    )

    case = _case_with_ledger(tmp_path, ["vol", "hayabusa", "evtxecmd", "mftecmd"])
    terms = playbook_strong_terms_for_families(_present_families(case))
    assert terms, "no needle terms derived from the case's families"
    # A memory/crash family must contribute credential-dump needles.
    assert any(t.lower() in {"mimikatz", "procdump", "lsass", "comsvcs"} for t in terms), terms


def test_query_pack_markdown_records_set_by_and_the_derivation(tmp_path: Path, monkeypatch):
    from nexus.langgraph import query_pack

    case = _case_with_ledger(tmp_path, ["vol", "hayabusa"])
    (case / "CASE.yaml").write_text(
        yaml.safe_dump({
            "case_id": case.name,
            "status": "created",
            "intake": {"question": "Compromise suspected.", "set_by": "operator"},
        }),
        encoding="utf-8",
    )
    # n4_hits needs the index; stub it — this test is about the pack's header.
    monkeypatch.setattr(
        query_pack, "n4_hits",
        lambda *a, **k: ([], "test"),
    )
    md = query_pack.build_query_pack_markdown(case)
    assert "intake set by: operator" in md
    assert "needle packs auto-chosen from the case's families" in md
    assert "Compromise suspected." in md


def test_a_placeholder_window_alone_is_not_intake():
    """The N1 gate: a placeholder window must not count as examiner intake."""
    from nexus.langgraph.llm_pipeline import has_examiner_intake

    assert has_examiner_intake({"question": "Compromise suspected."}) is True
    assert has_examiner_intake({"question": ""}) is False
    assert has_examiner_intake(
        {"window": "examiner-supplied; evidence timestamps win"}
    ) is False
    assert has_examiner_intake({"window": "2023-01-25..2023-01-26"}) is True
