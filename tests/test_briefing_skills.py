"""WP 4i tests — briefing, skills, skill-driven agent execution."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


def _mkcase(tmp_path: Path) -> Path:
    """Minimal case dir with tools extractions + ledger."""
    case = tmp_path / "CASE-T1"
    ext = case / "extractions"
    ext.mkdir(parents=True)
    (ext / "hayabusa_alerts.csv").write_text(
        "Timestamp,Computer,Channel,EventID,Level,RuleTitle,OtherDetails\n"
        "2026-08-10 14:32:01,WS01,Sec,4688,critical,LSASS Memory Access,powershell.exe\n"
        "2026-08-10 14:33:02,WS01,Sec,1102,high,Security Log Cleared,wevtutil\n"
        "2026-08-10 14:40:00,WS01,Sec,4688,low,Benign Process,notepad.exe\n",
        encoding="utf-8",
    )
    (ext / "evtx_security.csv").write_text(
        "TimeCreated,EventID,Computer,TargetUserName,IpAddress\n"
        "2026-08-10 14:32:05,4624,WS01,analyst_t1,10.0.0.5\n"
        "2026-08-10 14:32:06,4624,WS01,admin,192.168.1.9\n",
        encoding="utf-8",
    )
    (ext / "_tool_lane_ledger.json").write_text(
        json.dumps([
            {"tool": "evtxecmd", "status": "OK", "family": "evtx"},
            {"tool": "hayabusa", "status": "OK", "family": "hayabusa"},
            {"tool": "pecmd", "status": "SKIP", "family": "prefetch", "reason": "no prefetch dir"},
        ]),
        encoding="utf-8",
    )
    (case / "CASE.yaml").write_text("question: was lsass dumped\n", encoding="utf-8")
    return case


def test_briefing_inventory_alerts_entities(tmp_path):
    from nexus.langgraph.briefing import case_briefing

    b = case_briefing(_mkcase(tmp_path))
    assert set(b["families"]) == {"evtx", "hayabusa"}
    assert b["total_rows"] == 5
    assert b["alert_count"] == 2
    titles = {a["title"] for a in b["alerts"]}
    assert "LSASS Memory Access" in titles
    assert "Security Log Cleared" in titles
    assert "Benign Process" not in titles
    assert b["hosts"] == ["WS01"]
    assert b["ledger"]["ok"] == 2 and b["ledger"]["skip"] == 1
    # needle→count signal map populated
    scan = {s["needle"]: s["hits"] for s in b["needle_scan"]}
    assert scan.get("4624") == 2
    assert scan.get("lsass", 0) >= 1
    # entities extracted
    assert "domain" in b["entities"] or "ipv4" in b["entities"]


def test_briefing_markdown_renders(tmp_path):
    from nexus.langgraph.briefing import briefing_to_markdown, case_briefing

    md = briefing_to_markdown(case_briefing(_mkcase(tmp_path)))
    assert "# Case Briefing" in md
    assert "LSASS Memory Access" in md
    assert "Signal map" in md


def test_briefing_empty_case(tmp_path):
    from nexus.langgraph.briefing import case_briefing

    case = tmp_path / "CASE-EMPTY"
    case.mkdir()
    b = case_briefing(case)
    assert b["families"] == []
    assert b["alert_count"] == 0
    assert b["needle_scan"] == []


def test_skills_load_and_validate():
    from nexus.knowledge.loader import get_skills, list_skills, validate_skill

    skills = get_skills()
    assert len(skills) >= 10
    for s in skills:
        assert validate_skill(s) == [], f"{s.get('skill')}: {validate_skill(s)}"
    ids = list_skills()
    assert "lsass_credential_access" in ids
    assert "lateral_movement" in ids
    assert "persistence" in ids


def test_skills_match_families_keywords():
    from nexus.knowledge.skills import skills_for

    m = skills_for(families={"evtx", "sysmon"}, keywords={"credential", "lsass"})
    assert m and m[0]["skill"] == "lsass_credential_access"

    m2 = skills_for(families={"lnk", "prefetch", "browser"})
    assert any(s["skill"] == "initial_access" for s in m2)

    # no match → empty
    assert skills_for(families={"zeek"}, keywords={"nonexistentword"}) == []


def test_agent_executes_skill_steps(tmp_path):
    from nexus.langgraph.orchestrator import run_orchestrator

    case = _mkcase(tmp_path)
    result = run_orchestrator(case)
    runs = result["agent_runs"]
    assert runs
    # the timeline agent owns evtx/hayabusa and should have executed skills
    timeline = next((r for r in runs if r["agent"] == "timeline"), runs[0])
    assert timeline["skills_used"], "expected skills to be selected"
    assert len(timeline["skill_results"]) >= 3
    # every skill step recorded with hits_found
    for sr in timeline["skill_results"]:
        assert "hits_found" in sr and "query" in sr
    # lsass skill step should have hit on our synthetic hayabusa row
    lsass_hits = [sr for sr in timeline["skill_results"]
                  if sr["skill"] == "lsass_credential_access" and sr["hits_found"] > 0]
    assert lsass_hits, "lsass skill found no hits on synthetic evidence"


def test_negative_evidence_recorded(tmp_path):
    """Steps that find nothing record the skill's negative statement."""
    from nexus.langgraph.orchestrator import run_orchestrator

    case = _mkcase(tmp_path)
    # Remove the lsass hit so the lsass-access steps find nothing
    (case / "extractions" / "hayabusa_alerts.csv").write_text(
        "Timestamp,Computer,Channel,EventID,Level,RuleTitle,OtherDetails\n"
        "2026-08-10 14:40:00,WS01,Sec,4688,low,Benign Process,notepad.exe\n",
        encoding="utf-8",
    )
    result = run_orchestrator(case)
    negs = []
    for r in result["agent_runs"]:
        negs.extend(r.get("negative_evidence") or [])
    # at least one skill step found nothing and recorded negative evidence
    assert negs, "expected negative evidence to be recorded for empty steps"
    assert any("negative_evidence" in n for n in negs)
