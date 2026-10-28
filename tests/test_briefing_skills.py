"""WP 4i tests — briefing, skills, skill-driven agent execution."""
from __future__ import annotations

import json
from pathlib import Path


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


def test_briefing_inventory_alerts_entities(tmp_path, hayabusa_rule_leads):
    from nexus.langgraph.briefing import case_briefing

    b = case_briefing(_mkcase(tmp_path))
    assert set(b["families"]) == {"evtx", "hayabusa"}
    assert b["total_rows"] == 5
    assert b["alert_count"] == 2
    titles = {a["title"] for a in b["alerts"]}
    assert "LSASS Memory Access" in titles
    assert "Security Log Cleared" in titles
    assert "Benign Process" not in titles
    # Each alert is keyed by the audit id of its lead's rows, crit before high.
    assert [(a["key"], a["level"]) for a in b["alerts"]] == [
        ("nexus-hayabusa-d1", "crit"), ("nexus-hayabusa-d2", "high")]
    assert b["alerts"][0]["doc_ids"] == ["d1"]
    # D460: hosts and time come from the index only; this case has none, and its rows are no source.
    assert b["hosts"] == []
    assert b["ledger"]["ok"] == 2 and b["ledger"]["skip"] == 1
    # D460: no keyword is counted (no signal map, field facts, ubiquity or scan accounting).
    assert not {"needle_scan", "needle_facts", "itm_coverage", "scan_stats", "hits_examined"} & set(b)
    # Part 12 FM-7: entities come from typed index fields only; a case with no index has none,
    # and nothing is typed from the rows' text (10.0.0.5 and 192.168.1.9 sit in the CSV).
    assert b["entities"] == {}


def test_briefing_markdown_renders(tmp_path, hayabusa_rule_leads):
    from nexus.langgraph.briefing import briefing_to_markdown, case_briefing

    md = briefing_to_markdown(case_briefing(_mkcase(tmp_path)))
    assert "# Case Briefing" in md
    assert "LSASS Memory Access" in md
    assert "## Leads" in md and "Signal map" not in md


def test_briefing_empty_case(tmp_path):
    from nexus.langgraph.briefing import case_briefing

    case = tmp_path / "CASE-EMPTY"
    case.mkdir()
    b = case_briefing(case)
    assert b["families"] == []
    assert b["alert_count"] == 0
    assert "needle_scan" not in b


def test_briefing_guided_first_pass(tmp_path, hayabusa_rule_leads):
    """WP 4j.3 — walkthrough order: alerts → entities → leads → starts (D460: leads, not keyword counts)."""
    from nexus.langgraph.briefing import case_briefing

    b = case_briefing(_mkcase(tmp_path))
    walk = b["walkthrough"]
    assert [s["key"] for s in walk] == ["alerts", "entities", "leads", "starting_points"]
    assert [s["order"] for s in walk] == [1, 2, 3, 4]
    # step 1 triage carries the critical/high alerts with a runnable needle
    assert walk[0]["count"] == 2
    assert walk[0]["actions"], "expected alert actions"
    assert all(a.get("needle") for a in walk[0]["actions"])
    # step 2 counts entity types; step 3 the leads below crit/high (the crit/high ones are step 1)
    assert walk[1]["count"] == len(b["entities"])
    below = [lead for lead in b["leads"] if not (lead.get("extra") or {}).get("crit_high")]
    assert walk[2]["count"] == len(below) >= 1
    assert {a["needle"] for a in walk[2]["actions"]} <= {lead["subject"] for lead in below}
    # step 4 dedupes starting needles across the first three steps
    starts = [a["needle"].lower() for a in walk[3]["actions"]]
    assert starts == list(dict.fromkeys(starts))
    # every step explains itself (learning, not just a list)
    assert all(s["why"] for s in walk)


def test_briefing_walkthrough_empty_case(tmp_path):
    """A case with no hits still yields the walkthrough shape (counts 0)."""
    from nexus.langgraph.briefing import case_briefing

    case = tmp_path / "CASE-EMPTY"
    case.mkdir()
    walk = case_briefing(case)["walkthrough"]
    assert len(walk) == 4
    assert walk[0]["count"] == 0
    assert walk[0]["why"]


def test_briefing_walkthrough_learn_explanations(tmp_path):
    """WP 4j.4 — every walkthrough step teaches 'why this matters'."""
    from nexus.langgraph.briefing import case_briefing

    walk = case_briefing(_mkcase(tmp_path))["walkthrough"]
    for st in walk:
        learn = st.get("learn") or {}
        assert learn.get("headline"), f"{st['key']} missing learn headline"
        assert learn.get("why_matters"), f"{st['key']} missing why_matters"
    # the alerts step teaches FD-004-style caution from the technique caveat
    assert any("false" in w.lower() or "require" in w.lower() or "legitimate" in w.lower()
               for w in walk[0]["learn"]["why_matters"])


def test_briefing_markdown_learn(tmp_path):
    from nexus.langgraph.briefing import briefing_to_markdown, case_briefing

    md = briefing_to_markdown(case_briefing(_mkcase(tmp_path)))
    assert "Why this matters:" in md


def test_briefing_intake_echo_loaded(tmp_path):
    """Regression: intake is read via query_pack (was imported from the wrong
    module, so the intake echo silently never populated)."""
    from nexus.langgraph.briefing import case_briefing

    b = case_briefing(_mkcase(tmp_path))
    assert b["intake"].get("question") == "was lsass dumped"


def test_briefing_markdown_walkthrough(tmp_path):
    from nexus.langgraph.briefing import briefing_to_markdown, case_briefing

    md = briefing_to_markdown(case_briefing(_mkcase(tmp_path)))
    assert "## Guided first pass" in md
    assert "1. Triage the alerts" in md


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


def test_every_skill_step_query_parses():
    """4j.7 regression — every steps[].query in every shipped skill must
    parse through the real N4 DSL (orchestrator passes them verbatim)."""
    from nexus.knowledge.loader import get_skills
    from nexus.langgraph.query_dsl import parse_query

    skills = get_skills()
    assert len(skills) >= 20
    failures = []
    step_count = 0
    for s in skills:
        for st in s.get("steps") or []:
            step_count += 1
            q = str(st.get("query") or "")
            try:
                parse_query(q)
            except Exception as exc:  # pragma: no cover - report all
                failures.append(f"{s.get('skill')}::{st.get('name')}: {exc}")
    assert not failures, "unparseable skill queries:\n" + "\n".join(failures)
    assert step_count >= 150  # guard against accidental mass-drops


def test_skills_match_families_keywords():
    from nexus.knowledge.skills import skills_for

    m = skills_for(families={"evtx", "sysmon"}, keywords={"credential", "lsass"})
    assert m and m[0]["skill"] == "lsass_credential_access"

    m2 = skills_for(families={"lnk", "prefetch", "browser"})
    assert any(s["skill"] == "initial_access" for s in m2)

    # no match → empty
    assert skills_for(families={"nonexistent_family"}, keywords={"nonexistentword"}) == []


def test_briefing_route_excludes_llm_directions(tmp_path, monkeypatch):
    """The deterministic briefing must never block on the LLM — ``directions``
    is fetched lazily via a separate endpoint (was an inline 50s+ call)."""
    from unittest.mock import patch

    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case = _mkcase(tmp_path)
    with patch("nexus.dashboard.app._get_case_dir", return_value=case):
        app = Starlette(routes=create_dashboard())
        client = TestClient(app)
        resp = client.get("/portal/api/case/briefing")
    assert resp.status_code == 200
    data = resp.json()
    assert "directions" not in data  # LLM layer no longer inline
    assert "walkthrough" in data and len(data["walkthrough"]) == 4


def test_briefing_directions_endpoint_no_model(tmp_path):
    """Lazy directions endpoint returns an empty list when no LLM is set."""
    from unittest.mock import patch

    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    case = _mkcase(tmp_path)
    with patch("nexus.dashboard.app._get_case_dir", return_value=case), \
         patch("nexus.langgraph.llm_pipeline.get_model", side_effect=RuntimeError("no model")):
        app = Starlette(routes=create_dashboard())
        client = TestClient(app)
        resp = client.get("/portal/api/case/briefing/directions")
    assert resp.status_code == 200
    assert resp.json() == {"directions": []}


def test_a_playbook_line_about_events_the_case_lacks_is_not_shown(monkeypatch):
    """IC-14: "LSASS access detected in Sysmon Event ID 10" was why every alert of a case with no Sysmon log
    mattered, in 7 of Mode 1's 9 calls. A line naming events the index does not hold is left out."""
    from nexus.langgraph import interpret, named_events, query_pack

    monkeypatch.setattr(query_pack, "_family_matched_playbooks", lambda _f: [{"triggers": [
        "LSASS access detected in Sysmon Event ID 10",
        "Known credential tools in Prefetch (mimikatz, procdump, comsvcs.dll)",
        "Logons with explicit credentials, Event ID 4648",
    ]}])
    present = {("sysmon", "10"): 0, ("", "4648"): 21}
    monkeypatch.setattr(named_events, "_index_event_count", lambda _c, event: present.get(event))
    shown = interpret._playbook_triggers("hayabusa", limit=5, case_dir=Path("CASE-X"))
    assert shown == ["Known credential tools in Prefetch (mimikatz, procdump, comsvcs.dll)",
                     "Logons with explicit credentials, Event ID 4648"]
    # Without a case nothing can be checked, and every line stays.
    assert len(interpret._playbook_triggers("hayabusa", limit=5)) == 3


def test_briefing_writes_offline_artifacts(tmp_path):
    """WP 4j.5c — briefing persists analysis/briefing.md so the examiner can review
    the analysis even when the UI isn't usable. D460: no signal map or field facts."""
    from nexus.langgraph.briefing import case_briefing

    case = _mkcase(tmp_path)
    b = case_briefing(case)

    md = case / "analysis" / "briefing.md"
    assert b["artifacts"] == {"briefing_md": str(md)}
    assert md.exists()
    assert "# Case Briefing" in md.read_text(encoding="utf-8")
    assert not (case / "analysis" / "signal_map.csv").exists()
    assert not (case / "analysis" / "field_facts.csv").exists()


def test_briefing_artifact_write_failure_is_nonfatal(tmp_path, hayabusa_rule_leads):
    """A read-only case dir must never break the briefing itself."""
    from unittest.mock import patch

    from nexus.langgraph.briefing import case_briefing

    case = _mkcase(tmp_path)
    with patch("nexus.langgraph.briefing.Path.write_text", side_effect=OSError("ro fs")):
        b = case_briefing(case)
    assert b["artifacts"] == {}
    assert b["alert_count"] == 2

def test_briefing_hosts_users_and_time_come_from_the_index(tmp_path, monkeypatch):
    """RDP-style logs must show the host/user/time census from the index — a false
    "0 hosts" reads as "nothing was processed" and hides the evidence entirely."""
    from nexus.langgraph import briefing as bmod

    case = tmp_path / "CASE-CENSUS"
    ext = case / "extractions"
    ext.mkdir(parents=True)
    (ext / "evtxecmd_rdp.csv").write_text(
        "TimeCreated,EventID,Computer,UserName,RemoteHost\n"
        "2024-11-14 03:22:50,34,EC2AMAZ-JET8PQL,,219.100.37.234\n"
        "2024-11-23 04:06:23,21,EC2AMAZ-3NFFVNI,Administrator,219.100.37.234\n",
        encoding="utf-8",
    )
    (case / "CASE.yaml").write_text("question: rdp review\n", encoding="utf-8")

    def fake_agg(case_dir, dsl="", field="host", top=20, bucket="",
                 match_all=False, window=None, with_spans=False):
        if field == "host":
            return {"field": "host", "top": [
                {"value": "EC2AMAZ-JET8PQL", "count": 1,
                 "first_seen": "2024-11-14T03:22:50", "last_seen": "2024-11-14T03:22:50"},
                {"value": "EC2AMAZ-3NFFVNI", "count": 1,
                 "first_seen": "2024-11-23T04:06:23", "last_seen": "2024-11-23T04:06:23"},
            ]}
        if field == "user":
            return {"field": "user", "top": [
                {"value": "administrator", "count": 1,
                 "first_seen": "2024-11-23T04:06:23", "last_seen": "2024-11-23T04:06:23"},
            ]}
        return None

    monkeypatch.setattr("nexus.langgraph.case_index.es_aggregate", fake_agg)
    from nexus.langgraph import typed_entities

    monkeypatch.setattr(typed_entities, "case_entities", lambda case_id: {
        "fields": {}, "host": [{"value": "EC2AMAZ-JET8PQL", "count": 1, "families": ["evtxecmd"],
                                "source_file": "evtxecmd_rdp.csv"}],
        "user": [{"value": "administrator", "count": 1, "families": ["evtxecmd"],
                  "source_file": "evtxecmd_rdp.csv"}]})
    brief = bmod.case_briefing(case)
    assert "EC2AMAZ-JET8PQL" in brief["hosts"]
    assert brief["entities"]["host"][0]["value"] == "EC2AMAZ-JET8PQL"
    assert brief["entities"]["user"][0]["value"] == "administrator"
    assert brief["time_range"]["start"] == "2024-11-14T03:22:50"

def test_top_entities_are_typed_and_never_paths(tmp_path, monkeypatch):
    """Part 12 FM-7: the briefing's entities are the typed fields' values with their evidence file;
    a path inside an artifact (host filesystem content) is never typed as an entity from text."""
    from nexus.langgraph import typed_entities
    from nexus.langgraph.briefing import case_briefing

    case = _mkcase(tmp_path)
    (case / "extractions" / "mft.csv").write_text(
        "TimeCreated,Path,Computer\n"
        "2026-08-10 14:35:00,C:\\Windows\\System32\\lsass.exe,WS01\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(typed_entities, "case_entities", lambda case_id: {
        "fields": {}, "process": [{"value": "lsass.exe", "count": 1, "families": ["vol"],
                                   "source_file": "vol/pslist.txt"}]})
    b = case_briefing(case)
    assert set(b["entities"]) == {"process"}
    assert b["entities"]["process"][0]["source_file"] == "vol/pslist.txt"
    assert "paths_summary" not in b


def test_a_scanner_severity_alert_ranks_by_its_score(tmp_path, monkeypatch):
    """D459: T22's YARA alert at `severity 100` sorted after `high` review items by its level."""
    from nexus.analysis import leads as leads_mod
    from nexus.langgraph.briefing import alerts_from_leads

    def lead(subject, level, score):
        return leads_mod.Lead(kind="rule_engine", subject=subject, family="memprocfs", detail="", score=score,
                              audit_ids=(f"a-{subject}",), extra={"crit_high": True, "level": level}).to_dict()

    alerts = alerts_from_leads(tmp_path, [lead("baseline item", "high", 0.5), lead("YARA match", "severity 100", 1.0)])
    assert [a["title"] for a in alerts] == ["YARA match", "baseline item"]
