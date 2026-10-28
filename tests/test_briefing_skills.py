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
    assert b["hosts"] == ["WS01"]
    assert b["ledger"]["ok"] == 2 and b["ledger"]["skip"] == 1
    # needle→count signal map populated; EventId cells are field facts now
    scan = {s["needle"]: s["hits"] for s in b["needle_scan"]}
    facts = {f["needle"]: f["hits"] for f in b["needle_facts"]}
    assert "4624" not in scan, scan
    assert facts.get("4624") == 2, facts
    assert facts.get("4624", 0) and "EventID" in {
        f["field"] for f in b["needle_facts"] if f["needle"] == "4624"
    }
    assert scan.get("lsass", 0) >= 1
    # Part 12 FM-7: entities come from typed index fields only; a case with no index has none,
    # and nothing is typed from the rows' text (10.0.0.5 and 192.168.1.9 sit in the CSV).
    assert b["entities"] == {}


def test_briefing_markdown_renders(tmp_path, hayabusa_rule_leads):
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


def test_briefing_guided_first_pass(tmp_path, hayabusa_rule_leads):
    """WP 4j.3 — walkthrough order: alerts → entities → signals → starts."""
    from nexus.langgraph.briefing import case_briefing

    b = case_briefing(_mkcase(tmp_path))
    walk = b["walkthrough"]
    assert [s["key"] for s in walk] == ["alerts", "entities", "signals", "starting_points"]
    assert [s["order"] for s in walk] == [1, 2, 3, 4]
    # step 1 triage carries the critical/high alerts with a runnable needle
    assert walk[0]["count"] == 2
    assert walk[0]["actions"], "expected alert actions"
    assert all(a.get("needle") for a in walk[0]["actions"])
    # step 2 counts entity types; step 3 counts needles with hits
    assert walk[1]["count"] == len(b["entities"])
    assert walk[2]["count"] == len(b["needle_scan"])
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


def test_needles_are_counted_exactly_on_the_index(monkeypatch):
    """IC-13: on the index each needle's count is the index's own, not a count inside the scan's capped
    window (`lsass` 0 there, 18,977 rows on CASE-C5B04D31). A failed count is named, never sampled."""
    from nexus.langgraph import briefing, query_pack

    exact = {"lsass": 18977, "shell": 249419}

    def count_hits(_case, terms, _window, **_kw):
        term = terms[0]
        if term == "broken":
            raise RuntimeError("es down")
        return {"count": exact.get(term, 0), "exact": True, "backend": "elasticsearch"}

    monkeypatch.setattr(query_pack, "count_hits", count_hits)
    stats = {"backend": "elasticsearch"}
    counts = briefing._exact_needle_counts(Path("."), ["lsass", "shell", "procdump", "broken"], stats)
    assert counts == {"lsass": 18977, "shell": 249419, "procdump": 0}
    assert stats["count_failed"] == ["broken"]
    # Without the index nothing is claimed exact.
    assert briefing._exact_needle_counts(Path("."), ["lsass"], {"backend": "csv"}) is None


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
    """WP 4j.5c — briefing persists analysis/briefing.md + signal_map.csv so the
    examiner can review the analysis even when the UI isn't usable."""
    from nexus.langgraph.briefing import case_briefing

    case = _mkcase(tmp_path)
    b = case_briefing(case)

    md = case / "analysis" / "briefing.md"
    csv_path = case / "analysis" / "signal_map.csv"
    assert b["artifacts"]["briefing_md"] == str(md)
    assert b["artifacts"]["signal_map_csv"] == str(csv_path)
    assert md.exists() and csv_path.exists()
    assert "# Case Briefing" in md.read_text(encoding="utf-8")
    rows = csv_path.read_text(encoding="utf-8").splitlines()
    # IC-13: `exact` says whether the counts are the index's own or a capped sample's.
    assert rows[0] == "needle,hits,source,scanned,exact"
    # Scanned terms include 0-hit rows. Terms over the scan cap stay visible as
    # explicitly unscanned rows, so they cannot be mistaken for checked absence.
    # EventId cells are field facts — a 4624 row may remain in the map as a
    # scanned-with-0-signal entry (negative evidence), never with signal hits
    assert not any(
        r.startswith("4624,") and not r.startswith("4624,0,") for r in rows
    ), rows
    facts_path = case / "analysis" / "field_facts.csv"
    assert b["artifacts"]["field_facts_csv"] == str(facts_path)
    assert facts_path.exists()
    fact_rows = facts_path.read_text(encoding="utf-8").splitlines()
    assert fact_rows[0] == "needle,rows,field,class"
    assert any(r.startswith("4624,2,") for r in fact_rows), fact_rows
    # This scan covered every needle and every available file. With D325's
    # application caps removed, the local scan is complete and its counts are
    # exact even though it used the CSV backend rather than Elasticsearch.
    import csv as _csv

    records = list(_csv.DictReader(csv_path.read_text(encoding="utf-8").splitlines()))
    scanned = [r for r in records if r["scanned"] == "yes"]
    unscanned = [r for r in records if r["scanned"] == "no"]
    assert len(scanned) == b["scanned_needles"]
    assert len(scanned) + len(unscanned) == len(records)
    assert all(r["hits"] == "0" for r in unscanned)
    assert all(r["exact"] == "yes" for r in records)


def test_briefing_artifact_write_failure_is_nonfatal(tmp_path, hayabusa_rule_leads):
    """A read-only case dir must never break the briefing itself."""
    from unittest.mock import patch

    from nexus.langgraph.briefing import case_briefing

    case = _mkcase(tmp_path)
    with patch("nexus.langgraph.briefing.Path.write_text", side_effect=OSError("ro fs")):
        b = case_briefing(case)
    assert b["artifacts"] == {}
    assert b["alert_count"] == 2

def test_briefing_index_census_fallback_when_no_needle_hits(tmp_path, monkeypatch):
    """RDP-style logs with zero threat-needle hits must still show the
    host/user/time census — a false "0 hosts" reads as "nothing was
    processed" and hides the evidence entirely."""
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

    # No needle hits at all (threat needles vs benign RDP logs).
    monkeypatch.setattr(
        "nexus.langgraph.query_pack.n4_hits", lambda *a, **k: ([], "csv")
    )

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
    assert brief["census_source"] == "index"
    assert brief["hits_examined"] == 0          # honest: no needle hits
    assert "EC2AMAZ-JET8PQL" in brief["hosts"]
    assert brief["entities"]["host"][0]["value"] == "EC2AMAZ-JET8PQL"
    assert brief["entities"]["user"][0]["value"] == "administrator"
    assert brief["time_range"]["start"] == "2024-11-14T03:22:50"
    md = bmod.briefing_to_markdown(brief)
    assert "index census" in md

def test_briefing_markdown_flags_unscanned_needles():
    """When the retrieval layer could not query a needle, the briefing says so
    — a 0-hit row must never pass as 'checked, absent'."""
    from nexus.langgraph.briefing import briefing_to_markdown

    brief = {
        "inventory": {}, "families": [], "total_files": 0, "total_rows": 0,
        "scan_stats": {
            "mode": "terms", "terms_requested": 5, "terms_queried": 4,
            "terms_failed": ["rdp"], "chunk_queries": 1, "chunks_split": 0,
        },
        "needle_scan": [],
    }
    md = briefing_to_markdown(brief)
    assert "could NOT be queried" in md
    assert "rdp" in md
    assert "scanned=no" in md


def test_briefing_records_scan_stats(tmp_path, monkeypatch):
    """The briefing must report needle coverage (requested vs queried)."""
    from nexus.langgraph import briefing as bmod

    case = tmp_path / "CASE-STATS"
    ext = case / "extractions"
    ext.mkdir(parents=True)
    (ext / "hayabusa_x.csv").write_text(
        "TimeCreated,Computer,RuleTitle\n2024-01-01,WS01,RDP Logon\n",
        encoding="utf-8",
    )
    (case / "CASE.yaml").write_text("question: review\n", encoding="utf-8")

    def fake_hits(case_dir, terms, window, **kwargs):
        stats = kwargs.get("stats")
        if stats is not None:
            stats.update({
                "mode": "terms", "terms_requested": len(terms),
                "terms_queried": len(terms), "terms_failed": [],
                "chunk_queries": 1, "chunks_split": 0,
            })
        return [], "elasticsearch"

    monkeypatch.setattr("nexus.langgraph.query_pack.n4_hits", fake_hits)
    brief = bmod.case_briefing(case)
    assert brief["scan_stats"]["terms_requested"] > 0
    assert brief["scan_stats"]["terms_queried"] == brief["scan_stats"]["terms_requested"]
    assert brief["scan_stats"]["terms_failed"] == []
    assert brief["scan_truncated"] is False

def test_briefing_scan_incomplete_reports_failed_queries(tmp_path, monkeypatch):
    """A failed query is reported as incomplete; artificial result caps are gone."""
    from nexus.langgraph import briefing as bmod

    case = _mkcase(tmp_path)

    def fake_hits(case_dir, terms, window, **kwargs):
        stats = kwargs.get("stats")
        if stats is not None:
            stats.update({
                "mode": "terms", "terms_requested": len(terms),
                "terms_queried": len(terms) - 1, "terms_failed": ["one-failed-term"],
                "chunk_queries": 5, "chunks_split": 0,
            })
        return [], "elasticsearch"

    monkeypatch.setattr("nexus.langgraph.query_pack.n4_hits", fake_hits)
    brief = bmod.case_briefing(case)
    assert brief["scan_truncated"] is True
    assert brief["scan_stats"]["truncated"] is True
    assert brief["scan_stats"]["truncated_reasons"]
    md = bmod.briefing_to_markdown(brief)
    assert "LOWER BOUNDS" in md


def test_briefing_scans_every_curated_needle(tmp_path, monkeypatch):
    """Needle vocabulary is not cut at the former 300-term ceiling."""
    from nexus.knowledge import (
        attack_needles,
        external_needles,
        itm_needles,
        needle_terms,
        sigma_needles,
    )
    from nexus.langgraph import briefing as bmod
    from nexus.langgraph import query_pack

    terms = [f"artifact-command-{i:03d}" for i in range(350)]
    monkeypatch.setattr(attack_needles, "attack_needles_for", lambda *_a, **_k: terms)
    monkeypatch.setattr(sigma_needles, "sigma_needles_for", lambda *_a, **_k: [])
    monkeypatch.setattr(itm_needles, "itm_needles_for", lambda *_a, **_k: [])
    monkeypatch.setattr(itm_needles, "itm_strong_for", lambda *_a, **_k: [])
    monkeypatch.setattr(external_needles, "external_needles_for", lambda *_a, **_k: [])
    monkeypatch.setattr(external_needles, "external_strong_for", lambda *_a, **_k: [])
    monkeypatch.setattr(query_pack, "playbook_strong_terms_for_families", lambda *_a: [])
    monkeypatch.setattr(query_pack, "playbook_terms_for_families", lambda *_a: [])
    monkeypatch.setattr(query_pack, "collect_query_terms", lambda *_a: [])
    monkeypatch.setattr(needle_terms, "is_scannable_term", lambda _term: True)
    monkeypatch.setattr(query_pack, "is_needle_like", lambda _term: True)

    dropped: list[str] = []
    actual = bmod._scan_needles(tmp_path, ["hayabusa"], dropped)

    assert len(actual) == len(terms)
    assert dropped == []

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
    assert b["paths_summary"]["distinct"] == 0
