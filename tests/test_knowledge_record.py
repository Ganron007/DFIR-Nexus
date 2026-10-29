"""TA-5.2: each mode's run record says which knowledge it used, noted where the knowledge was chosen.

The R1 matrix read every playbook "not recorded": Mode 1's record named no skill or playbook, Modes 2/3 named skills
without why, and no record named an executed analytic. The selection points note what they choose inside a recorded
run (`analysis/knowledge_record.py`); each mode's own entry point records and writes the section.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import patch

from nexus.analysis import knowledge_record
from nexus.analysis.knowledge_record import recording
from nexus.knowledge.skills import retrieve_skills, skills_for

EVTX = {"evtxecmd", "hayabusa"}


def test_outside_a_recorded_run_a_selection_notes_nothing():
    skills_for(EVTX)
    assert knowledge_record.current() is None


def test_the_ranking_records_what_it_chose_with_its_own_score_and_reasons():
    with recording() as record:
        chosen = [s["skill"] for s in skills_for(EVTX)]
        retrieve_skills(families=EVTX)
    skills = {s["skill"]: s for s in record.section()["skills"]}
    assert set(chosen) <= set(skills)
    entry = skills["ad_credential_attacks"]
    assert entry["times_chosen"] == 2 and entry["best_score"] > 0
    assert any(reason.startswith("family ") for reason in entry["why"])


def test_a_matched_playbook_is_recorded_with_the_families_that_matched():
    from nexus.langgraph.query_pack import _family_matched_playbooks

    with recording() as record:
        matched = _family_matched_playbooks({"evtxecmd"})
    playbooks = record.section()["playbooks"]
    assert matched and len(playbooks) == len(matched)
    assert all(p["why"] and p["why"][0].startswith("the case holds its declared ") for p in playbooks)


def test_every_executed_analytic_is_recorded_with_its_hits_and_only_a_match_is_a_lead(tmp_path, monkeypatch):
    from nexus.analysis import leads
    from nexus.analysis.behavioural_analytics import analytics_for

    monkeypatch.setattr("nexus.langgraph.query_pack._present_families", lambda case_dir: {"evtxecmd"})
    pack = [a for a in analytics_for({"evtxecmd"}) if isinstance(a.get("es"), dict) and a.get("es")]
    assert len(pack) >= 2
    first = pack[0]["es"]

    class Probe:
        def count_analytic(self, clause):
            return 3 if clause == first else 0

    with recording() as record:
        found = leads.behavioural_analytics_leads(tmp_path, probe=Probe())
    analytics = record.section()["analytics"]
    assert {a["outcome"] for a in analytics} == {"ran"} and len(analytics) == len(pack)
    assert [a["hits"] for a in analytics if a["hits"]] == [3]
    assert len(found) == 1 and found[0].extra["analytic"] == analytics[0]["analytic"]


def test_a_resumed_run_keeps_what_it_chose_before():
    with recording() as first:
        skills_for(EVTX)
    earlier = first.section()
    with recording() as resumed:
        resumed.merge(earlier)
        skills_for(EVTX)
    again = {s["skill"]: s["times_chosen"] for s in resumed.section()["skills"]}
    assert all(again[s["skill"]] == 2 * s["times_chosen"] for s in earlier["skills"])


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-KREC"
    (case / "analysis").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "CASE.yaml").write_text("name: krec\nstatus: active\n", encoding="utf-8")
    (case / "findings.json").write_text("[]", encoding="utf-8")
    return case


def test_mode2s_record_carries_the_skills_its_work_orders_chose(tmp_path):
    """The real Mode 2 entry point; its planner picks skills through the shared retrieval it always uses."""
    from nexus.modes import multi_role as m2

    case = _case(tmp_path)

    def plan(_case_dir, _question, **_kwargs):
        refs = m2._retrieve_skill_refs(families=sorted(EVTX), keywords=[], limit=4)
        return [m2.WorkOrder(order_id="wo-1", role="evidence", task="t1", family="evtxecmd", skill_refs=refs)]

    def work(order, **kwargs):
        m2.request_stop(kwargs["case_dir"], kwargs["run_id"])
        return m2.AgentResult(order_id=order.order_id, role=order.role, status="ok",
                              parsed={"notes": [], "candidate_findings": [], "coverage": {}})

    with patch.object(m2, "run_work_order", side_effect=work), patch.object(m2, "plan_work_orders", side_effect=plan):
        state = m2.run_mode2(case, "what happened", model=object(), es_ok=True)
    saved = json.loads((case / "analysis" / "mode2_runs" / f"{state['run_id']}.json").read_text(encoding="utf-8"))
    skills = {s["skill"]: s for s in saved["knowledge"]["skills"]}
    assert "ad_credential_attacks" in skills and skills["ad_credential_attacks"]["why"]


def test_mode3s_record_carries_what_its_seats_chose(tmp_path, monkeypatch):
    """The real Mode 3 entry point: its seats run inside LangGraph, so this also proves the record reaches them."""
    from nexus.modes.multi_agent import run_mode3
    from tests._measured_index import measured_index

    class Silent:
        def invoke(self, messages):
            class _Reply:
                content = json.dumps({"claims": [], "open_questions": []})
            return _Reply()

    measured_index(monkeypatch, {"evtxecmd": 3, "hayabusa": 3})
    case = _case(tmp_path)
    record = run_mode3(case, "q", families=[("evtxecmd", 3), ("hayabusa", 3)], model=Silent(), es_ok=True)
    saved = json.loads((case / "analysis" / "mode3_runs" / f"{record['run_id']}.json").read_text(encoding="utf-8"))
    seat_skills = {u["skill"] for u in saved.get("skills_used") or []}
    recorded = {s["skill"] for s in saved["knowledge"]["skills"]}
    assert seat_skills and seat_skills <= recorded


def test_a_mode1_pipeline_run_writes_its_knowledge_into_the_manifest(tmp_path, monkeypatch):
    """`run_pipeline` records around the graph, and `finalize_run` writes the section into the run's manifest."""
    from nexus.langgraph import llm_pipeline, pipeline_runs

    case = _case(tmp_path)

    async def no_tools(_config, sessions=None):
        return {}

    async def graph(_tools, **_kwargs):
        run = pipeline_runs.create_run(case, "interpret")
        skills_for(EVTX)
        pipeline_runs.finalize_run(run, "completed")
        return json.loads((run.path / "manifest.json").read_text(encoding="utf-8"))

    monkeypatch.setattr(llm_pipeline, "_load_mcp_tools", no_tools)
    monkeypatch.setattr(llm_pipeline, "_run_pipeline_with_tools", graph)
    manifest = asyncio.run(llm_pipeline.run_pipeline(case_id=case.name, mode="interpret"))
    assert "ad_credential_attacks" in {s["skill"] for s in manifest["knowledge"]["skills"]}
    assert knowledge_record.current() is None
