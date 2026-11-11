"""Tests for D136 / KR3 / KR4: skill steps execution, leads, and absence accounting."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from nexus.analysis.absence import source_activity
from nexus.analysis.leads import Lead, skill_step_leads
from nexus.analysis.skill_steps import run_skill_steps
from nexus.modes.multi_role import WorkOrder, _record_skill_steps


def test_run_skill_steps_records_sample_rows_on_hit():
    skill = {
        "skill": "test_cred_theft",
        "steps": [
            {
                "name": "step1",
                "kind": "search",
                "es": {"query": {"term": {"event.code": 10}}},
                "pivot": "lsass",
                "look_for": "lsass access",
            }
        ],
    }

    def fake_search(query, limit):
        return {
            "total": 3,
            "hits": [
                {"_id": "doc1", "source": "evtx", "detail": "lsass open"},
                {"_id": "doc2", "source": "evtx", "detail": "lsass read"},
            ],
        }

    res = run_skill_steps(skill, es_search=fake_search, limit=5)
    assert res["methodology_only"] is False
    assert len(res["steps"]) == 1
    step = res["steps"][0]
    assert step["result"] == "hit"
    assert step["hits"] == 3
    assert len(step["sample_rows"]) == 2
    assert step["sample_rows"][0]["_id"] == "doc1"


def test_record_skill_steps_disposition_for_work_order(tmp_path: Path):
    case_dir = tmp_path / "CASE-TEST"
    case_dir.mkdir()
    order = WorkOrder(
        order_id="WO-01",
        role="evidence",
        task="examine creds",
        skill_refs=[{"skill": "lsass_credential_access", "version": "1.0"}],
    )

    records = _record_skill_steps(order, case_dir, case_families=["evtx"])
    assert len(records) == 1
    rec = records[0]
    assert rec["skill"] == "lsass_credential_access"
    assert "summary" in rec
    assert rec["summary"].get("not_applicable", 0) > 0
    assert any("WO-KR3" in s.get("reason", "") for s in rec.get("steps", []))


def test_skill_step_leads_generates_leads_on_matches(tmp_path: Path):
    case_dir = tmp_path / "CASE-TEST"
    case_dir.mkdir()

    class FakeProbe:
        def count_analytic(self, clause):
            return 2

        def analytic_hits(self, clause):
            return [{"source": "test", "detail": "match", "file": "test.evtx", "line": 1}]

    with patch("nexus.langgraph.es_native.family_doc_counts", return_value={"evtx": 100}):
        leads = skill_step_leads(case_dir, probe=FakeProbe(), limit=5)

    assert len(leads) > 0
    lead = leads[0]
    assert lead.kind == "skill_step"
    assert "skill" in lead.extra
    assert "step" in lead.extra
    assert lead.extra["count"] > 0
    assert len(lead.rows) > 0


def test_absence_source_activity_accurately_credits_skills_and_analytics(tmp_path: Path):
    # Case with no evidence families
    empty_activity = source_activity(tmp_path, families=[], leads=[])
    assert empty_activity["analytics"]["ran"] is False
    assert empty_activity["skills"]["ran"] is False

    # Case with families and executed leads
    leads = [
        Lead(kind="behavioral_analytic", subject="a1", family="evtx", detail="d", rows=(), audit_ids=(), score=0.9),
        Lead(kind="skill_step", subject="s1", family="evtx", detail="d", rows=(), audit_ids=(), score=0.9),
    ]
    with patch("nexus.analysis.behavioural_analytics.analytics_for", return_value=[{"id": "a1"}]):
        active_activity = source_activity(tmp_path, families=["evtx"], leads=leads)

    assert active_activity["analytics"]["ran"] is True
    assert active_activity["analytics"]["count"] == 1
    assert active_activity["skills"]["ran"] is True
    assert active_activity["skills"]["count"] == 1
