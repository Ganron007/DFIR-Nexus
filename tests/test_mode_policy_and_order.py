"""Modes 2 and 3 apply the run's context policy; Mode 2 plans the strongest leads first (2026-10-14).

CASE-C5B04D31's Mode 2 run (``independent``) spent four of six work orders on "seen once" rarity
leads and none on the critical detections, and it was handed every DRAFT of the case's other runs
as a work order. Mode 3 recorded ``informed`` and never applied it, so an informed run planned
exactly as an independent one.
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from nexus.analysis.work_orders import orders_from_leads
from nexus.modes import multi_role as m2

DRAFT = {"id": "F-9", "title": "Another run's DRAFT", "status": "DRAFT",
         "interpretation": "prior conclusion"}


def test_a_critical_detection_is_planned_before_a_rarity_lead_of_equal_score(tmp_path):
    leads = [
        {"kind": "rarity", "subject": "autochk.exe", "score": 1.0, "rows": [], "audit_ids": []},
        {"kind": "rule_engine", "subject": "Antivirus - Password Dumper Signature", "score": 1.0,
         "rows": [], "audit_ids": [], "extra": {"level": "crit"}},
    ]
    orders = orders_from_leads(tmp_path, "Compromise suspected.", leads=leads, max_orders=1)
    assert [o["lead_kind"] for o in orders] == ["rule_engine"]


def _case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-POL"
    (case / "analysis").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "CASE.yaml").write_text("name: pol\nstatus: active\n", encoding="utf-8")
    (case / "findings.json").write_text(json.dumps([DRAFT]), encoding="utf-8")
    return case


def _mode2_feedback(case: Path, policy: str) -> list:
    seen: list = []

    def plan(_case_dir, _question, **kwargs):
        seen.append(kwargs.get("known_findings"))
        return [m2.WorkOrder(order_id="wo-1", role="evidence", task="t1", family="evtxecmd")]

    def work(order, **kwargs):
        m2.request_stop(kwargs["case_dir"], kwargs["run_id"])
        return m2.AgentResult(order_id=order.order_id, role=order.role, status="ok",
                              parsed={"notes": [], "candidate_findings": [], "coverage": {}})

    with patch.object(m2, "run_work_order", side_effect=work), \
         patch.object(m2, "plan_work_orders", side_effect=plan):
        m2.run_mode2(case, "what happened", model=object(), es_ok=True, context_policy=policy)
    return seen


def test_an_independent_mode2_run_is_not_handed_the_cases_drafts(tmp_path):
    assert _mode2_feedback(_case(tmp_path), "independent") == [{}]


def test_an_informed_mode2_run_gets_them_as_examiner_feedback(tmp_path):
    (feedback,) = _mode2_feedback(_case(tmp_path), "informed")
    assert [d["id"] for d in feedback["draft"]] == ["F-9"]


class _Recording:
    """Answers every call with no claims, and keeps every message list it was sent."""

    def __init__(self):
        self.calls: list[list[dict]] = []

    def invoke(self, messages):
        self.calls.append(messages)

        class _Reply:
            content = json.dumps({"claims": [], "open_questions": []})
        return _Reply()


def _supervisor_prompt(case: Path, policy: str, monkeypatch) -> str:
    from nexus.modes.multi_agent import run_mode3
    from tests._measured_index import measured_index

    # Mode 3 selects knowledge by the index's measured evidence groups and refuses to run without them (TA-5.1).
    measured_index(monkeypatch, {"evtx": 3})
    model = _Recording()
    run_mode3(case, "q", families=[("evtx", 3)], model=model, es_ok=True, context_policy=policy)
    prompts = [m for m in model.calls if "You supervise a concurrent" in m[0]["content"]]
    assert prompts, "the supervisor was never asked"
    return prompts[0][1]["content"]


def test_an_informed_mode3_run_plans_with_the_prior_analysis(tmp_path, monkeypatch):
    prompt = _supervisor_prompt(_case(tmp_path), "informed", monkeypatch)
    assert "Another run's DRAFT" in prompt and "not evidence" in prompt.lower()


def test_an_independent_mode3_run_does_not(tmp_path, monkeypatch):
    assert "Another run's DRAFT" not in _supervisor_prompt(_case(tmp_path), "independent", monkeypatch)


def test_mode2_workers_are_handed_the_cases_top_leads(tmp_path):
    """The worker summary read `top_leads` from the briefing, which has none: every Mode 2 worker
    got the alert surface and no TOP LEADS block (traced on CASE-C5B04D31, 2026-10-14)."""
    case = _case(tmp_path)
    lead = {"kind": "rule_engine", "subject": "Antivirus - Password Dumper Signature",
            "family": "hayabusa", "detail": "crit detection", "score": 1.0, "rows": [],
            "audit_ids": ["nexus-t-20261014-007"], "extra": {"level": "crit", "crit_high": True}}
    (case / "analysis" / "leads.jsonl").write_text(json.dumps(lead) + "\n", encoding="utf-8")

    def work(order, **kwargs):
        m2.request_stop(kwargs["case_dir"], kwargs["run_id"])
        return m2.AgentResult(order_id=order.order_id, role=order.role, status="ok",
                              parsed={"notes": [], "candidate_findings": [], "coverage": {}})

    with patch.object(m2, "run_work_order", side_effect=work), \
         patch.object(m2, "plan_work_orders", return_value=[
             m2.WorkOrder(order_id="wo-1", role="evidence", task="t1", family="hayabusa")]), \
         patch("nexus.langgraph.briefing.case_briefing", return_value={"alerts": []}):
        state = m2.run_mode2(case, "what happened", model=object(), es_ok=True)
    summary = state["digest_summary"]
    assert "TOP LEADS (1):" in summary
    assert "- [CRIT] Antivirus - Password Dumper Signature" in summary
    assert "[audit_id nexus-t-20261014-007]" in summary
