"""D467: every mode is given the same case facts Mode 1's digest holds.

T22-R1z3d Mode 3 (M3-20261028T170325-969bbd) read two exited backgroundTaskHost.exe rows with ``pslist=False`` as
DKOM, while the lane ledger says the process-list walk returned nothing for the whole image ("a coverage gap, not
evidence of absence"), and called the F-Response acquisition driver a CRITICAL rootkit without ever seeing the alert
surface whose YARA record names it. Mode 1 had both; Mode 2 had the alerts only, capped; Mode 3 had neither.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph.case_digest import case_facts_markdown, render_digest_markdown

T22 = json.loads((Path(__file__).parent / "fixtures" / "t22_case_digest.json").read_text(encoding="utf-8"))["digest"]
CAVEAT = "process-list walk returned nothing while psscan saw 134 process(es)"


def test_t22_case_facts_carry_the_lane_caveat_the_scope_and_every_alert():
    facts = case_facts_markdown(T22)
    assert CAVEAT in facts and "a coverage gap, not evidence of absence" in facts
    assert "**NOT in evidence**" in facts
    for alert in T22["alerts"]:
        assert f"[audit_id {alert['key']}]" in facts
    assert "FILE:[\\Windows\\Mnemosyne.sys]" in facts
    assert "## Top leads" not in facts  # the leads reach each mode by its own route


def test_the_case_facts_are_the_digests_own_sections():
    """One definition: every line of the case facts' sections is a line of Mode 1's digest."""
    digest_lines = set(render_digest_markdown(T22).splitlines())
    sections = [line for line in case_facts_markdown(T22).splitlines()[1:-1] if line.strip()]
    assert sections and all(line in digest_lines for line in sections)


def test_mode2_summary_is_the_case_facts_whole_and_the_leads_capped():
    from nexus.modes.multi_role import _digest_summary

    text = _digest_summary(T22)
    assert text.startswith(case_facts_markdown(T22))
    assert "TOP LEADS (25):" in text
    many = {**T22, "alerts": [{**T22["alerts"][0], "title": "x" * 400, "key": f"a-{n}"} for n in range(100)]}
    summary = _digest_summary(many)
    assert all(f"[audit_id a-{n}]" in summary for n in range(100))  # alerts are never cut
    leads_block = summary.split("TOP LEADS", 1)[1]
    assert len(leads_block) <= 2400 + 80
    assert _digest_summary({}) == "" and _digest_summary("not a dict") == ""  # type: ignore[arg-type]


def test_mode2_workers_are_given_the_case_facts(tmp_path, monkeypatch):
    from unittest.mock import patch

    from nexus.langgraph import briefing, case_digest
    from nexus.modes import multi_role as m2

    case = tmp_path / "CASE-D467"
    (case / "analysis").mkdir(parents=True)
    (case / "audit").mkdir()
    (case / "CASE.yaml").write_text("name: d467\nstatus: active\n", encoding="utf-8")
    monkeypatch.setattr(briefing, "case_briefing", lambda case_dir: {"alerts": T22["alerts"]})
    monkeypatch.setattr(case_digest, "build_case_digest", lambda case_dir, brief=None: T22)
    seen: list[str] = []

    def fake_work(order, *, case_dir, model, run_id, sink, agent_id="", context=None):
        seen.append(str((context or {}).get("digest_summary") or ""))
        parsed = {"notes": [], "candidate_findings": [], "coverage": {}}
        return m2.AgentResult(order_id=order.order_id, role=order.role, status="ok",
                              reply=json.dumps(parsed), parsed=parsed, audit_id="ctx-1")

    with patch.object(m2, "run_work_order", side_effect=fake_work), \
         patch.object(m2, "plan_work_orders", return_value=[m2.WorkOrder(
             order_id="wo-1", role="evidence", task="t", family="memprocfs")]):
        m2.run_mode2(case, "Compromise suspected.", model=object(), es_ok=True)
    assert seen and all(CAVEAT in summary for summary in seen)


class _Recording:
    model_name = "recording"
    provider = "test"

    def __init__(self, reply: dict) -> None:
        self.reply = reply
        self.sent: list[str] = []

    def invoke(self, messages):
        self.sent.append("\n".join(str(m.get("content") or "") for m in messages))

        class _R:
            content = json.dumps(self.reply)

        return _R()


class _Sink:
    def emit(self, event):
        return None


def _mode3_case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-D467M3"
    ext = case / "runs" / "RUN-1" / "extractions"
    ext.mkdir(parents=True)
    (ext / "a.csv").write_text("x\n1\n", encoding="utf-8")
    (ext / "_tool_lane_ledger.json").write_text(json.dumps([{"tool": "vol", "status": "OK"}]), encoding="utf-8")
    (case / "CASE.yaml").write_text("name: d467m3\nstatus: active\n", encoding="utf-8")
    (case / "analysis").mkdir()
    return case


def test_mode3_seats_and_supervisor_are_given_the_case_facts(tmp_path, monkeypatch):
    from nexus.modes.multi_agent import _seat_with_model, _supervisor_with_model

    monkeypatch.setenv("NEXUS_MODE3_ROUNDS", "1")
    monkeypatch.setenv("NEXUS_MODE3_CALLS", "2")
    monkeypatch.setenv("NEXUS_MODE3_SECONDS", "60")
    case = _mode3_case(tmp_path)
    facts = case_facts_markdown(T22)
    for spawn in ({"role": "evidence", "family": "vol", "why": "domain seat: memory"},
                  {"role": "correlation", "family": "", "why": "cross-family"},
                  {"role": "verifier", "family": "", "why": "verify the board"}):
        model = _Recording({"claims": [], "open_questions": [], "verdicts": []})
        _seat_with_model({**spawn, "question": "Compromise suspected."}, case_dir=case, model=model,
                         run_id="M3-D467", sink=_Sink(), board_digest="(empty)", superstep=1, case_facts=facts)
        assert model.sent and facts in model.sent[0], spawn["role"]
    supervisor = _Recording({"spawns": []})
    _supervisor_with_model(supervisor, case_dir=case, question="Compromise suspected.",
                           families=[("vol", 432)], board_digest="", steering="", max_agents=2, case_facts=facts)
    assert facts in supervisor.sent[0]


def test_a_mode3_run_builds_the_case_facts_once_and_every_seat_gets_them(tmp_path, monkeypatch):
    from nexus.langgraph import case_digest
    from nexus.modes import multi_agent

    monkeypatch.setenv("NEXUS_MODE3_ROUNDS", "1")
    monkeypatch.setenv("NEXUS_MODE3_CALLS", "2")
    monkeypatch.setenv("NEXUS_MODE3_SECONDS", "60")
    monkeypatch.setenv("NEXUS_MODE3_MAX_SUPERSTEPS", "2")
    case = _mode3_case(tmp_path)
    built: list[int] = []
    monkeypatch.setattr(case_digest, "build_case_digest", lambda case_dir, brief=None: built.append(1) or T22)
    seen: list[str] = []
    real = multi_agent._seat_with_model

    def spy(spawn, **kwargs):
        seen.append(kwargs.get("case_facts") or "")
        return real(spawn, **kwargs)

    monkeypatch.setattr(multi_agent, "_seat_with_model", spy)
    # Mode 3 selects knowledge by the index's measured evidence groups and refuses to run without them (TA-5.1).
    from tests._measured_index import measured_index

    measured_index(monkeypatch, {"vol": 432})
    multi_agent.run_mode3(case, "Compromise suspected.", model=_Recording({"claims": [], "open_questions": []}),
                          families=[("vol", 432)], es_ok=True)
    assert built == [1]
    assert seen and all(facts == case_facts_markdown(T22) for facts in seen)
