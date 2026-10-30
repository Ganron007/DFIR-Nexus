"""The case facts reach every role once, and task data travels through one context payload."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from nexus.modes import multi_role as mode2


def _observe_contexts(tmp_path, monkeypatch):
    fixtures = Path(__file__).parent / "fixtures"
    capture = json.loads((fixtures / "mode2_context_r1.json").read_text(encoding="utf-8"))
    lead = json.loads((fixtures / "mode3_work_r1.json").read_text(encoding="utf-8"))[0]["leads"][0]
    # Opaque captured metadata exercises routing/serialization, not a forensic truth assertion.
    mandatory = json.dumps({k: lead[k] for k in ("kind", "subject", "family")}, sort_keys=True)
    case = tmp_path / "CASE-CONTEXT"
    (case / "analysis").mkdir(parents=True)
    monkeypatch.setattr("nexus.langgraph.case_digest.build_case_digest", lambda *a, **k: {})
    monkeypatch.setattr(mode2, "_digest_summary", lambda *a, **k: mandatory)
    monkeypatch.setattr(mode2, "_investigative_extras", lambda *a, **k: "")
    monkeypatch.setattr(mode2, "plan_work_orders", lambda *a, **k: [mode2.WorkOrder(
        order_id="context-order", role="evidence", task="Inspect the assigned evidence.")])
    observed = {}

    def native_loop_boundary(**kwargs):
        role = kwargs["task"].removeprefix("mode2-")
        question = kwargs["question"]
        context_text = question.split("Run context: ", 1)[1]
        payload, _ = json.JSONDecoder().raw_decode(context_text)
        observed[role] = {"question": question, "context": payload}
        if role == "evidence":
            parsed = {"candidate_findings": [copy.deepcopy(capture["candidate"])]}
        elif role == "verifier":
            parsed = {"verdicts": []}
        else:
            parsed = {"findings": [], "narrative": ""}
        return {"reply": json.dumps(parsed), "partial": False, "tool_calls": [], "hits": []}

    monkeypatch.setattr(mode2, "run_context_loop", native_loop_boundary)
    mode2.run_mode2(case, "Compromise suspected.", model=object(), es_ok=True)
    assert set(observed) == {"evidence", "verifier", "synthesis"}
    return observed, capture, mandatory


@pytest.mark.parametrize("role", ["evidence", "verifier", "synthesis"])
def test_real_graph_and_prompt_compositor_share_facts_with_every_role(tmp_path, monkeypatch, role):
    observed, _, mandatory = _observe_contexts(tmp_path, monkeypatch)
    output = observed[role]
    assert mandatory in output["question"], f"case facts missing from {role}"
    assert "digest_summary" not in output["context"], f"case facts duplicated in {role}'s JSON payload"


def test_verification_and_synthesis_data_have_one_context_payload(tmp_path, monkeypatch):
    observed, capture, _ = _observe_contexts(tmp_path, monkeypatch)
    title = capture["candidate"]["title"]
    for role in ("verifier", "synthesis"):
        assert observed[role]["context"]["candidates"][0]["title"] == title
        # The title may be Unicode-escaped in JSON. Test the actual task block, not its spelling.
        task_block = observed[role]["question"].split("Assigned family:", 1)[0]
        assert json.dumps(title) not in task_block and title not in task_block, "candidate data duplicated in task"
