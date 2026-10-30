"""D512: the final Mode 3 composer receives the same mandatory case facts as its other seats."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from nexus.langgraph.case_digest import case_facts_markdown
from nexus.modes import multi_agent as mode3
from nexus.modes import multi_role as mode2

FIXTURES = Path(__file__).parent / "fixtures"
DIGEST = json.loads((FIXTURES / "t22_case_digest.json").read_text(encoding="utf-8"))["digest"]
CAPTURE = json.loads((FIXTURES / "mode3_composer_context_r1.json").read_text(encoding="utf-8"))


class Sink:
    def emit(self, event):
        pass


def _observe_loop(monkeypatch):
    observed = []

    def loop(**kwargs):
        observed.append(kwargs["question"])
        return {"reply": '{"narrative":"","findings":[]}', "partial": False, "tool_calls": [], "hits": []}

    monkeypatch.setattr(mode2, "run_context_loop", loop)
    return observed


def _assert_facts_once(observed):
    assert len(observed) == 1
    facts = case_facts_markdown(DIGEST)
    assert observed[0].count(facts) == 1
    for alert in DIGEST["alerts"]:
        assert f"[audit_id {alert['key']}]" in observed[0]


def test_composer_real_work_order_and_prompt_receive_shared_facts_once(tmp_path, monkeypatch):
    case = tmp_path / "CASE-COMPOSER-CONTEXT"
    (case / "analysis").mkdir(parents=True)
    observed = _observe_loop(monkeypatch)
    mode3.compose_case(case, "M3-composer-context", "Compromise suspected.", [CAPTURE["candidate"]], [],
                       model=object(), sink=Sink(), case_facts=case_facts_markdown(DIGEST))
    _assert_facts_once(observed)


def test_real_mode3_graph_forwards_its_once_built_facts_to_the_final_composer(tmp_path, monkeypatch):
    case = tmp_path / "CASE-COMPOSER-GRAPH"
    (case / "analysis").mkdir(parents=True)
    built = []
    monkeypatch.setattr("nexus.langgraph.case_digest.build_case_digest", lambda *a, **k: built.append(1) or DIGEST)
    # Only the settled-output boundary is substituted with opaque native identity
    # metadata. No event rows or model judgments are authored or accepted here.
    monkeypatch.setattr(mode3, "settled_candidates", lambda *a, **k: ([CAPTURE["candidate"]], []))
    observed = _observe_loop(monkeypatch)

    class Quiet:
        def invoke(self, messages):
            return SimpleNamespace(content='{"spawns":[]}')

    mode3.run_mode3(case, "Compromise suspected.", model=Quiet(), families=[("vol", 432)], es_ok=True,
                    seat_fn=lambda spawn, board, step: {"claims": []})
    assert built == [1]
    _assert_facts_once(observed)
