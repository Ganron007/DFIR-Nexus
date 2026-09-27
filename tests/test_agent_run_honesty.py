"""A run whose model never answered must not report convergence.

Found by the design monitor on the real-corpus pass: **every** Mode 2 and Mode 3
run across all six groups reported `completed` with zero candidates. The run
records said `status=completed, error=None, gaps=0`, and `stop_reason="converged"`.

What had actually happened: the model key was invalid, so all four work orders
came back

    **Partial result — model call failed.**

with `status=unparsed`. The synthesis node then set `completed` unconditionally
and inferred `converged` from the empty candidate list. An examiner reading that
record would conclude the investigation ran and found nothing.

This is worse than the scan defect it sits beside: the scan at least reported
`nothing to promote`, which invites a second look. A dead model reported
convergence, which invites a signature.
"""
from __future__ import annotations

import ast
import pathlib

ROLE = pathlib.Path("src/nexus/modes/multi_role.py")
AGENT = pathlib.Path("src/nexus/modes/multi_agent.py")


def _fn(path: pathlib.Path, name: str) -> str:
    src = path.read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    return ""


# ------------------------------------------------------------------ mode 2

def test_mode2_detects_a_dead_model():
    src = ROLE.read_text(encoding="utf-8")
    assert "model_dead" in src, "no dead-model detection in the multi-role runtime"
    assert "model unavailable" in src, "the failure must be named"


def test_mode2_does_not_infer_convergence_from_an_empty_candidate_list():
    """`converged` because `candidates == []` is the bug, stated directly."""
    src = ROLE.read_text(encoding="utf-8")
    assert "unparsed" in src, "unparsed work orders are what identify the failure"
    # The old unconditional assignment must be gone.
    assert 'state["status"] = "completed"\n        state["stop_reason"] = (' not in src


def test_mode2_dead_model_fails_the_run():
    src = ROLE.read_text(encoding="utf-8")
    assert '"failed" if model_dead else "completed"' in src


def test_mode2_records_the_failure_as_a_gap_and_an_error():
    src = ROLE.read_text(encoding="utf-8")
    assert "the run did not investigate anything" in src
    assert 'state["error"] = state["stop_reason"]' in src, (
        "a failed run must carry an error, not just a status"
    )


def test_mode2_still_converges_normally_when_work_was_done():
    """The genuine paths must survive - this is not a blanket failure."""
    src = ROLE.read_text(encoding="utf-8")
    assert "converged_no_new_evidence" in src
    assert '"converged" if not state["candidates"] else "completed"' in src


def test_mode2_counts_what_it_lost():
    """The reason must say how many orders failed, not just that something did."""
    src = ROLE.read_text(encoding="utf-8")
    assert "of {len(orders)} work " in src or "of {len(orders)}" in src


# ------------------------------------------------------------------ mode 3

def test_mode3_keys_on_the_model_finish_reason_not_on_an_empty_board():
    """A seat that ran and found nothing is a real result; a seat that never got
    an answer is not. Both have an empty claim list, so the claim count cannot
    tell them apart - only the model's own finish reason can.
    """
    src = AGENT.read_text(encoding="utf-8")
    assert "_dead_model" in src
    assert 'finish_reason' in src
    assert '== "model_error"' in src
    assert "_claims == 0" not in src, (
        "an empty claim list is not evidence of a model failure"
    )


def test_mode3_records_the_finish_reason_on_every_seat():
    src = AGENT.read_text(encoding="utf-8")
    assert 'entry["finish_reason"]' in src


def test_mode3_dead_model_fails_rather_than_settling():
    src = AGENT.read_text(encoding="utf-8")
    assert '"model unavailable: ' in src or "model unavailable: " in src
    i = src.find("_dead_model")
    assert i > 0
    seg = src[i:i + 600]
    assert '"failed"' in seg, "a seat board with no claims must not settle"


def test_mode3_capped_and_stopped_paths_are_untouched():
    src = AGENT.read_text(encoding="utf-8")
    assert 'stop_reason = "run_cap"' in src
    assert 'stop_reason = "examiner_stop"' in src
    assert 'stop_reason = "paused"' in src


def test_the_normal_settle_path_survives():
    src = AGENT.read_text(encoding="utf-8")
    assert 'elif status == "settled":' in src
