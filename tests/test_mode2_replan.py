"""WO-R1F item 7c — Mode 2 re-plans from what it finds, and sees the digest.

The code review found two gaps: a worker's `next_questions` and new entities
never became new orders (follow-ups came only from refuted/inferred verdicts),
and the briefing was built and discarded so the digest summary never reached a
worker while it did reach Mode 1.
"""

from __future__ import annotations

from pathlib import Path


def test_digest_summary_carries_the_alert_surface_and_the_top_leads():
    from nexus.modes.multi_role import _digest_summary

    brief = {
        "alerts": [
            {"level": "crit", "family": "hayabusa",
             "title": "Defender Alert (Severe)", "host": "WS01", "time": "t"},
            {"level": "high", "family": "chainsaw",
             "title": "Hacktool Signature", "host": "WS01", "time": "t"},
        ],
        "top_leads": [
            {"subject": "Antivirus - Password Dumper Signature",
             "detail": "crit detection", "extra": {"level": "crit"}},
        ],
    }
    text = _digest_summary(brief)
    assert "ALERT SURFACE" in text
    assert "TOP LEADS" in text
    assert "Defender Alert (Severe)" in text
    assert "Antivirus - Password Dumper Signature" in text


def test_digest_summary_is_capped_and_never_raises():
    from nexus.modes.multi_role import _digest_summary

    assert _digest_summary({}) == ""
    assert _digest_summary("not a dict") == ""  # type: ignore[arg-type]
    huge = {
        "alerts": [
            {"level": "crit", "family": "f", "title": "x" * 400, "host": "h", "time": "t"}
            for _ in range(100)
        ]
    }
    assert len(_digest_summary(huge)) <= 2400


def test_replan_inputs_surface_open_questions_and_pivots():
    from nexus.modes.multi_role import _replan_inputs

    state = {
        "results": [
            {"parsed": {"next_questions": ["Who launched cmd.exe on ws01?"],
                        "entities": ["cmd.exe", "172.16.6.12"]}},
        ]
    }
    questions, pivots = _replan_inputs(state)
    assert questions == ["Who launched cmd.exe on ws01?"]
    assert "cmd.exe" in pivots
    assert "172.16.6.12" in pivots


def test_replan_inputs_drop_a_question_a_later_worker_answered():
    """A question already answered must not become a new order forever."""
    from nexus.modes.multi_role import _replan_inputs

    state = {
        "results": [
            {"parsed": {"next_questions": ["Who launched cmd.exe on ws01?"]}},
            {"parsed": {"notes": [{"statement":
                                   "Who launched cmd.exe on ws01? confirmed via evtxecmd"}]}},
        ]
    }
    questions, _pivots = _replan_inputs(state)
    assert questions == []


def test_replan_inputs_are_bounded():
    from nexus.modes.multi_role import _replan_inputs

    state = {
        "results": [
            {"parsed": {"next_questions": [f"q{i}" for i in range(50)],
                        "entities": [f"e{i}" for i in range(50)]}},
        ]
    }
    questions, pivots = _replan_inputs(state)
    assert len(questions) <= 8
    assert len(pivots) <= 8


def test_replan_inputs_pick_up_candidate_hosts():
    from nexus.modes.multi_role import _replan_inputs

    state = {
        "results": [
            {"parsed": {"candidate_findings": [
                {"title": "t", "host": "WS01", "affected_account": "analyst_t1"},
            ]}},
        ]
    }
    _questions, pivots = _replan_inputs(state)
    assert "WS01" in pivots
    assert "analyst_t1" in pivots


def test_replan_inputs_tolerate_an_empty_state():
    from nexus.modes.multi_role import _replan_inputs

    assert _replan_inputs({}) == ([], [])
    assert _replan_inputs({"results": [{"parsed": None}]}) == ([], [])


def test_the_worker_prompt_carries_the_digest_summary(tmp_path: Path):
    """The digest must reach the prompt, not just an event."""
    import inspect

    from nexus.modes import multi_role

    source = inspect.getsource(multi_role.run_work_order)
    assert "work_context_digest" in source
    # And it is placed in the question the worker is asked.
    assert "if work_context_digest else" in source
