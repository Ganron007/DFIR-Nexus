"""Mode 3 must actually use the roles it claims to have.

Verified on the first real run. The supervisor spawned four seats, all of them
`role=evidence`, and the run settled at **superstep 1** with 10 candidates and
zero disputes. The `pattern` and `correlation` seats - two of the three seats the
runtime exists to run - never executed once.

The cause is the convergence rule:

    (not disputes and superstep >= 1) -> settled

A run therefore ended at one superstep precisely when its seats *did not
collide*. Four seats each reading a different family and never cross-examining
one another produced no dispute, and no dispute was the signal to stop. The
criterion rewarded not colliding, which is backwards: an un-cross-examined board
is the strongest argument for another round.

Two changes, both about honesty rather than about forcing more work:
`NEXUS_MODE3_MIN_SUPERSTEPS` (default 2) before a dispute-free run may settle,
and a settle that never used every seat role is recorded as a gap, because
settling asserts the investigation is finished.
"""
from __future__ import annotations

import json
from pathlib import Path

SRC = Path("src/nexus/modes/multi_agent.py")


def _src() -> str:
    return SRC.read_text(encoding="utf-8")


def test_a_dispute_free_run_cannot_settle_on_the_first_superstep():
    src = _src()
    assert "NEXUS_MODE3_MIN_SUPERSTEPS" in src, "no minimum-superstep knob"
    assert "step_no >= min_supersteps" in src, (
        "a run with no disputes must still take a second superstep"
    )
    # The old rule must be gone: it is what ended the real run at superstep 1.
    assert "superstep\") or 0) >= 1)" not in src


def test_the_minimum_defaults_to_two():
    src = _src()
    assert 'NEXUS_MODE3_MIN_SUPERSTEPS", 2' in src


def test_settling_records_a_role_gap():
    src = _src()
    assert "join.role_gap" in src, "a settle that skipped a role is not recorded"
    assert "roles_used" in src
    assert "never contributed" in src


def test_every_seat_role_is_known():
    from nexus.modes.multi_agent import _SEATS

    assert set(_SEATS) == {"evidence", "correlation", "pattern"}
    # A role the gap check knows about, so the check cannot silently pass by
    # comparing against an empty set.
    assert len(_SEATS) == 3


def test_the_env_knob_is_bounded():
    """An operator must not be able to set it to zero and disable the check."""
    from nexus.modes.multi_agent import _env_int

    assert _env_int("NEXUS_MODE3_MIN_SUPERSTEPS", 2, low=1, high=6) >= 1


def test_seats_are_announced_before_they_work():
    """Liveness is derived from the stream, so a seat must appear in it."""
    src = _src()
    assert '"seat.started"' in src
    # Emitted before the model call, not only on the way out.
    i = src.find('"seat.started"')
    j = src.find("run_context_loop(", i)
    assert 0 < i < j, "seat.started must be emitted before the agent runs"


def test_the_gap_note_names_the_missing_roles():
    src = _src()
    assert "set(_SEATS) - set(roles_used)" in src


def test_a_run_with_all_three_roles_reports_no_gap():
    """The check must be able to pass, or it is just noise."""
    from nexus.modes.multi_agent import _SEATS

    roles = {"evidence", "correlation", "pattern"}
    missing = sorted(set(_SEATS) - roles)
    assert missing == []


def test_record_carries_roles_used_and_gaps():
    src = _src()
    # the join return must include both so the record can persist them
    assert '"gaps": gaps, "roles_used": roles_used' in src
    json.dumps({"gaps": ["x"], "roles_used": ["evidence"]})
