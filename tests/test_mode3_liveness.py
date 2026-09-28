"""Mode 3 liveness and the agent-to-agent interaction log.

The Investigation Board could not answer the two questions an examiner watching a
live run actually asks: *how many agents are working right now*, and *how are
they interacting with each other*. Both because of the same gap - the board
holds only seats that have **finished**.

Verified on the first real run: the board showed one lane while three seats were
in flight, and `supervisor.spawn` recorded only `{"agents": 3}` - a count with no
identity - so the event stream could not answer it either. Liveness is now
derived from the stream: a `seat.started` with no matching `board.entry` is in
flight.

Derived rather than stored deliberately. The stream is already the append-only
record of what the agents did, so a second mutable liveness counter could
disagree with it and nothing would reveal which one was lying.
"""
from __future__ import annotations

import json

from nexus.modes.multi_agent import (
    active_seats,
    interaction_timeline,
)


def _stream(*kinds):
    base = [{"ts": f"2026-09-27T18:00:0{i}Z", "event_id": f"e{i}"} for i in range(9)]
    for i, ev in enumerate(base):
        ev["event_type"] = kinds[i % len(kinds)]
    return base


def test_a_seat_that_started_and_has_not_reported_is_active(tmp_path):
    events = [
        {"ts": "t0", "event_type": "supervisor.spawn", "actor": "supervisor",
         "agent_id": "", "data": {"agents": 2}},
        {"ts": "t1", "event_type": "seat.started", "actor": "agent",
         "agent_id": "evidence:hayabusa:1",
         "data": {"role": "evidence", "family": "hayabusa", "superstep": 1,
                  "why": "highest-value family"}},
    ]
    active = active_seats(tmp_path, "M3-x", events=events)
    assert len(active) == 1
    assert active[0]["agent_id"] == "evidence:hayabusa:1"
    assert active[0]["role"] == "evidence"
    assert active[0]["family"] == "hayabusa"
    assert active[0]["superstep"] == 1
    assert "highest-value family" in active[0]["why"]


def test_a_seat_that_reported_is_no_longer_active(tmp_path):
    events = [
        {"ts": "t1", "event_type": "seat.started", "actor": "agent",
         "agent_id": "pattern:prefetch:1", "data": {"role": "pattern"}},
        {"ts": "t2", "event_type": "board.entry", "actor": "agent",
         "agent_id": "pattern:prefetch:1", "data": {"claims": 3}},
    ]
    assert active_seats(tmp_path, "M3-x", events=events) == []


def test_three_in_flight_reports_three(tmp_path):
    """The real failure: three seats working, the board showed one lane."""
    events = [{"ts": "t0", "event_type": "supervisor.spawn", "agent_id": "",
               "data": {"agents": 3}}]
    for role, fam in (("evidence", "hayabusa"), ("pattern", "prefetch"),
                      ("correlation", "evtxecmd")):
        events.append({"ts": "t1", "event_type": "seat.started", "actor": "agent",
                       "agent_id": f"{role}:{fam}:1",
                       "data": {"role": role, "family": fam}})
    events.append({"ts": "t2", "event_type": "board.entry", "actor": "agent",
                   "agent_id": "evidence:hayabusa:1", "data": {}})
    active = active_seats(tmp_path, "M3-x", events=events)
    assert len(active) == 2
    assert {a["agent_id"] for a in active} == {"pattern:prefetch:1", "correlation:evtxecmd:1"}


def test_a_re_dispatched_seat_shows_its_current_superstep(tmp_path):
    events = [
        {"ts": "t1", "event_type": "seat.started", "actor": "agent",
         "agent_id": "pattern:prefetch:1", "data": {"role": "pattern", "superstep": 1}},
        {"ts": "t2", "event_type": "seat.started", "actor": "agent",
         "agent_id": "pattern:prefetch:1", "data": {"role": "pattern", "superstep": 2}},
    ]
    active = active_seats(tmp_path, "M3-x", events=events)
    assert len(active) == 1, "one seat re-dispatched is still one seat"
    assert active[0]["superstep"] == 2


def test_a_spawn_count_alone_is_not_an_agent(tmp_path):
    """`{"agents": 3}` names nobody, so it must not register as a live seat."""
    events = [{"ts": "t0", "event_type": "supervisor.spawn", "actor": "supervisor",
               "agent_id": "", "data": {"agents": 3}}]
    assert active_seats(tmp_path, "M3-x", events=events) == []


def test_an_empty_or_missing_stream_is_zero_not_an_error(tmp_path):
    assert active_seats(tmp_path, "M3-missing", events=[]) == []
    assert active_seats(tmp_path, "M3-missing") == []


def test_malformed_rows_are_skipped(tmp_path):
    events = [None, "junk", 7, {"event_type": "seat.started", "agent_id": "a:1",
                                 "data": {"role": "a"}}]
    assert len(active_seats(tmp_path, "M3-x", events=events)) == 1


def test_timeline_is_ordered_and_carries_the_interaction_fields(tmp_path):
    events = [
        {"ts": "t1", "event_type": "supervisor.spawn", "actor": "supervisor",
         "agent_id": "", "detail": "2 seats", "data": {"agents": 2}},
        {"ts": "t2", "event_type": "seat.started", "actor": "agent",
         "agent_id": "evidence:hayabusa:1", "detail": "evidence hayabusa",
         "tool": "", "audit_id": ""},
        {"ts": "t3", "event_type": "board.entry", "actor": "agent",
         "agent_id": "evidence:hayabusa:1", "data": {"claims": 4}},
        {"ts": "t4", "event_type": "dispute.opened", "actor": "join",
         "agent_id": "", "detail": "lsass.exe", "data": {}},
    ]
    rows = interaction_timeline(events)
    assert [r["event"] for r in rows] == [
        "supervisor.spawn", "seat.started", "board.entry", "dispute.opened"]
    entry = rows[1]
    assert entry["agent_id"] == "evidence:hayabusa:1"
    assert entry["actor"] == "agent"
    assert entry["ts"] == "t2"
    json.dumps(rows)  # must be serialisable for the portal


def test_timeline_drops_rows_with_no_event_type(tmp_path):
    rows = interaction_timeline([{"ts": "t"}, {"ts": "t", "event_type": "x"}])
    assert len(rows) == 1


def test_timeline_is_bounded(tmp_path):
    events = [{"ts": f"t{i}", "event_type": "board.entry", "actor": "agent",
               "agent_id": f"a{i}", "data": {}} for i in range(400)]
    assert len(interaction_timeline(events, limit=50)) == 50


def test_timeline_data_defaults_to_a_dict(tmp_path):
    """A row whose data is a string must not crash the renderer."""
    rows = interaction_timeline([{"ts": "t", "event_type": "seat.started", "data": "oops"}])
    assert rows[0]["data"] == {}


# --------------------------------------------------------------------------
# the portal surfaces
# --------------------------------------------------------------------------

def test_status_and_board_expose_liveness_and_timeline(tmp_path):
    """Both endpoints must carry them - a value nobody can fetch is not a feature."""
    from pathlib import Path as _P

    src = _P("src/nexus/dashboard/app.py").read_text(encoding="utf-8")
    status = src[src.find("async def api_mode3_run_status"):
                 src.find("async def api_mode3_run_board")]
    board = src[src.find("async def api_mode3_run_board"):
                src.find("async def api_mode3_run_stop")]
    for key in ("agents_running", "agents_active", "roles", "skills_used"):
        assert f'"{key}"' in status, key
    for key in ("active", "timeline", "skills_used"):
        assert f'"{key}"' in board, key
    assert "interaction_timeline" in board
    assert "active_seats" in status
