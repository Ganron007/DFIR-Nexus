"""D214: an EvtxECmd generic column is read through its map's template, not copied with its label.

The rows are CASE-C5B04D31's (SANS SRL lab data), verbatim from its index on 2026-10-15: a Defender 1116
whose map renders `Detection User: %User%` with no user, a Security 4799 rendering
`%domain%\\%user% (%sid%)`, a Task Scheduler 100 rendering `Context: %UserContext%`, and a 4624 whose
own SubjectUserName the rendered UserName overwrote.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ROWS = json.loads((Path(__file__).parent / "fixtures" / "evtxecmd_rendered_user_rows.json")
                  .read_text(encoding="utf-8"))


@pytest.mark.parametrize("row, user", [
    ("defender_1116_empty", ""),
    ("security_sid", "shieldbase\\RD01$"),
    ("task_context", "shieldbase\\tdungan"),
])
def test_the_user_is_what_the_map_placed(row, user):
    from nexus.langgraph.evtx_templates import map_value

    fields = ROWS[row]
    assert map_value(fields["Channel"], fields["EventId"], "UserName", fields["UserName"]) == user


def test_ecs_reads_the_user_not_the_label():
    from nexus.langgraph.ecs_normalize import normalize

    assert "name" not in (normalize("evtxecmd", ROWS["defender_1116_empty"]).get("user") or {})
    assert normalize("evtxecmd", ROWS["security_sid"])["user"]["name"] == "shieldbase\\RD01$"
    assert normalize("evtxecmd", ROWS["task_context"])["user"]["name"] == "shieldbase\\tdungan"


def test_the_events_own_user_is_not_overwritten_and_the_logging_host_stays():
    from nexus.langgraph.ecs_normalize import normalize

    ecs = normalize("evtxecmd", ROWS["security_4624"])
    # D471: the event's own subject through the pinned map's `%domain%\%user%`, read from its data; never the
    # rendered `UserName` with its `(sid)`.
    assert ecs["user"]["name"] == "shieldbase\\RD01$", "the map's user from the event, not the rendered UserName"
    assert ecs["user"]["target"]["name"] == "tdungan"
    assert ecs["host"]["name"] == "rd01.shieldbase.com", "Computer is a System field, not a rendered column"


def test_the_envelope_user_reads_the_same_value():
    from nexus.langgraph.case_index import _host_user_event
    from nexus.langgraph.ecs_normalize import normalize

    assert _host_user_event(ROWS["security_sid"])[1] == "shieldbase\\RD01$"
    # D471: on the indexing path the row's user is the one its ECS layer types, the event's own (the map's
    # `Context: %UserContext%`). The System UserID, `S-1-5-18`, the account Task Scheduler logged under, came first
    # only because its column does.
    for name, user in (("security_sid", "shieldbase\\RD01$"), ("task_context", "shieldbase\\tdungan")):
        ecs = normalize("evtxecmd", ROWS[name])
        assert ecs["user"]["name"] == user
        assert _host_user_event(ROWS[name], ecs=ecs)[1] == user
    # A row whose ECS layer types no user keeps the first generic column, UserId, as before.
    assert _host_user_event(ROWS["task_context"])[1] == "S-1-5-18"


def test_a_value_no_template_fits_is_kept_and_none_is_a_placeholder():
    from nexus.langgraph.event_categories import present
    from nexus.langgraph.evtx_templates import map_value

    assert map_value("Security", "9999", "UserName", "Context: x") == "Context: x"
    assert map_value("Microsoft-Windows-TaskScheduler/Operational", "100", "UserName", "Context: (NONE)") == "(NONE)"
    assert present("(NONE)") == ""
