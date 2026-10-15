"""D212: a machine renamed over its life is one host, and its own event logs prove it.

The edges below are CASE-C5B04D31's (2026-10-15): the first and last record under each name in its
Security and System channels. Every mode read `tpl-packer`, `rd01` and `rd01.shieldbase.com` as
three hosts; the record numbers run on across each rename. `OFFDEVS-TUHMGJE`'s records restart at 1
in the middle of `tpl-packer`'s, a separate log, and stay unlinked.
"""
from __future__ import annotations

import json


def _edge(channel, name, first_ts, first_record, last_ts, last_record):
    return {"channel": channel, "name": name, "first_ts": first_ts, "first_record": str(first_record),
            "last_ts": last_ts, "last_record": str(last_record)}


EDGES = [
    _edge("Security", "tpl-packer", "2022-08-31T17:36:13Z", 318, "2022-09-30T23:37:06Z", 12965),
    _edge("Security", "OFFDEVS-TUHMGJE", "2022-08-31T19:34:46Z", 1, "2022-08-31T19:35:21Z", 137),
    _edge("Security", "rd01", "2022-09-30T23:37:17Z", 12968, "2022-09-30T23:45:35Z", 13224),
    _edge("Security", "rd01.shieldbase.com", "2022-09-30T23:45:47Z", 13225, "2023-01-25T17:19:22Z", 167942),
    _edge("System", "tpl-packer", "2022-08-31T17:36:13Z", 161, "2022-09-30T23:37:06Z", 946),
    _edge("System", "OFFDEVS-TUHMGJE", "2022-08-31T19:34:40Z", 3, "2022-08-31T19:35:21Z", 115),
    _edge("System", "rd01", "2022-09-30T23:37:11Z", 958, "2022-09-30T23:45:35Z", 1022),
    _edge("System", "rd01.shieldbase.com", "2022-09-30T23:45:40Z", 1033, "2023-01-25T17:39:21Z", 10464),
]


def test_the_record_sequence_names_one_machine():
    from nexus.analysis.host_identity import link_names

    machines = link_names(EDGES)["machines"]
    assert [m["names"] for m in machines] == [["tpl-packer", "rd01", "rd01.shieldbase.com"]]
    renames = machines[0]["renames"]
    assert [(r["from"], r["to"]) for r in renames] == [("tpl-packer", "rd01"), ("rd01", "rd01.shieldbase.com")]
    assert renames[0]["proof"][0] == {"channel": "Security", "last_record": 12965, "first_record": 12968}
    assert machines[0]["eras"][0] == {"name": "tpl-packer", "first": "2022-08-31T17:36:13Z",
                                      "last": "2022-09-30T23:37:06Z"}


def test_names_whose_records_do_not_continue_stay_apart():
    from nexus.analysis.host_identity import link_names

    other = [
        _edge("Security", "ws01", "2023-01-01T00:00:00Z", 1, "2023-01-02T00:00:00Z", 5000),
        # Starts right after ws01 in time, but its own log: the numbers do not continue.
        _edge("Security", "ws02", "2023-01-02T00:00:05Z", 90000, "2023-01-03T00:00:00Z", 91000),
        # Continues the numbers, but in the channel that holds other machines' records.
        _edge("ForwardedEvents", "ws01", "2023-01-01T00:00:00Z", 1, "2023-01-02T00:00:00Z", 10),
        _edge("ForwardedEvents", "dc01", "2023-01-02T00:00:01Z", 11, "2023-01-03T00:00:00Z", 20),
        # Continues the numbers a month later: no rename leaves a log silent that long.
        _edge("System", "ws01", "2023-01-01T00:00:00Z", 1, "2023-01-02T00:00:00Z", 100),
        _edge("System", "ws03", "2023-02-02T00:00:00Z", 101, "2023-02-03T00:00:00Z", 200),
    ]
    assert link_names(other)["machines"] == []


def test_every_investigative_prompt_and_the_digest_carry_it(tmp_path):
    from nexus.analysis.host_identity import link_names
    from nexus.langgraph.case_digest import render_digest_markdown
    from nexus.modes.multi_role import _investigative_extras

    case = tmp_path / "CASE-HOSTID"
    (case / "analysis").mkdir(parents=True)
    (case / "analysis" / "index_state.json").write_text(json.dumps({"indexed_at": "2026-10-15T06:07:24Z"}),
                                                        encoding="utf-8")
    identity = {**link_names(EDGES), "index_stamp": "2026-10-15T06:07:24Z"}
    (case / "analysis" / "host_identity.json").write_text(json.dumps(identity), encoding="utf-8")

    extras = _investigative_extras(case)
    assert "HOST IDENTITY" in extras
    assert "tpl-packer (2022-08-31T17:36:13Z to 2022-09-30T23:37:06Z), rd01" in extras
    assert "Security 12965 -> 12968 (tpl-packer -> rd01)" in extras
    assert "OFFDEVS" not in extras
    digest = render_digest_markdown({"case_id": case.name, "host_identity": identity})
    assert "## Host identity (one machine, several names)" in digest
    assert "one host renamed over time, not separate hosts" in digest


def test_a_case_without_an_index_gets_no_block(tmp_path, monkeypatch):
    from nexus.analysis.host_identity import host_identity_block

    monkeypatch.setenv("NEXUS_ES_URL", "")
    assert host_identity_block(tmp_path / "CASE-NONE") == ""
