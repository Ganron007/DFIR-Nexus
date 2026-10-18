"""D273: what Suricata and Zeek write about their own run is not evidence, and is not dated as evidence.

Samples S03 and S04 hold captures of 2016; after their lanes each case held 32 rows dated the day of the lane run:
Suricata's engine log and counters (suricata.log, stats.log, the eve.json `stats` event) and Zeek's packet filter. The
eve.json lines are S04's, verbatim (tests/fixtures/d273_suricata_eve.json: one dns event, the stats event).
"""
from __future__ import annotations

import shutil
from pathlib import Path

from nexus.langgraph.case_index import iter_index_docs
from nexus.langgraph.query_pack import is_tool_own_log

FIXTURE = Path(__file__).parent / "fixtures" / "d273_suricata_eve.json"


def test_the_engines_run_logs_are_the_tools_own(tmp_path):
    root = tmp_path / "extractions"
    for rel in ("network/capture/suricata/suricata.log", "network/capture/suricata/stats.log",
                "network/capture/zeek/packet_filter.log", "network/capture/zeek/loaded_scripts.log"):
        assert is_tool_own_log(root / rel, root), rel
    for rel in ("network/capture/suricata/eve.json", "network/capture/suricata/fast.log",
                "network/capture/zeek/conn.log", "network/capture/zeek/dns.log", "network/capture/zeek/stats.log"):
        assert not is_tool_own_log(root / rel, root), rel


def test_a_stats_event_has_no_event_time_and_a_dns_event_keeps_its_own(tmp_path):
    out = tmp_path / "extractions" / "network" / "capture" / "suricata"
    out.mkdir(parents=True)
    shutil.copyfile(FIXTURE, out / "eve.json")
    docs = {d["line"]: d for d in iter_index_docs(tmp_path) if d["family"] == "suricata"}
    dns, stats = docs[1], docs[2]
    # 2016-01-26T01:27:24.048885+0530, written in the lane host's zone with its offset.
    assert dns["ts"] == "2016-01-25T19:57:24Z"
    assert "ts" not in stats, "the engine's counters are stamped when the engine ran"
