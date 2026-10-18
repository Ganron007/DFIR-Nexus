"""Zeek and Suricata on SIFT for a capture registered on this host (samples S03/S04, 2026-10-18).

Three things kept every capture of a Windows examiner off SIFT: a registered folder was never searched for captures;
a capture was planned only if its local path began with the SIFT evidence root, which a Windows path never does; and
the jobs wrote under the evidence root, which the lane's pull does not read. The layout is S03's.
"""
from __future__ import annotations

from pathlib import Path

from nexus.langgraph.network_lane import discover_network_inputs, plan_network_triage
from nexus.langgraph.tool_lane import sift_jobs_for_lane

ROOT = "/home/sansforensics/.nexus/cases/CASE-EA24B279/evidence"
EXTRACTIONS = "/home/sansforensics/.nexus/cases/CASE-EA24B279/extractions"
PCAP_HEADER = b"\xd4\xc3\xb2\xa1" + b"\x00" * 40


def _sample(tmp_path: Path) -> Path:
    s03 = tmp_path / "S03"
    (s03 / "capture").mkdir(parents=True)
    (s03 / "capture" / "capture.pcap").write_bytes(PCAP_HEADER)
    (s03 / "logs").mkdir()
    (s03 / "logs" / "bind.log").write_text("x\n", encoding="utf-8")
    return s03


def test_a_registered_folder_is_searched_for_captures(tmp_path):
    s03 = _sample(tmp_path)
    found = discover_network_inputs([str(s03)])
    assert found == {"pcap": [str(s03 / "capture" / "capture.pcap")], "nfcapd": []}


def test_a_capture_registered_here_is_read_on_sift_from_its_staged_copy(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_SIFT_ZEEK", "1")
    monkeypatch.setenv("NEXUS_SIFT_SURICATA", "1")
    pcap = str(_sample(tmp_path) / "capture" / "capture.pcap")
    jobs = {j.tool: j for j in plan_network_triage([pcap], [], ROOT, has_sift_mcp=True,
                                                   remote_extractions=EXTRACTIONS)}
    zeek, suricata = jobs["zeek"], jobs["suricata"]
    assert zeek.status == suricata.status == "PENDING"
    assert zeek.argv[:3] == ["zeek", "-Cr", f"{ROOT}/capture.pcap"]
    assert suricata.argv[:3] == ["suricata", "-r", f"{ROOT}/capture.pcap"]
    # The outputs go where the lane pulls from, and their folders are made first.
    assert zeek.argv[-1] == f"Log::default_logdir={EXTRACTIONS}/network/capture/zeek"
    assert zeek.prep_dirs == [f"{EXTRACTIONS}/network/capture/zeek"]
    assert suricata.prep_dirs == [f"{EXTRACTIONS}/network/capture/suricata"]


def test_two_captures_of_one_name_are_not_guessed_on_sift(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_SIFT_ZEEK", "1")
    a = tmp_path / "a" / "capture.pcap"
    b = tmp_path / "b" / "capture.pcap"
    for p in (a, b):
        p.parent.mkdir(parents=True)
        p.write_bytes(PCAP_HEADER)
    jobs = plan_network_triage([str(a), str(b)], [], ROOT, has_sift_mcp=True, remote_extractions=EXTRACTIONS)
    assert [j.status for j in jobs] == ["SKIP", "SKIP"]
    assert all("same name" in j.reason for j in jobs)


def test_the_lane_plans_into_the_remote_case_extractions(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_SIFT_ZEEK", "1")
    s03 = _sample(tmp_path)
    jobs = sift_jobs_for_lane(ROOT, has_sift_mcp=True, network_inputs=discover_network_inputs([str(s03)]),
                              remote_extractions=EXTRACTIONS)
    zeek = next(j for j in jobs if j.tool == "zeek")
    assert zeek.status == "PENDING" and zeek.prep_dirs == [f"{EXTRACTIONS}/network/capture/zeek"]


def test_local_app_logs_go_to_the_runs_extractions(tmp_path, monkeypatch):
    """D272: S03's local Suricata alerts were written to the case's own extractions, which the index does not read
    once a run holds data of its own (here, Zeek's logs from SIFT)."""
    import subprocess

    from nexus.langgraph import network_lane as lane

    monkeypatch.setattr(lane, "resolve_local_tool", lambda name: "suricata" if name == "suricata" else None)
    seen: list[list[str]] = []
    monkeypatch.setattr(lane.subprocess, "run",
                        lambda cmd, **_k: seen.append(list(cmd)) or subprocess.CompletedProcess(cmd, 0, "", ""))
    pcap = _sample(tmp_path) / "capture" / "capture.pcap"
    case = tmp_path / "CASE-EA24B279"
    run_extractions = case / "runs" / "RUN-1-tools-x" / "extractions"
    lane.enrich_local_network(pcap, case, run_extractions)
    suricata = next(cmd for cmd in seen if cmd[0] == "suricata")
    assert Path(suricata[suricata.index("-l") + 1]) == run_extractions / "network" / "capture" / "suricata"
    assert not (case / "extractions").exists()
