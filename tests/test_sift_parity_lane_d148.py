"""D148: the lane hands the SIFT host no job when the host does not run this tree's code (2026-10-18).

`nexus sift setup` refuses to start the host's server on stale code, but the host's systemd unit restarts it with no
check, so after a reboot the lane could hand jobs to old code with no sign of it. The host's listing here is this
tree's own manifest, in `sha256sum`'s format, with one real file's hash changed.
"""
from __future__ import annotations

import subprocess
from dataclasses import asdict
from pathlib import Path

from nexus.case import sift_parity
from nexus.langgraph import tool_lane as tl
from nexus.langgraph.lane_gate import write_lane_gate

SRC = Path(sift_parity.__file__).resolve().parents[2]


def _host_listing(change: str | None) -> str:
    manifest = sift_parity.code_manifest(SRC)
    if change:
        manifest[change] = "0" * 64
    return "\n".join(f"{digest}  {path}" for path, digest in manifest.items()) + "\n"


def _jobs() -> list[tl.ToolJob]:
    return [tl.ToolJob(host="sift", tool="zeek", argv=["zeek", "-r", "/cases/x/evidence/capture.pcap"],
                       purpose="Zeek capture.pcap"),
            tl.ToolJob(host="windows", tool="hayabusa", argv=["hayabusa"], purpose="EVTX timeline")]


def _host(monkeypatch, tmp_path, listing: str) -> None:
    key = tmp_path / "key"
    key.write_text("k", encoding="utf-8")
    monkeypatch.setattr("nexus.case.sift_sync._ssh_opts", lambda: {"host": "h", "user": "u", "key": str(key),
                                                                   "remote_cases": "/r"})
    monkeypatch.setattr(sift_parity.subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout=listing, stderr=""))


def test_a_host_with_other_code_holds_the_sift_jobs(monkeypatch, tmp_path):
    _host(monkeypatch, tmp_path, _host_listing("nexus/langgraph/tool_lane.py"))
    jobs = _jobs()
    tl._hold_sift_jobs_on_stale_code(jobs, "CASE-X", has_sift_mcp=True)
    sift, windows = jobs
    assert sift.status == "SKIP" and sift.argv, "it keeps its command: it waits, it is not dropped"
    assert "1 changed" in sift.reason and "nexus sift setup --case CASE-X --sync-code" in sift.reason
    assert windows.status == "PENDING", "the Windows lane runs as before"
    gate = write_lane_gate(tmp_path, "RUN-1", [{**asdict(sift), "status": "SKIP"}, {**asdict(windows), "status": "OK"}])
    assert gate["status"] == "waiting" and gate["waiting_count"] == 1


def test_a_host_with_this_tree_s_code_runs_them(monkeypatch, tmp_path):
    _host(monkeypatch, tmp_path, _host_listing(None))
    jobs = _jobs()
    tl._hold_sift_jobs_on_stale_code(jobs, "CASE-X", has_sift_mcp=True)
    assert [j.status for j in jobs] == ["PENDING", "PENDING"]
