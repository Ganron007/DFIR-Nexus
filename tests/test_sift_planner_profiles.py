"""SIFT planner profiles: OS-aware Volatility plugins + SleuthKit disk jobs.

The SIFT case set (dmz-www) is a Linux target: vol3 must run linux.* plugins,
and the raw disk image must schedule the SleuthKit tools nothing else in the
pipeline can drive. The Windows profile stays the default for backward
compatibility with the existing KAPE-triage flow.
"""
from __future__ import annotations

from nexus.langgraph.tool_lane import plan_sift_triage


def _vol_plugins(jobs: list) -> list[str]:
    return [j.argv[-1] for j in jobs if j.tool == "vol" and j.status == "PENDING"]


def test_linux_profile_selects_linux_plugins(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_OS", raising=False)
    jobs = plan_sift_triage("/evidence/608", sift_os="linux")
    plugins = _vol_plugins(jobs)
    assert "linux.pslist" in plugins
    assert "linux.bash" in plugins
    assert "linux.sockstat" in plugins
    assert not any(p.startswith("windows.") for p in plugins)


def test_default_profile_stays_windows(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_OS", raising=False)
    plugins = _vol_plugins(plan_sift_triage("/evidence/pack"))
    assert plugins and all(p.startswith("windows.") for p in plugins)


def test_env_profile_is_read_when_param_absent(monkeypatch):
    monkeypatch.setenv("NEXUS_SIFT_OS", "linux")
    plugins = _vol_plugins(plan_sift_triage("/evidence/608"))
    assert "linux.pslist" in plugins and not any(p.startswith("windows.") for p in plugins)


def test_disk_image_schedules_sleuthkit_pair(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_DISK", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_BULK", raising=False)
    jobs = plan_sift_triage(
        "/evidence/608", sift_os="linux", disk_image="/evidence/608/disk.img",
    )
    pending = {j.tool for j in jobs if j.status == "PENDING"}
    assert {"mmls", "fls"} <= pending
    assert "bulk_extractor" not in pending
    fls = next(j for j in jobs if j.tool == "fls")
    assert fls.argv == ["fls", "-r", "-p", "/evidence/608/disk.img"]
    mmls = next(j for j in jobs if j.tool == "mmls")
    assert mmls.argv == ["mmls", "/evidence/608/disk.img"]


def test_bulk_extractor_is_opt_in(monkeypatch):
    monkeypatch.setenv("NEXUS_SIFT_BULK", "1")
    jobs = plan_sift_triage("/evidence/608", disk_image="/evidence/608/disk.img")
    bulk = next((j for j in jobs if j.tool == "bulk_extractor"), None)
    assert bulk is not None
    assert bulk.argv[:3] == ["bulk_extractor", "-o", "/evidence/608/bulk_extractor"]


def test_no_disk_image_keeps_fls_out(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_DISK", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    pending = {j.tool for j in plan_sift_triage("/evidence/608") if j.status == "PENDING"}
    assert "fls" not in pending and "mmls" not in pending
