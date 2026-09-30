"""Sweep R7-R16: a folder of one format dispatches through the file planner.

These seven formats were SKIPped as "no recognized evidence shape" when
registered as folders, although the per-file branches parse every one of them.
The dispatch dedupes identical real jobs (RDP's two cache files -> one
bmc-tools run) and gives duplicate stems distinct output names.
"""
from __future__ import annotations

from pathlib import Path

from nexus.langgraph.tool_lane import _plan_single_artifact


def _jobs(root: Path, files: dict[str, bytes | str]):
    src = root / "in"
    for rel, content in files.items():
        p = src / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content, encoding="utf-8")
    return _plan_single_artifact(src, root / "ex"), src


def test_jumplists_folder_schedules_jlecmd_per_file(tmp_path):
    jobs, _ = _jobs(tmp_path, {
        "automatic/1bc392b8e104a00e.automaticDestinations-ms": b"x",
        "custom/abcdef0123456789.customDestinations-ms": b"y",
    })
    assert [j.tool for j in jobs].count("jlecmd") == 2
    csvfs = [j.argv[j.argv.index("--csvf") + 1] for j in jobs if "--csvf" in j.argv]
    assert len(set(csvfs)) == 2, csvfs


def test_rdp_folder_deduplicates_to_one_bmc_job(tmp_path):
    jobs, _ = _jobs(tmp_path, {"Cache0000.bin": b"\x00\x01", "Cache0001.bin": b"\x00\x02"})
    bmc = [j for j in jobs if j.tool == "bmc-tools"]
    assert len(bmc) == 1, [j.argv for j in jobs]
    assert "-s" in bmc[0].argv  # folder mode


def test_thumbcache_folder_uses_the_file_flag(tmp_path):
    jobs, _ = _jobs(tmp_path, {"thumbcache_256.db": b"\x01\x02", "thumbcache_32.db": b"\x03\x04"})
    thumb = [j for j in jobs if j.tool == "thumbcache_viewer"]
    assert len(thumb) == 2
    assert all("-t" in j.argv for j in thumb)


def test_thumbcache_idx_companion_skips_without_a_viewer_run(tmp_path):
    """The index/pointer companion is not a thumbnail cache.

    thumbcache_viewer answers "The file is not a thumbcache database." and
    writes nothing (sweep R10 re-run). That message is identical for a
    truncated real cache, so the skip keys on the file NAME - a corrupt cache
    must keep failing the gate instead of being masked as "no entries".
    """
    jobs, _ = _jobs(tmp_path, {
        "thumbcache_256.db": b"\x01\x02",
        "thumbcache_idx.db": b"\x03\x04",
    })
    dispatched = [j for j in jobs if j.status != "SKIP"]
    skips = [j for j in jobs if j.status == "SKIP"]
    assert [j.tool for j in dispatched] == ["thumbcache_viewer"]
    assert "thumbcache_256.db" in " ".join(dispatched[0].argv)
    assert len(skips) == 1
    assert "index/pointer companion" in skips[0].reason
    assert "thumbcache_idx.db" in skips[0].reason


def test_lone_thumbcache_idx_file_skips(tmp_path):
    p = tmp_path / "thumbcache_idx.db"
    p.write_bytes(b"\x03\x04")
    jobs = _plan_single_artifact(p, tmp_path / "ex")
    assert [(j.tool, j.status) for j in jobs] == [("thumbcache_viewer", "SKIP")]
    assert "no thumbnail entries" in jobs[0].reason


def test_folder_dispatch_is_unlimited_by_default(tmp_path, monkeypatch):
    """WO-13: no cap means every file is planned (a real Recent\\ folder)."""
    monkeypatch.delenv("NEXUS_FOLDER_DISPATCH_MAX", raising=False)
    files = {f"sample_{i:03d}.exe": b"MZ" for i in range(250)}
    jobs, _ = _jobs(tmp_path, files)
    sig = [j for j in jobs if j.tool == "sigcheck"]
    assert len(sig) == 250
    assert not [j for j in jobs if j.status == "FAIL"]


def test_folder_dispatch_cap_fails_closed(tmp_path, monkeypatch):
    """WO-13: with a cap, the overflow is a FAIL row and the gate blocks."""
    from nexus.langgraph.lane_gate import lane_gate_blocked, write_lane_gate

    monkeypatch.setenv("NEXUS_FOLDER_DISPATCH_MAX", "200")
    files = {f"sample_{i:03d}.exe": b"MZ" for i in range(250)}
    jobs, _ = _jobs(tmp_path, files)
    sig = [j for j in jobs if j.tool == "sigcheck"]
    assert len(sig) == 200
    fails = [j for j in jobs if j.status == "FAIL"]
    assert len(fails) == 1
    assert fails[0].tool == "(discovery)"
    assert fails[0].critical is True
    assert "NEXUS_FOLDER_DISPATCH_MAX" in fails[0].reason

    case = tmp_path / "CASE-GATE0001"
    gate = write_lane_gate(case, "run-test", [
        {"tool": j.tool, "purpose": j.purpose, "status": j.status, "reason": j.reason}
        for j in jobs
    ])
    assert gate["status"] == "blocked"
    assert lane_gate_blocked(case)


def test_setupapi_folder_stages_strings(tmp_path):
    jobs, _ = _jobs(tmp_path, {"setupapi.dev.log": "device install log line\n"})
    assert [j.tool for j in jobs] == ["strings"]
    assert jobs[0].argv[-1].endswith("setupapi.dev.log")


def test_samples_folder_sigcheck_is_offline_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("NEXUS_SIGCHECK_VT", raising=False)
    jobs, _ = _jobs(tmp_path, {"chrome.exe": b"MZ", "msedge.exe": b"MZ"})
    sig = [j for j in jobs if j.tool == "sigcheck"]
    assert len(sig) == 2
    assert all("-vt" not in j.argv for j in sig), "VT probe must be opt-in"

    monkeypatch.setenv("NEXUS_SIGCHECK_VT", "1")
    jobs2, _ = _jobs(tmp_path / "vt", {"chrome.exe": b"MZ"})
    assert any("-vt" in j.argv for j in jobs2)


def test_activitiescache_folder_outputs_do_not_collide(tmp_path):
    jobs, _ = _jobs(tmp_path, {
        "profile1/ActivitiesCache.db": b"sqlite",
        "profile2/ActivitiesCache.db": b"sqlite",
    })
    wxt = [j for j in jobs if j.tool == "wxtcmd"]
    assert len(wxt) == 2
    assert all("--csvf" not in j.argv for j in wxt), "WxTCmd rejects --csvf"
    csv_dirs = [j.argv[j.argv.index("--csv") + 1] for j in wxt]
    assert len(set(csv_dirs)) == 2, csv_dirs  # per-file output dirs


def test_empty_thumbcache_is_a_skip_not_a_fail():
    from nexus.langgraph.tool_lane import ToolJob, _empty_output_status

    job = ToolJob(host="windows", tool="thumbcache_viewer", argv=[], purpose="t")
    status, reason = _empty_output_status(
        job, {"stdout": "Extracting cache entry 1...\nEnd of file reached. There are no more entries.\n"}
    )
    assert status == "SKIP", reason
    status2, _ = _empty_output_status(job, {"stdout": "loaded 12 entries"})
    assert status2 == "FAIL"


def test_empty_thumbcache_marker_read_from_saved_capture(tmp_path):
    """The MCP result carries the capture path, not its text."""
    from nexus.langgraph.tool_lane import ToolJob, _empty_output_status

    cap = tmp_path / "cap.txt"
    cap.write_text("End of file reached. There are no more entries.\n", encoding="utf-8")
    job = ToolJob(host="windows", tool="thumbcache_viewer", argv=[], purpose="t")
    status, _ = _empty_output_status(job, {"output_saved_to": str(cap)})
    assert status == "SKIP"


def test_srum_folder_plans_the_database_only(tmp_path, monkeypatch):
    import nexus.langgraph.tool_lane as lane

    def _fake_copy(parent, work, prefixes):
        work.mkdir(parents=True, exist_ok=True)
        (work / "SRUDB.dat").write_bytes(b"ese")

    monkeypatch.setattr(lane, "_copy_ese_siblings", _fake_copy)
    monkeypatch.setattr(lane, "_esentutl_repair", lambda *a, **k: None)

    jobs, _ = _jobs(tmp_path, {
        "SRUDB.dat": b"ese",
        "SRU.log": b"log",
        "SRU.chk": b"chk",
    })
    srum = [j for j in jobs if j.tool == "srumecmd"]
    assert len(srum) == 1, [j.tool for j in jobs]
    assert any("SRUDB.dat" in a for a in srum[0].argv)
