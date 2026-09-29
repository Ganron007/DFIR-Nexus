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
