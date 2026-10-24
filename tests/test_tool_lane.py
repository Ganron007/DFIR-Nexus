"""Deterministic tool-lane planner tests (no MCP required)."""

from pathlib import Path

from nexus.langgraph.tool_lane import (
    ToolJob,
    _apply_default_optional_tool_skips,
    _artifact_completeness_for_paths,
    _mark_dirty_hive_warnings,
    find_windows_root,
    plan_sift_triage,
    plan_windows_triage,
    sift_jobs_for_lane,
    timeout_for_bytes,
)


def test_find_windows_root(tmp_path: Path):
    root = tmp_path / "img"
    (root / "Windows" / "System32").mkdir(parents=True)
    assert find_windows_root(root) == root
    assert find_windows_root(tmp_path / "missing") is None


def test_completeness_covers_expanded_roots_in_plan_paths(tmp_path: Path, monkeypatch):
    from nexus.langgraph import artifact_map

    source = tmp_path / "S08"
    source.mkdir()
    (source / "sample.7z").write_bytes(b"archive")
    expanded_a = tmp_path / "case" / "evidence" / "_expanded" / "archive-a"
    expanded_b = tmp_path / "case" / "evidence" / "_expanded" / "archive-b"
    roots = [expanded_a / "host-a" / "C", expanded_b / "host-b" / "C"]
    for root in roots:
        (root / "Windows" / "System32").mkdir(parents=True)

    discovered = []
    monkeypatch.setattr(
        artifact_map,
        "discover_windows_artifacts",
        lambda root: discovered.append(root) or [],
    )
    monkeypatch.setattr(artifact_map, "completeness_table", lambda hits, tools, ledger=None: [])

    rows = _artifact_completeness_for_paths(
        [source, expanded_a, expanded_b, expanded_a], set(),
    )

    assert rows == []
    assert discovered == roots


def test_completeness_finds_root_for_a_registered_file(tmp_path: Path, monkeypatch):
    from nexus.langgraph import artifact_map

    root = tmp_path / "case" / "evidence" / "_expanded" / "host" / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    registered_file = root / "Windows" / "System32" / "winevt" / "Logs" / "Security.evtx"
    registered_file.parent.mkdir(parents=True)
    registered_file.write_bytes(b"evtx")

    discovered = []
    monkeypatch.setattr(
        artifact_map,
        "discover_windows_artifacts",
        lambda image_root: discovered.append(image_root) or [],
    )
    monkeypatch.setattr(artifact_map, "completeness_table", lambda hits, tools, ledger=None: [])

    assert _artifact_completeness_for_paths([registered_file], set()) == []
    assert discovered == [root]


def test_plan_windows_triage_skips_and_schedules(tmp_path: Path):
    root = tmp_path / "C"
    (root / "Windows" / "System32" / "winevt" / "Logs").mkdir(parents=True)
    sec = root / "Windows/System32/winevt/Logs/Security.evtx"
    sec.write_bytes(b"evtx")
    (root / "Windows" / "Prefetch").mkdir(parents=True)
    extractions = tmp_path / "extractions"
    extractions.mkdir()

    jobs = plan_windows_triage(str(root), extractions)
    tools = {j.tool for j in jobs if j.status == "PENDING"}
    assert "hayabusa" in tools
    assert "pecmd" in tools
    skipped = {j.tool for j in jobs if j.status == "SKIP"}
    assert "mftecmd" in skipped  # no $MFT
    hay = next(j for j in jobs if j.tool == "hayabusa" and j.status == "PENDING")
    assert "-d" in hay.argv
    # Suzaku 2.x dropped local EVTX support — it must skip with a reason.
    assert "suzaku" not in tools
    suz_skip = next(j for j in jobs if j.tool == "suzaku")
    assert suz_skip.status == "SKIP" and "cloud-log" in suz_skip.reason


def test_plan_windows_triage_stage0_pack_wevtutil(tmp_path: Path):
    pack = tmp_path / "pack"
    wevt = pack / "hosts" / "WS01" / "wevtutil"
    wevt.mkdir(parents=True)
    (wevt / "Security.evtx").write_bytes(b"evtx")
    extractions = tmp_path / "extractions"
    extractions.mkdir()

    jobs = plan_windows_triage(str(pack), extractions)
    pending = {j.tool for j in jobs if j.status == "PENDING"}
    assert "hayabusa" in pending
    assert "evtxecmd" in pending
    # Suzaku 2.x dropped local EVTX support — skip, don't schedule.
    assert "suzaku" not in pending
    suz_skip = next(j for j in jobs if j.tool == "suzaku")
    assert suz_skip.status == "SKIP" and "cloud-log" in suz_skip.reason
    hay = next(j for j in jobs if j.tool == "hayabusa" and j.status == "PENDING")
    assert str(wevt) in hay.argv
    assert not any(j.tool == "(discovery)" and j.status == "SKIP" for j in jobs)
    # parsers write under case extractions, not empty dirs on the pack
    assert not (wevt.parent / "hayabusa").exists()


def test_plan_windows_triage_all_user_profiles(tmp_path: Path):
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    for name in ("alice", "bob"):
        recent = root / "Users" / name / "AppData/Roaming/Microsoft/Windows/Recent"
        recent.mkdir(parents=True)
        (root / "Users" / name / "NTUSER.DAT").write_bytes(b"hive")
    (root / "Users" / "Public").mkdir(parents=True)
    extractions = tmp_path / "extractions"
    extractions.mkdir()
    jobs = plan_windows_triage(str(root), extractions)
    lecmd = [j for j in jobs if j.tool == "lecmd" and j.status == "PENDING"]
    assert len(lecmd) == 2
    purposes = " ".join(j.purpose for j in lecmd)
    assert "alice" in purposes and "bob" in purposes
    assert "Public" not in purposes


def test_plan_sbecmd_for_ntuser_and_usrclass_as_separate_inputs(tmp_path: Path):
    root = tmp_path / "image"
    (root / "Windows" / "System32").mkdir(parents=True)
    user = root / "Users" / "alice"
    ntuser = user / "NTUSER.DAT"
    usrclass = user / "AppData/Local/Microsoft/Windows/UsrClass.dat"
    ntuser.parent.mkdir(parents=True)
    usrclass.parent.mkdir(parents=True)
    ntuser.touch()
    usrclass.touch()

    extractions = tmp_path / "extractions"
    jobs = plan_windows_triage(str(root), extractions)
    shellbags = [j for j in jobs if j.tool == "sbecmd" and j.status == "PENDING"]

    assert len(shellbags) == 2
    assert {j.source for j in shellbags} == {str(ntuser), str(usrclass)}
    stages = {Path(j.argv[j.argv.index("-d") + 1]) for j in shellbags}
    assert len(stages) == 2
    assert all(stage.is_dir() for stage in stages)
    assert {p.name for stage in stages for p in stage.iterdir()} == {
        "NTUSER.DAT", "UsrClass.dat"
    }
    assert not any(j.tool == "sbecmd" and j.status == "SKIP" for j in jobs)


def test_plan_sbecmd_for_registered_ntuser_file(tmp_path: Path):
    ntuser = tmp_path / "NTUSER.DAT"
    ntuser.touch()

    jobs = plan_windows_triage(str(ntuser), tmp_path / "extractions")
    shellbags = [j for j in jobs if j.tool == "sbecmd" and j.status == "PENDING"]

    assert len(shellbags) == 1
    assert shellbags[0].source == str(ntuser)
    stage = Path(shellbags[0].argv[shellbags[0].argv.index("-d") + 1])
    assert [p.name for p in stage.iterdir()] == ["NTUSER.DAT"]
    assert shellbags[0].argv[-2:] == ["--nl", "true"]


def test_sbecmd_dirty_hive_without_logs_is_warned_after_output(tmp_path: Path):
    hive = tmp_path / "UsrClass.dat"
    hive.write_bytes(b"regf" + (7).to_bytes(4, "little") + (6).to_bytes(4, "little"))

    jobs = plan_windows_triage(str(hive), tmp_path / "extractions")
    job = next(j for j in jobs if j.tool == "sbecmd")
    assert job.preflight["registry_hive"] == {
        "dirty": True,
        "transaction_logs": [],
        "dirty_without_logs": True,
    }

    job.status = "OK"  # the lane reaches this hook only after a product passed validation
    ledger = [{"host": job.host, "tool": job.tool, "purpose": job.purpose, "status": "OK"}]
    warned = _mark_dirty_hive_warnings([job], ledger)

    expected = "dirty hive parsed without its transaction logs: changes held only in the logs are absent"
    assert warned == [job]
    assert job.status == "WARN" and job.reason == expected
    assert ledger[0]["status"] == "WARN" and ledger[0]["reason"] == expected


def test_sbecmd_drive_tree_stages_case_insensitive_transaction_logs(tmp_path: Path):
    root = tmp_path / "image"
    (root / "Windows" / "System32").mkdir(parents=True)
    user = root / "Users" / "alice"
    hive = user / "NTUSER.DAT"
    hive.parent.mkdir(parents=True)
    hive.write_bytes(b"regf" + (11).to_bytes(4, "little") + (10).to_bytes(4, "little"))
    sidecars = {
        "nTuSeR.dAt.LoG": b"log",
        "NTUSER.DAT.lOg1": b"log1",
        "ntuser.dat.LOG2": b"log2",
    }
    for name, contents in sidecars.items():
        (user / name).write_bytes(contents)

    jobs = plan_windows_triage(str(root), tmp_path / "extractions")
    job = next(j for j in jobs if j.tool == "sbecmd" and "NTUSER.DAT" in j.purpose)
    stage = Path(job.argv[job.argv.index("-d") + 1])

    assert {path.name for path in stage.iterdir()} == {hive.name, *sidecars}
    assert {
        path.name: path.read_bytes() for path in stage.iterdir() if path.name in sidecars
    } == sidecars
    assert job.preflight["registry_hive"]["transaction_logs"] == [
        "nTuSeR.dAt.LoG", "NTUSER.DAT.lOg1", "ntuser.dat.LOG2",
    ]
    assert job.preflight["registry_hive"]["dirty_without_logs"] is False
    assert job.argv[-2:] == ["--nl", "true"]


def test_recmd_schedules_machine_and_user_hives_without_software(monkeypatch, tmp_path: Path):
    from nexus.langgraph import tool_lane

    root = tmp_path / "image"
    config = root / "Windows/System32/config"
    config.mkdir(parents=True)
    (config / "SYSTEM").write_bytes(b"hive")
    user_hive = root / "Users/alice/NTUSER.DAT"
    user_hive.parent.mkdir(parents=True)
    user_hive.write_bytes(b"hive")
    monkeypatch.setattr(tool_lane, "_find_recmd_batch", lambda: tmp_path / "machine.reb")
    monkeypatch.setattr(tool_lane, "_find_recmd_user_batch", lambda: tmp_path / "user.reb")

    jobs = tool_lane.plan_windows_triage(str(root), tmp_path / "extractions")
    recmd = [j for j in jobs if j.tool == "recmd" and j.status == "PENDING"]

    assert len(recmd) == 2
    assert any("-d" in j.argv and str(config) in j.argv for j in recmd)
    assert any("-f" in j.argv and str(user_hive) in j.argv for j in recmd)


def test_wmi_parser_is_a_related_tool_for_the_wmi_persistence_artifact():
    from nexus.knowledge.loader import get_artifacts_for_tool

    artifacts = get_artifacts_for_tool("wmi-parser")

    assert any(artifact["name"] == "WMI Event Subscription Persistence" for artifact in artifacts)


def test_plan_sift_requires_root(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_TRIAGE_ROOT", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_SKIP_PLASO", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_PLASO", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_MEMORY_FILE", raising=False)
    jobs = plan_sift_triage("")
    assert jobs[0].status == "SKIP"
    # D46: a bare root schedules no Volatility 3 job. Memory needs a declared
    # image (caller, env or the evidence registry); inventing one is the defect.
    jobs2 = plan_sift_triage("/home/sansforensics/Evidence-files/pack")
    assert any(j.tool == "vol" and j.status == "SKIP" for j in jobs2)
    assert not any(j.tool == "vol" and j.status == "PENDING" for j in jobs2)
    assert not any(j.tool == "fls" for j in jobs2)
    assert not any(j.tool == "log2timeline" and j.status == "PENDING" for j in jobs2)


def test_plan_sift_no_full_tree_plaso(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_SKIP_PLASO", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_PLASO", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_MEMORY_FILE", raising=False)
    jobs = plan_sift_triage(
        "/home/sansforensics/Evidence-files/pack",
        triage_root="/mnt/windows_mount/C",
    )
    tools = {j.tool for j in jobs if j.status == "PENDING"}
    assert "log2timeline" not in tools
    assert "psort" not in tools
    assert "fls" not in tools
    assert not any(j.tool == "log2timeline" for j in jobs)


def test_empty_usnjrnl_is_skipped_not_scheduled(tmp_path: Path):
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    ext = root / "$Extend"
    ext.mkdir()
    (ext / "$UsnJrnl").write_bytes(b"")
    jobs = plan_windows_triage(str(root), tmp_path / "ex")
    pending_usn = [
        j for j in jobs
        if j.status == "PENDING" and "USN" in (j.purpose or "")
    ]
    assert pending_usn == []
    skipped = [j for j in jobs if j.tool == "mftecmd-usn" and j.status == "SKIP"]
    assert skipped


def test_usable_usn_j_is_scheduled(tmp_path: Path):
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    ext = root / "$Extend"
    ext.mkdir()
    (ext / "$J").write_bytes(b"x" * 8192)
    jobs = plan_windows_triage(str(root), tmp_path / "ex")
    pending = [
        j for j in jobs
        if j.tool == "mftecmd" and j.status == "PENDING" and "USN" in j.purpose
    ]
    assert len(pending) == 1
    assert str(ext / "$J") in pending[0].argv


def test_mactime_not_in_default_sift_plan(monkeypatch):
    """mactime is injected only when NEXUS_SIFT_MACTIME=1 (full-MFT stdout deadlocks MCP)."""
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_PLASO", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_MACTIME", raising=False)
    jobs = plan_sift_triage("/home/sansforensics/Evidence-files/pack")
    assert not any(j.tool == "mactime" for j in jobs)


def test_plan_sift_plaso_opt_in(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    monkeypatch.setenv("NEXUS_SIFT_PLASO", "1")
    jobs = plan_sift_triage("/home/sansforensics/Evidence-files/pack")
    pending = {j.tool for j in jobs if j.status == "PENDING"}
    assert "log2timeline" in pending
    assert "psort" in pending


def test_gap_parsers_are_practical(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("NEXUS_LIVE_RESPONSE", raising=False)
    monkeypatch.delenv("NEXUS_LIVE_ACQUIRE_MEMORY", raising=False)
    monkeypatch.delenv("NEXUS_SAMPLE_FILES", raising=False)
    monkeypatch.delenv("NEXUS_TOOL_LANE_QUICK", raising=False)
    monkeypatch.setattr(
        "nexus.langgraph.tool_lane._esentutl_replay",
        lambda *a, **k: None,
    )
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    inf = root / "Windows" / "INF"
    inf.mkdir(parents=True)
    (inf / "setupapi.dev.log").write_text("usb first seen\n", encoding="utf-8")
    qdir = root / "ProgramData" / "Microsoft" / "Network" / "Downloader"
    qdir.mkdir(parents=True)
    (qdir / "qmgr.db").write_bytes(b"ese")
    expl = root / "Users" / "alice" / "AppData" / "Local" / "Microsoft" / "Windows" / "Explorer"
    expl.mkdir(parents=True)
    (expl / "thumbcache_256.db").write_bytes(b"db")
    cache = (
        root / "Users" / "alice" / "AppData" / "Local"
        / "Microsoft" / "Terminal Server Client" / "Cache"
    )
    cache.mkdir(parents=True)
    (cache / "b0.bmc").write_bytes(b"bmc")
    (root / "$LogFile").write_bytes(b"log")
    extractions = tmp_path / "ex"
    jobs = plan_windows_triage(str(root), extractions)
    pending = {j.tool for j in jobs if j.status == "PENDING"}
    # Plain text is copied, not run through strings.
    assert "strings" not in pending
    assert (extractions / "setupapi" / "setupapi.dev.log").is_file()
    # Unverified CLIs are not forced.
    assert "thumbcache_viewer" not in pending
    # $LogFile must always get a row, never a silent skip. Since TA-Z (OD-T13, 2026-10-24) MFTECmd parses it; this
    # 3-byte one is too small to hold a log, so its row is the visible SKIP that says so.
    assert not [j for j in jobs if j.tool == "logfileparser"]
    lf = [j for j in jobs if j.tool == "mftecmd-logfile" or (j.tool == "mftecmd" and "$LogFile" in j.purpose)]
    assert lf, "$LogFile must always get a row"
    assert all(j.status in ("PENDING", "SKIP") for j in lf)
    # Live acq is silent on an image.
    assert "winpmem" not in pending
    assert not any(j.tool == "winpmem" for j in jobs)
    assert "capa" not in pending
    # Optional parsers: PENDING only if installed, else one SKIP, never FAIL-later.
    for key in ("bitsparser", "bmc-tools"):
        matching = [j for j in jobs if j.tool == key]
        assert all(j.status in ("PENDING", "SKIP") for j in matching)


def test_sample_files_only_when_named(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("NEXUS_SAMPLE_FILES", raising=False)
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    sample = tmp_path / "evil.exe"
    sample.write_bytes(b"MZ")
    jobs = plan_windows_triage(
        str(root), tmp_path / "ex", sample_files=[str(sample)],
    )
    capa = [j for j in jobs if j.tool == "capa"]
    assert capa
    assert all(j.status in ("PENDING", "SKIP") for j in capa)
    jobs_none = plan_windows_triage(str(root), tmp_path / "ex2")
    assert not any(j.tool == "capa" for j in jobs_none)


def test_live_response_off_does_not_mention_winpmem(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("NEXUS_LIVE_RESPONSE", raising=False)
    monkeypatch.delenv("NEXUS_LIVE_ACQUIRE_MEMORY", raising=False)
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    jobs = plan_windows_triage(str(root), tmp_path / "ex")
    assert not any(j.tool == "winpmem" for j in jobs)


def test_dead_box_plan_never_queries_the_examiner_host(tmp_path: Path, monkeypatch):
    """WO-TA item 1: the env gates must not put a live host command on a case plan."""
    monkeypatch.setenv("NEXUS_LIVE_RESPONSE", "1")
    monkeypatch.setenv("NEXUS_LIVE_ACQUIRE_MEMORY", "1")
    root = tmp_path / "C"
    tasks = root / "Windows" / "System32" / "Tasks"
    tasks.mkdir(parents=True)
    (tasks / "Nightly.xml").write_text("<Task/>", encoding="utf-8")
    jobs = plan_windows_triage(str(root), tmp_path / "ex")
    live = {"schtasks", "autorunsc", "handle", "get_injectedthreadex", "winpmem"}
    assert not any(j.tool in live for j in jobs)
    assert not any(j.argv and j.argv[0] in live for j in jobs)
    assert not any("/query" in " ".join(j.argv) for j in jobs if j.argv)


def test_default_lane_leaves_optional_tools_unscheduled(tmp_path: Path, monkeypatch):
    """WO-TA trim: Chainsaw, both Zircolite jobs, RegRipper, USBDeview, KStrike."""
    monkeypatch.delenv("NEXUS_LANE_OPT_IN", raising=False)
    root = tmp_path / "C"
    logs = root / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    (logs / "Security.evtx").write_bytes(b"evtx")
    (root / "Windows" / "System32" / "config").mkdir(parents=True)
    (root / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"hive")
    sum_dir = root / "Windows" / "System32" / "LogFiles" / "SUM"
    sum_dir.mkdir(parents=True)
    (sum_dir / "Current.mdb").write_bytes(b"mdb")
    jobs = plan_windows_triage(str(root), tmp_path / "ex")
    pending = {j.tool for j in jobs if j.status == "PENDING"}
    for name in ("chainsaw", "zircolite", "regripper", "usbdeview", "kstrike"):
        assert name not in pending
    assert "suzaku" not in pending


def test_usbdeview_returns_when_opted_in(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NEXUS_LANE_OPT_IN", "usbdeview")
    monkeypatch.setattr(
        "nexus.langgraph.tool_lane._windows_tool_available",
        lambda key: key == "usbdeview",
    )
    root = tmp_path / "C"
    (root / "Windows" / "System32" / "config").mkdir(parents=True)
    (root / "Windows" / "System32" / "config" / "SYSTEM").write_bytes(b"hive")
    jobs = plan_windows_triage(str(root), tmp_path / "ex")
    usb = [j for j in jobs if j.tool == "usbdeview" and j.status == "PENDING"]
    assert usb
    assert "/regfile" in usb[0].argv


def test_case_pipeline_refuses_live_and_unbound_commands(tmp_path: Path):
    """The real refusal used by the lane executor and the hunt wrapper."""
    import asyncio

    from nexus.langgraph.tool_lane import CasePipelineTool
    from nexus.tools.windows import case_pipeline_refusal

    root = tmp_path / "image"
    root.mkdir()
    evtx = root / "Security.evtx"
    evtx.write_bytes(b"ElfFile")
    assert case_pipeline_refusal(
        "schtasks", ["schtasks", "/query", "/fo", "csv", "/v", "/nh"], [root],
    )
    assert case_pipeline_refusal("netstat", ["netstat", "-ano"], [root])
    assert case_pipeline_refusal(
        "evtxecmd", ["evtxecmd", "-f", str(evtx)], [root],
    ) is None
    assert case_pipeline_refusal("strings", ["strings", str(evtx)], [root]) is None
    assert case_pipeline_refusal("evtxecmd", ["evtxecmd", "-f", r"C:\Windows\System32\config\SAM"], [root])

    class Inner:
        def __init__(self) -> None:
            self.calls = 0

        async def ainvoke(self, payload, config=None, **kwargs):
            self.calls += 1
            return {"success": True}

    inner = Inner()
    guarded = CasePipelineTool(inner, [root])
    refused = asyncio.run(guarded.ainvoke({"command": ["netstat", "-ano"]}))
    assert refused["success"] is False
    assert inner.calls == 0
    allowed = asyncio.run(guarded.ainvoke({"command": ["evtxecmd", "-f", str(evtx)]}))
    assert allowed["success"] is True
    assert inner.calls == 1


def test_case_pipeline_refuses_host_tools_and_unbound_paths(tmp_path: Path):
    """The executor refuses a job that reads the examiner host or names no evidence path."""
    from nexus.tools.windows import _CASE_PIPELINE_EXCLUDED, case_pipeline_refusal

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for key in ("schtasks", "autorunsc", "handle", "winpmem", "get_injectedthreadex"):
        assert key in _CASE_PIPELINE_EXCLUDED
        assert case_pipeline_refusal(key, [key, "/query"], [evidence])
    unbound = case_pipeline_refusal(
        "hayabusa", ["hayabusa", r"C:\Windows\System32\winevt"], [evidence],
    )
    assert unbound
    assert case_pipeline_refusal(
        "hayabusa", ["hayabusa", "-d", str(evidence)], [evidence],
    ) is None
    assert case_pipeline_refusal("hayabusa", ["hayabusa", "-h"], None) is None


def test_n2_extras_gated_chrome_profile(tmp_path: Path):
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    default = root / "Users/alice/AppData/Local/Google/Chrome/User Data/Default"
    prof = root / "Users/alice/AppData/Local/Google/Chrome/User Data/Profile 2"
    default.mkdir(parents=True)
    prof.mkdir(parents=True)
    (default / "History").write_bytes(b"sql")
    (prof / "History").write_bytes(b"sql")
    jobs_off = plan_windows_triage(str(root), tmp_path / "ex")
    extra_off = [j for j in jobs_off if "extra profile" in (j.purpose or "")]
    assert extra_off == []
    jobs_on = plan_windows_triage(str(root), tmp_path / "ex2", extras=["chrome_profiles"])
    extra_on = [j for j in jobs_on if "extra profile" in (j.purpose or "") and j.status == "PENDING"]
    assert len(extra_on) == 1
    assert "Profile 2" in extra_on[0].purpose


def test_timeout_for_bytes_scales_and_caps():
    assert timeout_for_bytes(0) == 600
    assert timeout_for_bytes(1024) == 600
    assert timeout_for_bytes(2 * 1024 * 1024) == 660
    assert timeout_for_bytes(200 * 1024 * 1024) == 3600


def test_sift_jobs_for_lane_windows_only_is_silent():
    assert sift_jobs_for_lane("", has_sift_mcp=False) == []


def test_sift_jobs_for_lane_mcp_without_root_is_honest_skip():
    jobs = sift_jobs_for_lane("", has_sift_mcp=True)
    assert len(jobs) == 1
    assert jobs[0].status == "SKIP"
    assert "NEXUS_SIFT_EVIDENCE_ROOT" in jobs[0].reason


def test_sift_jobs_for_lane_with_root_schedules_vol(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_PLASO", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_MEMORY_FILE", raising=False)
    jobs = sift_jobs_for_lane("/evidence/pack", has_sift_mcp=True)
    # D46: memory is never scheduled from a guessed path. A declared image does
    # schedule it - the registry hands the examiner's own image to the lane.
    assert any(j.tool == "vol" and j.status == "SKIP" for j in jobs)
    assert not any(j.tool == "vol" and j.status == "PENDING" for j in jobs)
    with_declared = sift_jobs_for_lane(
        "/evidence/pack", has_sift_mcp=True,
        memory_file="/evidence/pack/memory/target-memory.raw",
    )
    assert any(j.tool == "vol" and j.status == "PENDING" for j in with_declared)


def test_bmc_skips_zero_byte_only_tiles(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "nexus.langgraph.tool_lane._windows_tool_available",
        lambda key: key == "bmc-tools",
    )
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    cache = (
        root / "Users" / "wacsvc" / "AppData" / "Local"
        / "Microsoft" / "Terminal Server Client" / "Cache"
    )
    cache.mkdir(parents=True)
    (cache / "bcache24.bmc").write_bytes(b"")
    jobs = plan_windows_triage(str(root), tmp_path / "ex")
    bmc = [j for j in jobs if j.tool == "bmc-tools"]
    assert len(bmc) == 1
    assert bmc[0].status == "SKIP"
    assert "0 bytes" in bmc[0].reason


def test_bmc_stages_nonzero_and_scales_timeout(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "nexus.langgraph.tool_lane._windows_tool_available",
        lambda key: key == "bmc-tools",
    )
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    cache = (
        root / "Users" / "wacsvc" / "AppData" / "Local"
        / "Microsoft" / "Terminal Server Client" / "Cache"
    )
    cache.mkdir(parents=True)
    payload = b"x" * (2 * 1024 * 1024)
    (cache / "Cache0000.bin").write_bytes(payload)
    (cache / "bcache24.bmc").write_bytes(b"")
    extractions = tmp_path / "ex"
    jobs = plan_windows_triage(str(root), extractions)
    bmc = next(j for j in jobs if j.tool == "bmc-tools" and j.status == "PENDING")
    src = Path(bmc.argv[bmc.argv.index("-s") + 1])
    assert src.name == "src"
    assert (src / "Cache0000.bin").is_file()
    assert not (src / "bcache24.bmc").exists()
    assert bmc.timeout == 660
    dest = Path(bmc.argv[bmc.argv.index("-d") + 1])
    assert dest.name == "tiles"


def test_bitsparser_stages_a_staged_copy_with_its_logs_replayed(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "nexus.langgraph.tool_lane._windows_tool_available",
        lambda key: key == "bitsparser",
    )
    called: dict = {}

    def _fake_replay(work, *, log_bases):
        called["work"] = work
        called["log_bases"] = log_bases

    monkeypatch.setattr(
        "nexus.langgraph.tool_lane._esentutl_replay",
        _fake_replay,
    )
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)
    qdir = root / "ProgramData" / "Microsoft" / "Network" / "Downloader"
    qdir.mkdir(parents=True)
    (qdir / "qmgr.db").write_bytes(b"ese" * 100)
    (qdir / "edb.log").write_bytes(b"log")
    extractions = tmp_path / "ex"
    jobs = plan_windows_triage(str(root), extractions)
    bp = next(j for j in jobs if j.tool == "bitsparser" and j.status == "PENDING")
    staged = Path(bp.argv[bp.argv.index("-i") + 1])
    assert staged.name == "qmgr.db"
    assert "workdir" in staged.parts
    assert staged.is_file()
    assert (staged.parent / "edb.log").is_file()
    assert "staged copy" in bp.purpose and "repaired" not in bp.purpose
    assert "--carvedb" in bp.argv
    assert "--carveall" not in bp.argv
    assert Path(called["work"]) == staged.parent, "the replay runs in the staged copy's folder"
    assert called["log_bases"] == ("edb", "qmgr")


def test_apply_prior_ok_reuses_matching_purpose(tmp_path: Path, monkeypatch):
    import json

    from nexus.langgraph.tool_lane import ToolJob, apply_prior_ok

    monkeypatch.delenv("NEXUS_TOOL_LANE_RERUN", raising=False)
    ext = tmp_path / "extractions"
    ext.mkdir()
    (ext / "_tool_lane_ledger.json").write_text(
        '[{"host":"windows","tool":"hayabusa","purpose":"Hayabusa EVTX",'
        '"status":"OK","audit_id":"a1","argv":["hayabusa","-d","old"],'
        '"evidence_sha":"' + "ab" * 32 + '",'
        '"lineage":{"tool":"hayabusa","file_version":"4.0.0","version_source":"pe-version-resource"}}]',
        encoding="utf-8",
    )
    # The registered evidence the job reads; its hash is the one the prior row was written for.
    (tmp_path / "evidence.json").write_text(
        json.dumps([{"path": str(tmp_path / "H"), "kind": "directory", "sha256": "ab" * 32}]),
        encoding="utf-8",
    )
    jobs = [
        ToolJob(host="windows", tool="hayabusa", argv=["hayabusa", "-d", str(tmp_path / "H")],
                purpose="Hayabusa EVTX"),
        ToolJob(host="windows", tool="bitsparser", argv=["bitsparser"], purpose="BITS job queue"),
    ]
    assert apply_prior_ok(jobs, tmp_path) == 1
    assert jobs[0].status == "OK"
    assert jobs[0].audit_id == "a1"
    assert jobs[0].reason.startswith("reused prior OK")
    assert jobs[1].status == "PENDING"


def test_apply_prior_ok_rerun_env_disables(tmp_path: Path, monkeypatch):
    from nexus.langgraph.tool_lane import ToolJob, apply_prior_ok

    monkeypatch.setenv("NEXUS_TOOL_LANE_RERUN", "1")
    ext = tmp_path / "extractions"
    ext.mkdir()
    (ext / "_tool_lane_ledger.json").write_text(
        '[{"host":"windows","tool":"hayabusa","purpose":"Hayabusa EVTX","status":"OK"}]',
        encoding="utf-8",
    )
    jobs = [
        ToolJob(host="windows", tool="hayabusa", argv=["hayabusa"], purpose="Hayabusa EVTX"),
    ]
    assert apply_prior_ok(jobs, tmp_path) == 0
    assert jobs[0].status == "PENDING"


def test_plan_sift_memory_file_is_used_and_no_default_exists(monkeypatch):
    """D46: the memory path comes from the caller or the registry, never src."""
    monkeypatch.delenv("NEXUS_SIFT_MEMORY_FILE", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_PLASO", raising=False)
    jobs = plan_sift_triage(
        "/mnt/srl_rd01",
        memory_file="/mnt/srl_rd01/memory/rd01-memory.img",
    )
    vol = [j for j in jobs if j.tool == "vol" and j.status == "PENDING"]
    assert vol
    assert any("/mnt/srl_rd01/memory/rd01-memory.img" in a for j in vol for a in j.argv)

    # Nothing is declared: an honest SKIP row, and no invented path anywhere.
    jobs_none = plan_sift_triage("/mnt/srl_rd01")
    skip = [j for j in jobs_none if j.tool == "vol" and j.status == "SKIP"]
    assert skip and "No memory image declared" in skip[0].reason
    assert not any(j.tool == "vol" and j.status == "PENDING" for j in jobs_none)
    for j in jobs_none:
        for a in j.argv:
            assert "rd01-memory.img" not in a and "Rocba-Memory.raw" not in a


def test_plan_sift_no_memory_declared_still_plans_disk_and_plaso(monkeypatch):
    """A missing memory image must not silently drop the other SIFT jobs."""
    monkeypatch.delenv("NEXUS_SIFT_MEMORY_FILE", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_PLASO", raising=False)
    monkeypatch.setenv("NEXUS_SIFT_PLASO", "1")
    jobs = plan_sift_triage(
        "/mnt/evidence",
        disk_image="/mnt/evidence/disk.dd",
    )
    pending = {j.tool for j in jobs if j.status == "PENDING"}
    assert "mmls" in pending and "fls" in pending
    assert "log2timeline" in pending and "psort" in pending
    assert any(j.tool == "vol" and j.status == "SKIP" for j in jobs)


def test_copy_text_skips_existing_readonly(tmp_path: Path):
    from nexus.langgraph.tool_lane import _copy_text

    src = tmp_path / "setupapi.dev.log"
    src.write_text("usb", encoding="utf-8")
    dest_dir = tmp_path / "ex"
    dest = dest_dir / "setupapi" / "setupapi.dev.log"
    dest.parent.mkdir(parents=True)
    dest.write_text("already", encoding="utf-8")
    dest.chmod(0o444)
    _copy_text(dest_dir, "setupapi/setupapi.dev.log", src)
    assert dest.read_text(encoding="utf-8") == "already"
    from nexus.tools.windows import _hash_file

    d = tmp_path / "Cache"
    d.mkdir()
    assert _hash_file(str(d)) == ""
    f = d / "x.bin"
    f.write_bytes(b"abc")
    digest = _hash_file(str(f))
    assert len(digest) == 64


def test_plan_single_evtx_file_is_staged_and_parsed(tmp_path: Path):
    """Phase 4h: a lone .evtx file is valid evidence (was discovery SKIP)."""
    evtx = tmp_path / "susp_explorer.evtx"
    evtx.write_bytes(b"evtx")
    extractions = tmp_path / "extractions"
    extractions.mkdir()

    jobs = plan_windows_triage(str(evtx), extractions)
    pending = {j.tool for j in jobs if j.status == "PENDING"}
    assert "evtxecmd" in pending and "hayabusa" in pending
    assert all(j.tool != "(discovery)" for j in jobs)
    assert (extractions / "evtx_input" / "susp_explorer.evtx").is_file()


def test_plan_evtx_folder_is_recognized(tmp_path: Path):
    """Phase 4h: any folder of *.evtx (no Stage-0 pack) is parsable."""
    folder = tmp_path / "Execution"
    folder.mkdir()
    (folder / "a.evtx").write_bytes(b"evtx")
    (folder / "b.evtx").write_bytes(b"evtx")
    extractions = tmp_path / "extractions"
    extractions.mkdir()

    jobs = plan_windows_triage(str(folder), extractions)
    pending = {j.tool for j in jobs if j.status == "PENDING"}
    assert "evtxecmd" in pending


def test_plan_single_artifacts_map_to_their_tool(tmp_path: Path):
    """Phase 4h: a lone prefetch/hive schedules the right parser."""
    extractions = tmp_path / "extractions"
    extractions.mkdir()
    pf = tmp_path / "CMD.EXE-ABC123.pf"
    pf.write_bytes(b"pf")
    assert {j.tool for j in plan_windows_triage(str(pf), extractions) if j.status == "PENDING"} == {"pecmd"}

    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"regf")
    tools = {j.tool for j in plan_windows_triage(str(hive), extractions) if j.status == "PENDING"}
    assert {"recmd", "appcompatcacheparser"} <= tools


def test_plan_unknown_shape_skips_with_guidance(tmp_path: Path):
    mystery = tmp_path / "mystery.bin"
    mystery.write_bytes(b"x")
    extractions = tmp_path / "extractions"
    extractions.mkdir()
    jobs = plan_windows_triage(str(mystery), extractions)
    assert len(jobs) == 1 and jobs[0].status == "SKIP"
    assert "Accepted:" in jobs[0].reason


def test_is_host_evidence_routes_non_host_to_importers(tmp_path: Path):
    from nexus.langgraph.tool_lane import is_host_evidence

    evtx = tmp_path / "a.evtx"
    evtx.write_bytes(b"e")
    pcap = tmp_path / "a.pcap"
    pcap.write_bytes(b"p")
    assert is_host_evidence(str(evtx)) is True
    assert is_host_evidence(str(pcap)) is False


def test_default_optional_tools_are_explicit_skips():
    jobs = [
        ToolJob(host="windows", tool="logfileparser", argv=["logfileparser"], purpose="$LogFile"),
        ToolJob(host="windows", tool="DeepBlueCLI", argv=["deepbluecli"], purpose="Security.evtx"),
        ToolJob(host="windows", tool="hayabusa", argv=["hayabusa"], purpose="EVTX"),
        ToolJob(
            host="windows", tool="deepbluecli", argv=["deepbluecli"], purpose="reused result",
            status="OK", audit_id="old-audit", output_saved_to="old-output.csv",
            output_files=["old-output.csv"], result={"success": True}, lineage={"version": "1.0"},
        ),
        ToolJob(host="windows", tool="logfileparser", argv=[], purpose="missing", status="SKIP", reason="missing artifact"),
    ]

    # TA-Z (operator OD-T13, 2026-10-24): LogFileParser left the default-skip policy; MFTECmd parses $LogFile and
    # the lane no longer plans LogFileParser, so the policy leaves a LogFileParser row as it is.
    assert _apply_default_optional_tool_skips(jobs) == 2
    assert [job.status for job in jobs] == ["PENDING", "SKIP", "PENDING", "SKIP", "SKIP"]
    assert "long channel scans" in jobs[1].reason
    assert jobs[4].reason == "missing artifact"
    assert jobs[3].audit_id == ""
    assert jobs[3].output_saved_to == ""
    assert jobs[3].output_files == []
    assert jobs[3].result == {}
    assert jobs[3].lineage == {}


def test_optional_parser_skip_overrides_carried_prior_ok(tmp_path: Path, monkeypatch):
    from nexus.langgraph import tool_lane

    prior_ok = {
        "host": "windows",
        "tool": "deepbluecli",
        "purpose": "Security.evtx",
        "status": "OK",
        "audit_id": "old-audit",
        "output_saved_to": "old-output.csv",
        "lineage": {"version": "1.0"},
    }
    monkeypatch.setattr(tool_lane, "_prior_ledger_rows", lambda *_args: [prior_ok])
    jobs = [ToolJob(
        host="windows", tool="deepbluecli", argv=["deepbluecli"], purpose="Security.evtx",
    )]

    carried = tool_lane._settle_prior_rows(
        jobs, tmp_path, tmp_path / "extractions", carry_ok=True,
        only_tools=frozenset({"hayabusa"}),
    )

    assert carried == []
    assert len(jobs) == 1
    assert jobs[0].status == "SKIP"
    assert "operator policy" in jobs[0].reason
