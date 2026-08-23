"""Deterministic tool-lane planner tests (no MCP required)."""

from pathlib import Path

from nexus.langgraph.tool_lane import (
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
    assert "suzaku" in tools


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
    assert "suzaku" in pending
    assert "evtxecmd" in pending
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


def test_plan_sift_requires_root(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_TRIAGE_ROOT", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_SKIP_PLASO", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_PLASO", raising=False)
    jobs = plan_sift_triage("")
    assert jobs[0].status == "SKIP"
    jobs2 = plan_sift_triage("/home/sansforensics/Evidence-files/pack")
    assert any(j.tool == "vol" and j.status == "PENDING" for j in jobs2)
    assert not any(j.tool == "fls" for j in jobs2)
    assert not any(j.tool == "log2timeline" and j.status == "PENDING" for j in jobs2)


def test_plan_sift_no_full_tree_plaso(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_SKIP_PLASO", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_PLASO", raising=False)
    jobs = plan_sift_triage(
        "/home/sansforensics/Evidence-files/pack",
        triage_root="/mnt/windows_mount/C",
    )
    tools = {j.tool for j in jobs if j.status == "PENDING"}
    assert "vol" in tools
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
        "nexus.langgraph.tool_lane._esentutl_repair",
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
    assert "logfileparser" not in pending
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
    jobs = sift_jobs_for_lane("/evidence/pack", has_sift_mcp=True)
    assert any(j.tool == "vol" and j.status == "PENDING" for j in jobs)


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


def test_bitsparser_stages_repaired_copy(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(
        "nexus.langgraph.tool_lane._windows_tool_available",
        lambda key: key == "bitsparser",
    )
    called: dict = {}

    def _fake_repair(work, *, db_name, log_bases):
        called["work"] = work
        called["db_name"] = db_name
        called["log_bases"] = log_bases

    monkeypatch.setattr(
        "nexus.langgraph.tool_lane._esentutl_repair",
        _fake_repair,
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
    assert "repaired copy" in bp.purpose
    assert "--carveall" not in bp.argv
    assert called["db_name"] == "qmgr.db"
    assert called["log_bases"] == ("edb", "qmgr")


def test_apply_prior_ok_reuses_matching_purpose(tmp_path: Path, monkeypatch):
    from nexus.langgraph.tool_lane import ToolJob, apply_prior_ok

    monkeypatch.delenv("NEXUS_TOOL_LANE_RERUN", raising=False)
    ext = tmp_path / "extractions"
    ext.mkdir()
    (ext / "_tool_lane_ledger.json").write_text(
        '[{"host":"windows","tool":"hayabusa","purpose":"Hayabusa EVTX",'
        '"status":"OK","audit_id":"a1","argv":["hayabusa","-d","old"]}]',
        encoding="utf-8",
    )
    jobs = [
        ToolJob(host="windows", tool="hayabusa", argv=["hayabusa", "-d", "new"], purpose="Hayabusa EVTX"),
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


def test_plan_sift_memory_file_overrides_default(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_MEMORY_FILE", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_PLASO", raising=False)
    jobs = plan_sift_triage(
        "/mnt/srl_rd01",
        memory_file="/mnt/srl_rd01/memory/rd01-memory.img",
    )
    vol = next(j for j in jobs if j.tool == "vol")
    assert "/mnt/srl_rd01/memory/rd01-memory.img" in vol.argv
    assert "Rocba-Memory.raw" not in vol.argv


def test_plan_sift_rocba_root_keeps_rocba_dump(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_MEMORY_FILE", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_PLASO", raising=False)
    jobs = plan_sift_triage("/home/sansforensics/Evidence-files/rocba-500")
    vol = next(j for j in jobs if j.tool == "vol")
    assert any("Rocba-Memory.raw" in a for a in vol.argv)


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
