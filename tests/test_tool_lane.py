"""Deterministic tool-lane planner tests (no MCP required)."""

from pathlib import Path

from nexus.langgraph.tool_lane import find_windows_root, plan_sift_triage, plan_windows_triage


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
