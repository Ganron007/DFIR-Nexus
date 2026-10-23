"""Formats the lane can parse must not be routed nowhere.

Debug-mode sweep finding: five of ten formats produced a single
``(discovery) SKIP — No recognized evidence shape`` row and no parser job at all,
so the evidence was registered, hashed, and then never processed, while the run
still reported ``complete``. Thumbnail caches, RDP bitmap caches, SRUM, setupapi
logs and dropped executables all have tools in the catalog; the recogniser simply
did not know about them.
"""
from __future__ import annotations

from pathlib import Path

from nexus.langgraph.tool_lane import (  # noqa: E402
    ToolJob,
    _mark_dirty_registry_hive_warnings,
    _plan_single_artifact,
    is_host_evidence,
)


def _make(tmp_path: Path, name: str, data: bytes = b"\x00\x01") -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_thumbcache_file_is_recognised_and_parsed(tmp_path):
    f = _make(tmp_path, "thumbcache_256.db")
    assert is_host_evidence(f) is True
    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    assert [j.tool for j in jobs] == ["thumbcache_viewer"]


def test_thumbcache_argv_matches_the_real_tool_interface(tmp_path):
    """thumbcache_viewer_cmd is not a Zimmerman CSV tool.

    Passing --csv/--csvf to it makes it print its usage banner and exit 0: ten
    OK ledger rows, zero evidence. It needs -o <dir> and -c for the CSV.
    """
    f = _make(tmp_path, "thumbcache_96.db")
    job = _plan_single_artifact(f, tmp_path / "extractions")[0]
    argv = job.argv
    assert "--csv" not in argv and "--csvf" not in argv
    assert "-o" in argv, "no report directory given"
    assert "-c" in argv, "CSV switch missing — the tool would print usage and exit 0"
    # `-t` loads a single database file. `-d` loads a DIRECTORY of databases -
    # passing a file with -d made the tool open nothing and exit 0 with no
    # output (found on iconcache_16.db, CASE-BC13CCC9, 2026-09-29).
    assert "-t" in argv, "single-file flag missing - the tool opens nothing with -d"
    assert "-d" not in argv
    assert argv[argv.index("-t") + 1] == str(f)


def test_defender_support_logs_are_planned_not_dropped(tmp_path):
    """17 of 20 files on CASE-BC13CCC9 were dropped before this existed.

    Defender support logs, BITS ESE companions and WPP traces had no parser
    and were not recognised as host evidence, so they were never planned and
    never read - no job, no SKIP row. Text logs get ONE pass; a `-u` pass over
    ASCII text extracts nothing and the honest output check would fail it.
    Binary containers get both encodings.
    """
    d = tmp_path / "defender" / "Support"
    d.mkdir(parents=True)
    log = _make(d, "MPLog-20201020-091428.log", b"defender log line\n")
    wpp = _make(d, "MpWppTracing-20201111-031319.bin", b"W\x00i\x00d\x00e\x00" * 8)
    assert is_host_evidence(log) is True
    assert is_host_evidence(wpp) is True
    text_jobs = _plan_single_artifact(log, tmp_path / "extractions")
    assert [j.tool for j in text_jobs] == ["strings"]
    assert "-u" not in text_jobs[0].argv, "a wide-char pass over ASCII text yields nothing"
    bin_jobs = _plan_single_artifact(wpp, tmp_path / "extractions")
    assert [j.tool for j in bin_jobs] == ["strings", "strings"]
    assert any("-u" in j.argv for j in bin_jobs), "binary container misses the utf16 pass"


def test_tiny_staged_artifact_is_skip_not_fail(tmp_path):
    d = tmp_path / "defender" / "Scans-History-Service"
    d.mkdir(parents=True)
    tiny = _make(d, "History.Log", b"\r\n")
    jobs = _plan_single_artifact(tiny, tmp_path / "extractions")
    assert jobs and all(j.status == "SKIP" for j in jobs)
    assert "nothing to extract" in jobs[0].reason


def test_bits_ese_companions_are_planned_not_dropped(tmp_path):
    d = tmp_path / "bits"
    d.mkdir()
    edb = _make(d, "edb.log", b"\x00\x01ese")
    jfm = _make(d, "qmgr.jfm", b"\x00\x01")
    assert is_host_evidence(edb) is True
    assert is_host_evidence(jfm) is True
    jobs = _plan_single_artifact(edb, tmp_path / "extractions")
    assert jobs and all(j.tool == "strings" for j in jobs)


def test_bitsparser_stages_a_staged_copy_for_a_single_database(tmp_path, monkeypatch):
    """BitsParser returns 0 bytes on a raw dirty ESE db.

    The host-scan path already staged a repaired copy; the single-file path
    handed the tool the raw database (0-byte JSON) and once even the parent
    DIRECTORY (no output at all). It must stage the same repaired copy.
    """
    from nexus.langgraph import tool_lane as tl

    called: dict = {}

    def _fake_replay(work, *, log_bases):
        called["work"] = work
        called["log_bases"] = log_bases

    monkeypatch.setattr(tl, "_esentutl_replay", _fake_replay)
    f = _make(tmp_path, "qmgr.db", b"ese" * 32)
    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    bp = next(j for j in jobs if j.tool == "bitsparser")
    staged = Path(bp.argv[bp.argv.index("-i") + 1])
    assert staged.name == "qmgr.db"
    assert staged != f, "the raw database must not be handed to BitsParser"
    assert any(part.endswith("-workdir") for part in staged.parts)
    assert staged.is_file()
    assert "staged copy" in bp.purpose and "repaired" not in bp.purpose
    assert Path(called["work"]) == staged.parent
    assert called["log_bases"] == ("edb", "qmgr")
    assert "--carvedb" in bp.argv
    assert "--carveall" not in bp.argv
    assert bp.optional_output is False


def test_amcacheparser_stages_dirty_hive_and_warns_without_logs(tmp_path):
    hive = _make(
        tmp_path,
        "Amcache.hve",
        b"regf" + (7).to_bytes(4, "little") + (6).to_bytes(4, "little"),
    )
    jobs = _plan_single_artifact(hive, tmp_path / "extractions")
    job = next(j for j in jobs if j.tool == "amcacheparser")
    staged = Path(job.argv[job.argv.index("-f") + 1])

    assert staged != hive and staged.is_file()
    assert staged.parent.name.endswith("-workdir")
    assert "--nl" in job.argv
    assert job.preflight["registry_hive"] == {
        "dirty": True,
        "transaction_logs": [],
        "dirty_without_logs": True,
    }

    job.status = "OK"
    ledger = [{"host": job.host, "tool": job.tool, "purpose": job.purpose, "source": job.source,
               "status": "OK"}]
    warned = _mark_dirty_registry_hive_warnings([job], ledger)
    expected = "dirty hive parsed without its transaction logs: changes held only in the logs are absent"
    assert warned == [job]
    assert job.status == "WARN" and job.reason == expected
    assert ledger[0]["status"] == "WARN" and ledger[0]["reason"] == expected


def test_amcacheparser_stages_its_matching_log_and_uses_default_replay(tmp_path):
    hive = _make(
        tmp_path,
        "Amcache.hve",
        b"regf" + (7).to_bytes(4, "little") + (6).to_bytes(4, "little"),
    )
    log = _make(tmp_path, "aMcache.hve.lOg2", b"transaction log")
    _make(tmp_path, "SYSTEM.LOG2", b"unrelated log")
    jobs = _plan_single_artifact(hive, tmp_path / "extractions")
    job = next(j for j in jobs if j.tool == "amcacheparser")
    staged = Path(job.argv[job.argv.index("-f") + 1])

    assert staged.is_file()
    assert (staged.parent / log.name).read_bytes() == log.read_bytes()
    assert "--nl" not in job.argv, "the parser should consume the staged transaction log"
    assert job.preflight["registry_hive"]["transaction_logs"] == [log.name]


def test_dirty_hive_warnings_match_each_ledger_row_by_source():
    details = {"dirty": True, "transaction_logs": [], "dirty_without_logs": True}
    jobs = [
        ToolJob(
            host="windows",
            tool="amcacheparser",
            argv=[],
            purpose="Amcache application execution",
            status="OK",
            source=f"C:/evidence/{name}",
            preflight={"registry_hive": details},
        )
        for name in ("one/Amcache.hve", "two/Amcache.hve")
    ]
    ledger = [
        {
            "host": job.host,
            "tool": job.tool,
            "purpose": job.purpose,
            "source": job.source,
            "status": "OK",
        }
        for job in jobs
    ]

    warned = _mark_dirty_registry_hive_warnings(jobs, ledger)

    assert warned == jobs
    assert [row["status"] for row in ledger] == ["WARN", "WARN"]


def test_ese_reserve_and_checkpoint_are_skip_not_fail(tmp_path):
    d = tmp_path / "bits"
    d.mkdir()
    jrs = _make(d, "edbres00001.jrs", b"\x01" + b"\x00" * 63)
    chk = _make(d, "edb.chk", b"\x01" + b"\x00" * 63)
    for f in (jrs, chk):
        assert is_host_evidence(f) is True
        jobs = _plan_single_artifact(f, tmp_path / "extractions")
        assert jobs and all(j.status == "SKIP" for j in jobs)
        assert "recoverable strings" in jobs[0].reason


def test_utf16_pass_only_when_wide_text_present(tmp_path):
    """A `-u` pass over data with no wide characters extracts nothing.

    Scheduling it anyway made the honest output check fail jobs that behaved
    correctly (qmgr.jfm, 2026-09-29). The probe decides from content.
    """
    d = tmp_path / "defender" / "Support"
    d.mkdir(parents=True)
    wide = _make(d, "MpWppTracing-20201111-031319.bin", b"W\x00i\x00d\x00e\x00" * 8)
    narrow = _make(d, "MpWppTracing-20201113-000000.bin", b"only ascii text here, no wide chars")
    narrow.write_bytes(b"\x01\x02\x03" * 40)
    jobs_wide = _plan_single_artifact(wide, tmp_path / "extractions")
    assert any("-u" in j.argv for j in jobs_wide)
    jobs_narrow = _plan_single_artifact(narrow, tmp_path / "extractions")
    assert jobs_narrow and not any("-u" in j.argv for j in jobs_narrow)


def test_iconcache_file_is_recognised(tmp_path):
    f = _make(tmp_path, "iconcache_32.db")
    assert is_host_evidence(f) is True
    assert _plan_single_artifact(f, tmp_path / "extractions")


def test_rdp_cache_bin_is_recognised(tmp_path):
    """bmc-tools reconstructs the bitmap tiles. I first routed this to strings
    believing the catalogue had no RDP parser; it ships bmc-tools, so the cache
    was being keyword-searched instead of reconstructed."""
    f = _make(tmp_path, "Cache0000.bin", b"\x01\x02" * 2048)
    assert is_host_evidence(f) is True
    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    assert [j.tool for j in jobs] == ["bmc-tools"]


def test_i30_routes_to_mftecmd_not_rbcmd(tmp_path):
    """`$I30` is an NTFS directory index, not a Recycle Bin record.

    The recycle prefix test (`$i*`) swallowed it: seven $I30 files went to
    rbcmd, wrote header-only CSVs that were recorded OK, and contributed zero
    indexed rows (CASE-4EFD5EB2, 2026-09-29). MFTECmd parses it.
    """
    f = _make(tmp_path, "$I30", b"INDX" + b"\x00" * 60)
    assert is_host_evidence(f) is True
    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    assert [j.tool for j in jobs] == ["mftecmd"]


def test_recycle_i_records_still_route_to_rbcmd(tmp_path):
    f = _make(tmp_path, "$I2F4A1B.txt", b"\x01\x00" + b"\x00" * 64)
    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    assert [j.tool for j in jobs] == ["rbcmd"]


def test_logfile_gets_a_real_job_not_a_skip(tmp_path, monkeypatch):
    """LogFileParser runs headless - the old "GUI-only" skip was wrong.

    Its readme documents the switches and the validated W1 run used them
    (/LogFileFile: /OutputPath: -> 139,496-row LogFile.csv). No-arg launches
    the GUI; that is what the earlier conclusion mistook.
    """
    from nexus.langgraph import tool_lane as tl

    monkeypatch.setattr(tl, "_windows_tool_available", lambda key: True)
    f = _make(tmp_path, "$LogFile", b"RSTR" + b"\x01" * 4096)
    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    assert [j.tool for j in jobs] == ["logfileparser"]
    argv = jobs[0].argv
    assert any(a.startswith("/LogFileFile:") for a in argv)
    assert any(a.startswith("/OutputPath:") for a in argv)
    assert jobs[0].optional_output is True


def test_all_zero_artifact_is_skipped_without_running_a_tool(tmp_path):
    """MFTECmd 2026.5.0 loops forever on an all-zero $I30.

    The file holds no evidence (0 non-zero bytes - verified next to a
    21.9%-non-zero twin that parses in under a second), so the honest outcome
    is a plan-time SKIP naming the emptiness. No parser is ever launched.
    """
    f = _make(tmp_path, "$I30", b"\x00" * 4096)
    assert is_host_evidence(f) is True
    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    assert jobs and all(j.status == "SKIP" for j in jobs)
    assert "zeros" in jobs[0].reason
    assert "mftecmd" not in {j.tool for j in jobs}


def test_outputpath_switch_directory_is_tracked(tmp_path):
    from nexus.langgraph.tool_lane import ToolJob, _output_dirs_of

    d = tmp_path / "out"
    d.mkdir()
    job = ToolJob(host="windows", tool="logfileparser",
                  argv=["logfileparser", "/LogFileFile:x", f"/OutputPath:{d}"],
                  purpose="p")
    assert d in _output_dirs_of(job)


def test_srum_db_is_recognised(tmp_path):
    f = _make(tmp_path, "SRUDB.dat")
    assert is_host_evidence(f) is True
    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    assert [j.tool for j in jobs] == ["srumecmd"]


def test_srum_is_staged_off_the_evidence_path(tmp_path):
    """SrumECmd refuses a live ESE database, so it must be handed a staged copy."""
    src = tmp_path / "srum"
    src.mkdir()
    db = src / "SRUDB.dat"
    db.write_bytes(b"ESE\x00")
    (src / "SRU.log").write_bytes(b"log")
    (src / "SRU00001.log").write_bytes(b"log1")

    jobs = _plan_single_artifact(db, tmp_path / "extractions")
    assert jobs, "no srum job planned"
    target = jobs[0].argv[jobs[0].argv.index("-f") + 1]
    assert target != str(db), "srumecmd was pointed at the live evidence file"
    staged = Path(target)
    assert staged.is_file(), "the staged SRUDB.dat does not exist"


def test_srum_skips_honestly_when_staging_fails(tmp_path, monkeypatch):
    """If the copy fails the lane must say SKIP + why, not plan a doomed job."""
    from nexus.langgraph import tool_lane as tl

    def boom(*_a, **_k):
        raise OSError("disk gone")

    monkeypatch.setattr(tl, "_copy_ese_siblings", boom)
    src = tmp_path / "srum"
    src.mkdir()
    db = src / "SRUDB.dat"
    db.write_bytes(b"ESE\x00")

    jobs = tl._plan_single_artifact(db, tmp_path / "extractions")
    assert len(jobs) == 1
    assert jobs[0].status == "SKIP"
    assert "staging failed" in jobs[0].reason
    assert jobs[0].argv == []


def test_setupapi_log_is_recognised(tmp_path):
    f = _make(tmp_path, "setupapi.dev.log", b"[Device Install]\n")
    assert is_host_evidence(f) is True


def test_dropped_exe_is_recognised_and_hashed(tmp_path):
    f = _make(tmp_path, "chrome.exe", b"MZ\x00\x00")
    assert is_host_evidence(f) is True
    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    assert [j.tool for j in jobs] == ["sigcheck"]


def test_format_folders_are_recognised(tmp_path):
    for folder, probe in (
        ("srum", "SRUDB.dat"),
        ("rdp", "Cache0000.bin"),
        ("setupapi", "setupapi.dev.log"),
        ("samples", "chrome.exe"),
    ):
        d = tmp_path / folder
        d.mkdir()
        _make(d, probe)
        assert is_host_evidence(d) is True, folder


def test_thumbcache_folder_is_recognised(tmp_path):
    d = tmp_path / "thumbcache"
    d.mkdir()
    _make(d, "thumbcache_96.db")
    assert is_host_evidence(d) is True


def test_unknown_binary_stays_unrouted(tmp_path):
    """Recognition must stay narrow: a random blob is not host evidence."""
    f = _make(tmp_path, "mystery.bin", b"\x01\x02\x03" * 16)
    assert is_host_evidence(f) is False
    assert _plan_single_artifact(f, tmp_path / "extractions") == []


def test_every_recognised_single_file_gets_a_job_or_a_honest_skip(tmp_path):
    """A recognised file must never fall through to 'no jobs planned'."""
    samples = [
        "thumbcache_256.db", "iconcache_16.db", "Cache0001.bin",
        "SRUDB.dat", "setupapi.dev.log", "dropped.exe",
        "A.EXE-1.pf", "link.lnk", "Amcache.hve",
    ]
    for name in samples:
        f = _make(tmp_path, name)
        if not is_host_evidence(f):
            continue
        jobs = _plan_single_artifact(f, tmp_path / "extractions")
        assert jobs, f"{name} recognised as host evidence but no parser scheduled"
        for j in jobs:
            assert j.status in {"PENDING", "SKIP"}
            if j.status == "SKIP":
                # A skip must say why - that is the difference between honest and silent.
                assert j.reason, f"{name}: SKIP with no reason"
