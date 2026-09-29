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

from nexus.langgraph.tool_lane import _plan_single_artifact, is_host_evidence  # noqa: E402


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


def test_bitsparser_stages_a_repaired_copy_for_a_single_database(tmp_path, monkeypatch):
    """BitsParser returns 0 bytes on a raw dirty ESE db.

    The host-scan path already staged a repaired copy; the single-file path
    handed the tool the raw database (0-byte JSON) and once even the parent
    DIRECTORY (no output at all). It must stage the same repaired copy.
    """
    from nexus.langgraph import tool_lane as tl

    called: dict = {}

    def _fake_repair(work, *, db_name, log_bases):
        called["db_name"] = db_name
        called["log_bases"] = log_bases

    monkeypatch.setattr(tl, "_esentutl_repair", _fake_repair)
    f = _make(tmp_path, "qmgr.db", b"ese" * 32)
    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    bp = next(j for j in jobs if j.tool == "bitsparser")
    staged = Path(bp.argv[bp.argv.index("-i") + 1])
    assert staged.name == "qmgr.db"
    assert staged != f, "the raw database must not be handed to BitsParser"
    assert any(part.endswith("-workdir") for part in staged.parts)
    assert staged.is_file()
    assert "repaired copy" in bp.purpose
    assert called["db_name"] == "qmgr.db"
    assert called["log_bases"] == ("edb", "qmgr")
    assert bp.optional_output is True, (
        "BitsParser writes nothing when the queue holds no recoverable jobs - "
        "that is a SKIP with a reason, not a failure"
    )


def test_ese_reserve_and_checkpoint_are_skip_not_fail(tmp_path):
    d = tmp_path / "bits"
    d.mkdir()
    jrs = _make(d, "edbres00001.jrs", b"\x00" * 64)
    chk = _make(d, "edb.chk", b"\x00" * 64)
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
    f = _make(tmp_path, "Cache0000.bin", b"\x00" * 4096)
    assert is_host_evidence(f) is True
    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    assert [j.tool for j in jobs] == ["bmc-tools"]


def test_i30_routes_to_mftecmd_not_rbcmd(tmp_path):
    """`$I30` is an NTFS directory index, not a Recycle Bin record.

    The recycle prefix test (`$i*`) swallowed it: seven $I30 files went to
    rbcmd, wrote header-only CSVs that were recorded OK, and contributed zero
    indexed rows (CASE-4EFD5EB2, 2026-09-29). MFTECmd parses it.
    """
    f = _make(tmp_path, "$I30", b"\x00" * 64)
    assert is_host_evidence(f) is True
    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    assert [j.tool for j in jobs] == ["mftecmd"]


def test_recycle_i_records_still_route_to_rbcmd(tmp_path):
    f = _make(tmp_path, "$I2F4A1B.txt", b"\x01\x00" + b"\x00" * 64)
    jobs = _plan_single_artifact(f, tmp_path / "extractions")
    assert [j.tool for j in jobs] == ["rbcmd"]


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
    f = _make(tmp_path, "mystery.bin", b"\x00" * 32)
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
