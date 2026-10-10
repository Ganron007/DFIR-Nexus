"""WO-TA item 5: the Defender, WMI, Search, transcript, WER and Outlook jobs.

These tests pin the command each job is planned with and the honest skip when
its precondition is missing. They run the real planner on a small directory tree
that has the artifact paths; tool presence is patched, and nothing is executed.
The real-path proof is the run of each binary on the operator's triage (see the
work order), not these tests.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from nexus.langgraph import tool_lane
from nexus.langgraph.tool_lane import _unique_name


def _touch(path: Path, text: str = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def triage(tmp_path: Path) -> Path:
    root = tmp_path / "C"
    _touch(root / "ProgramData/Microsoft/Windows Defender/Support/MPLog-20230121-192504.log")
    _touch(root / "ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory/00/ABC")
    _touch(root / "ProgramData/Microsoft/Windows Defender/Quarantine/Entries/QE1")
    _touch(root / "Windows/System32/wbem/Repository/OBJECTS.DATA", "obj")
    _touch(root / "ProgramData/Microsoft/Search/Data/Applications/Windows/Windows.edb", "edb")
    _touch(root / "ProgramData/Microsoft/Search/Data/Applications/Windows/edb.jtx", "log")
    _touch(root / "ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_x/Report.wer", "Version=1")
    _touch(root / "Users/alice/Documents/PowerShell/PowerShell_transcript.HOST.abc.20230117.txt", "t")
    _touch(root / "Users/alice/AppData/Local/Microsoft/Outlook/alice@corp.ost", "ost")
    return root


@pytest.fixture
def planned(triage, tmp_path, monkeypatch):
    """Run the planner with the lane elevated; tool presence is the caller's add_installed."""
    monkeypatch.setattr(tool_lane, "_is_elevated", lambda: True)
    extractions = tmp_path / "extractions"
    jobs: list = []

    def add_installed(key, argv, purpose, timeout=600):
        jobs.append(tool_lane.ToolJob(host="windows", tool=key, argv=argv,
                                      purpose=purpose, timeout=timeout))

    def skip(tool, reason):
        jobs.append(tool_lane.ToolJob(host="windows", tool=tool, argv=[], purpose="",
                                      status="SKIP", reason=reason))

    def blocked(tool, reason):
        jobs.append(tool_lane.ToolJob(host="windows", tool=tool, argv=[], purpose="",
                                      status="BLOCKED", reason=reason))

    tool_lane._plan_defender_and_search(triage, extractions, add_installed, skip, blocked)
    return jobs, extractions


def _job(jobs, tool):
    return next(j for j in jobs if j.tool == tool and j.status == "PENDING")


def test_mplog_reads_the_support_folder_and_writes_its_own_family(planned, triage):
    jobs, extractions = planned
    job = _job(jobs, "mplog")
    assert job.argv[:4] == ["mplog", "-d", str(triage / "ProgramData/Microsoft/Windows Defender/Support"), "-o"]
    assert Path(job.argv[4]) == extractions / "mplog"


def test_dhparser_is_recursive_over_detection_history(planned, triage):
    jobs, extractions = planned
    job = _job(jobs, "dhparser")
    assert job.argv[0] == "dhparser" and "-r" in job.argv
    assert Path(job.argv[job.argv.index("-o") + 1]) == extractions / "defender_detectionhistory"


def test_maldump_is_metadata_only_and_runs_on_the_os_root(planned, triage):
    jobs, _ = planned
    job = _job(jobs, "maldump")
    assert job.argv[:2] == ["maldump", str(triage)]
    assert "-m" in job.argv and "-q" not in job.argv and "-a" not in job.argv


def test_maldump_is_blocked_with_a_reason_when_not_elevated(triage, tmp_path, monkeypatch):
    monkeypatch.setattr(tool_lane, "_windows_tool_available", lambda key: True)
    monkeypatch.setattr(tool_lane, "_is_elevated", lambda: False)
    jobs: list = []
    tool_lane._plan_defender_and_search(
        triage, tmp_path / "e",
        lambda key, argv, purpose, timeout=600: jobs.append((key, argv)),
        lambda tool, reason: jobs.append(("SKIP", tool, reason)),
        lambda tool, reason: jobs.append(("BLOCKED", tool, reason)),
    )
    # Quarantine is present but unreadable: BLOCKED (the gate counts it), never SKIP.
    assert ("BLOCKED", "maldump",
            "Defender quarantine present, but this lane is not elevated: "
            "maldump needs Administrator rights and was not run") in jobs
    assert not any(entry[0] == "SKIP" and entry[1] == "maldump" for entry in jobs)


def test_a_missing_parser_on_present_evidence_is_blocked_not_skipped(triage, tmp_path, monkeypatch):
    monkeypatch.setattr(tool_lane, "_is_elevated", lambda: True)
    monkeypatch.setattr(tool_lane, "_windows_tool_available", lambda key: key != "mplog")
    blocked: dict[str, str] = {}
    tool_lane._plan_defender_and_search(
        triage, tmp_path / "e",
        lambda key, argv, purpose, timeout=600: None,
        lambda tool, reason: None,
        lambda tool, reason: blocked.setdefault(tool, reason),
    )
    assert "mplog" in blocked and "not installed" in blocked["mplog"]


def test_wmi_parser_reads_the_repository_file_in_place(planned, triage):
    jobs, extractions = planned
    job = _job(jobs, "wmi-parser")
    assert job.argv[:2] == ["wmi-parser", "-i"]
    assert Path(job.argv[2]) == triage / "Windows/System32/wbem/Repository/OBJECTS.DATA"
    assert Path(job.argv[job.argv.index("-o") + 1]) == extractions / "wmi_parser"


def test_sidr_runs_on_a_repaired_copy_not_the_dirty_original(planned, triage, tmp_path):
    jobs, extractions = planned
    job = _job(jobs, "sidr")
    work = Path(job.argv[-1])
    assert work == extractions / "sidr" / "workdir"
    assert (work / "Windows.edb").is_file()
    assert Path(job.argv[job.argv.index("-o") + 1]) == extractions / "sidr"
    assert str(triage) not in " ".join(job.argv)


def test_transcripts_are_copied_from_anywhere_under_the_volume(planned):
    _, extractions = planned
    copied = list((extractions / "pstranscript").iterdir())
    assert len(copied) == 1
    assert copied[0].name.endswith(".txt") and "PowerShell_transcript" in copied[0].name


def test_wer_reports_are_copied_as_text_the_indexer_reads(planned):
    _, extractions = planned
    copied = list((extractions / "wer").iterdir())
    assert len(copied) == 1
    assert copied[0].name.endswith(".wer.txt")


def test_outlook_store_is_parsed_by_default_with_no_size_cap(planned, triage):
    jobs, extractions = planned
    job = _job(jobs, "pff-ost")
    assert job.argv[1] == str(triage / "Users/alice/AppData/Local/Microsoft/Outlook/alice@corp.ost")
    assert Path(job.argv[2]).parent == extractions / "email"
    assert Path(job.argv[2]).suffix == ".csv"


def test_absent_artifacts_are_named_skips(tmp_path):
    empty = tmp_path / "C"
    empty.mkdir()
    reasons: dict[str, str] = {}
    tool_lane._plan_defender_and_search(
        empty, tmp_path / "e",
        lambda *a, **k: None,
        lambda tool, reason: reasons.setdefault(tool, reason),
        lambda tool, reason: reasons.setdefault(tool, reason),
    )
    for tool in ("mplog", "dhparser", "maldump", "wmi-parser", "sidr", "pstranscript", "wer", "pff-ost"):
        assert reasons.get(tool), tool


def test_memory_image_gets_one_memprocfs_job_read_in_place(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_lane, "_MEMORY_MIN_BYTES", 4)
    monkeypatch.setattr(tool_lane, "_windows_tool_available", lambda key: key == "memprocfs")
    image = _touch(tmp_path / "evidence" / "rd01-memory.img", "MEMORYIMAGE")
    notes = _touch(tmp_path / "evidence" / "notes.txt", "not memory")
    jobs = tool_lane._memory_image_jobs([str(image), str(notes)], tmp_path / "extractions")
    assert len(jobs) == 1
    job = jobs[0]
    assert job.tool == "memprocfs" and job.status == "PENDING"
    assert job.argv[:3] == ["memprocfs", "--image", str(image)]
    assert Path(job.argv[4]).parent == tmp_path / "extractions" / "memprocfs"
    assert image.read_text(encoding="utf-8") == "MEMORYIMAGE"


def test_memory_image_without_the_tool_is_a_named_skip(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_lane, "_MEMORY_MIN_BYTES", 4)
    monkeypatch.setattr(tool_lane, "_windows_tool_available", lambda key: False)
    image = _touch(tmp_path / "rd01-memory.raw", "MEMORYIMAGE")
    (job,) = tool_lane._memory_image_jobs([str(image)], tmp_path / "e")
    assert job.status == "SKIP" and "memprocfs not installed" in job.reason


def test_unique_name_keeps_same_named_files_apart(tmp_path):
    a = tmp_path / "hostA" / "parsed.csv"
    b = tmp_path / "hostB" / "parsed.csv"
    assert _unique_name(a) != _unique_name(b)
    assert _unique_name(a).endswith(".csv") and _unique_name(a).startswith("hostA-parsed-")
    assert _unique_name(a) == _unique_name(a)
