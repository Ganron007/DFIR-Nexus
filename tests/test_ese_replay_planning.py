"""D517: both BITS planners use staged log families and retain real preparation outcomes.

The inventory and database header are captured verbatim from T07. Only planning
executes: transaction companions are empty path placeholders, and subprocess
outcomes/state are control-plane mocks. No forensic event rows are authored.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from nexus.langgraph import tool_lane

FIXTURES = Path(__file__).parent / "fixtures"


def _plan_bits(tmp_path, monkeypatch, shape, *, replay_returncode=0):
    fixture = json.loads((FIXTURES / "d517_t07_ese_inventory.json").read_text(encoding="utf-8"))
    root = tmp_path / "C"
    (root / "Windows/System32").mkdir(parents=True)
    downloader = root / "ProgramData/Microsoft/Network/Downloader"
    downloader.mkdir(parents=True)
    for row in fixture["files"]:
        (downloader / Path(row["path"]).name).touch()
    database = downloader / "qmgr.db"
    database.write_bytes(bytes.fromhex(fixture["database_header_hex"]))
    calls = []
    error = (FIXTURES / "d517_t07_recovery_error.txt").read_text(encoding="utf-8").strip()

    def run(argv, **kwargs):
        assert argv[:2] == ["esentutl.exe", "/r"]
        calls.append((list(argv), kwargs))
        return subprocess.CompletedProcess(argv, replay_returncode, "", error if replay_returncode else "")

    monkeypatch.setattr(tool_lane.subprocess, "run", run)
    monkeypatch.setattr(tool_lane, "_ese_state", lambda _: "Dirty Shutdown")
    monkeypatch.setattr(tool_lane, "_windows_tool_available", lambda _: True)
    extractions = tmp_path / "extractions"
    if shape == "loose":
        jobs = tool_lane._plan_single_artifact(database, extractions)
    else:
        jobs = tool_lane.plan_windows_triage(str(root), extractions)
    job = next(job for job in jobs if job.tool == "bitsparser" and job.status == "PENDING")
    assert database.read_bytes() == bytes.fromhex(fixture["database_header_hex"])
    return job, calls, error


@pytest.mark.parametrize("shape", ["loose", "drive"])
def test_bits_replays_only_the_staged_transaction_family(tmp_path, monkeypatch, shape):
    job, calls, _ = _plan_bits(tmp_path, monkeypatch, shape)
    assert [argv[2] for argv, _ in calls] == ["edb"]
    assert job.preflight["esentutl_replay"] == [
        {"log_base": "edb", "returncode": 0, "stdout": "", "stderr": ""}
    ]
    assert job.preflight["state_after_replay"] == "Dirty Shutdown"
    assert "replay completed" in job.purpose
    assert "Clean Shutdown" not in job.purpose
    staged = Path(job.argv[job.argv.index("-i") + 1])
    assert staged.is_file() and "--carvedb" in job.argv
    for argv, kwargs in calls:
        assert argv[3:] == [f"/l{staged.parent}", f"/s{staged.parent}", f"/d{staged.parent}"]
        assert kwargs["cwd"] == str(staged.parent)
        assert not {"/p", "/i", "/a", "/t"}.intersection(argv)


@pytest.mark.parametrize("shape", ["loose", "drive"])
def test_bits_preserves_failed_preparation_without_claiming_replay(tmp_path, monkeypatch, shape):
    job, calls, error = _plan_bits(tmp_path, monkeypatch, shape, replay_returncode=4294966293)
    assert [argv[2] for argv, _ in calls] == ["edb"]
    assert job.preflight["esentutl_replay"] == [
        {"log_base": "edb", "returncode": 4294966293, "stdout": "", "stderr": error}
    ]
    assert job.preflight["state_after_replay"] == "Dirty Shutdown"
    assert "replay incomplete" in job.purpose
    assert "logs replayed" not in job.purpose


def test_no_transaction_logs_does_not_attempt_recovery(tmp_path, monkeypatch):
    """Use the captured reserve/checkpoint/temp names; none is a replay family."""
    fixture = json.loads((FIXTURES / "d517_t07_ese_inventory.json").read_text(encoding="utf-8"))
    names = {Path(row["path"]).name for row in fixture["files"]}
    for name in ("edb.chk", "edbres00001.jrs", "edbtmp.log", "qmgr.db", "qmgr.jfm"):
        assert name in names
        (tmp_path / name).touch()

    def unexpected(*args, **kwargs):
        raise AssertionError("No transaction log is present")

    monkeypatch.setattr(tool_lane.subprocess, "run", unexpected)
    monkeypatch.setattr(tool_lane, "_ese_state", lambda _: "Dirty Shutdown")
    preflight = tool_lane._ese_preflight(tmp_path, tmp_path / "qmgr.db")
    assert preflight == {"esentutl_replay": [], "state_after_replay": "Dirty Shutdown"}
    assert "no transaction logs available" in tool_lane._ese_preparation_note(preflight)


@pytest.mark.parametrize("filename", ["edb00005.log", "EDB00100000.LOG", "edb00005.jtx"])
def test_archived_transaction_names_identify_their_family_without_an_active_log(tmp_path, monkeypatch, filename):
    """Metadata-only cases: captured five-digit name and Microsoft's documented naming variants.

    https://learn.microsoft.com/en-us/windows/win32/extensible-storage-engine/extensible-storage-engine-files
    """
    (tmp_path / filename).touch()
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(tool_lane.subprocess, "run", run)
    outcomes = tool_lane._esentutl_replay(tmp_path)
    assert [argv[2] for argv in calls] == ["edb"]
    assert outcomes == [{"log_base": "edb", "returncode": 0, "stdout": "", "stderr": ""}]


def test_launch_failure_is_retained_in_preflight_and_report(tmp_path, monkeypatch):
    (tmp_path / "edb.log").touch()

    def unavailable(*args, **kwargs):
        raise FileNotFoundError("esentutl.exe")

    monkeypatch.setattr(tool_lane.subprocess, "run", unavailable)
    preflight = tool_lane._ese_preflight(tmp_path, tmp_path / "qmgr.db")
    assert preflight["esentutl_replay"] == [{"log_base": "edb", "error": "esentutl.exe"}]
    assert preflight["state_after_replay"] == ""
    assert "replay incomplete" in tool_lane._ese_preparation_note(preflight)
    assert "state unreadable" in tool_lane._ese_preparation_note(preflight)
