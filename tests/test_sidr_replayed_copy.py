"""sidr runs on a replayed copy of the Windows Search database, and only on a clean one (2026-10-11).

The earlier block assumed the database needed a repair. A replay is enough when the log generations are
complete: on CASE-C5B04D31 the replay reached a clean shutdown on a copy, and sidr then wrote its three
CSV reports. The planner stages the copy, replays it, reads the state (read only), and plans sidr only
when that state is Clean Shutdown. No repair (/p) and no ignored logs (/i) are ever used.
"""

from __future__ import annotations

import subprocess

import pytest


@pytest.fixture()
def search_volume(tmp_path):
    root = tmp_path / "C"
    (root / "Windows" / "System32").mkdir(parents=True)  # the planner needs a Windows root
    search = root / "ProgramData" / "Microsoft" / "Search" / "Data" / "Applications" / "Windows"
    search.mkdir(parents=True)
    (search / "Windows.edb").write_bytes(b"ese" * 100)
    (search / "edb.jtx").write_bytes(b"log")
    (search / "edb00060.jtx").write_bytes(b"log")
    (search / "GatherLogs").mkdir()
    extractions = tmp_path / "extractions"
    extractions.mkdir()
    return root, extractions


def _sidr_jobs(root, extractions, monkeypatch, state: str):
    from nexus.langgraph import tool_lane

    replayed: list[tuple[str, tuple[str, ...]]] = []
    monkeypatch.setattr(
        tool_lane, "_esentutl_replay",
        lambda work, *, log_bases: replayed.append((work.name, tuple(log_bases))),
    )
    monkeypatch.setattr(tool_lane, "_ese_state", lambda database: state)
    jobs = tool_lane.plan_windows_triage(str(root), extractions)
    return [j for j in jobs if j.tool == "sidr"], replayed


def test_sidr_is_planned_on_the_replayed_copy_when_the_database_is_clean(search_volume, monkeypatch):
    root, extractions = search_volume
    sidr, replayed = _sidr_jobs(root, extractions, monkeypatch, "Clean Shutdown")
    assert len(sidr) == 1 and sidr[0].status == "PENDING"
    work = extractions / "sidr" / "workdir"
    assert list(sidr[0].argv) == ["sidr", "-f", "csv", "-o", str(extractions / "sidr"), str(work)]
    assert (work / "Windows.edb").is_file() and (work / "edb00060.jtx").is_file()
    assert not (work / "GatherLogs").exists()
    assert replayed == [("workdir", ("edb",))]


def test_sidr_is_blocked_when_the_replay_does_not_reach_a_clean_shutdown(search_volume, monkeypatch):
    root, extractions = search_volume
    sidr, _ = _sidr_jobs(root, extractions, monkeypatch, "Dirty Shutdown")
    assert len(sidr) == 1 and sidr[0].status == "BLOCKED" and not sidr[0].argv
    assert "Dirty Shutdown" in sidr[0].reason and "sidr is not run on it" in sidr[0].reason


def test_the_state_is_read_from_the_database_header(tmp_path, monkeypatch):
    from nexus.langgraph import tool_lane

    header = "DATABASE HEADER:\n        File Type: Database\n            State: Clean Shutdown\n"
    seen: list[list[str]] = []

    def fake_run(argv, **kwargs):
        seen.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, header, "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert tool_lane._ese_state(tmp_path / "Windows.edb") == "Clean Shutdown"
    assert seen[0][:2] == ["esentutl.exe", "/mh"]  # read only: the header dump, never /r, /p or /i


def test_an_unreadable_database_has_no_state(tmp_path, monkeypatch):
    from nexus.langgraph import tool_lane

    def boom(argv, **kwargs):
        raise OSError("esentutl missing")

    monkeypatch.setattr(subprocess, "run", boom)
    assert tool_lane._ese_state(tmp_path / "Windows.edb") == ""
