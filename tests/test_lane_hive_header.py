"""D279, D280: a hive or a mail store registered under a name of its own is still parsed (2026-10-18).

Sample S09 registers its hives as ``NTUSER.DAT_clean``, ``SOFTWARE_clean`` and ``SYSTEM_clean`` and its mail as three
loose ``.ost`` stores; the lane recognised hives by name and mail stores only under a drive tree's Users folder, so all
six went to the importer pass and were not read. The fixtures are the first 512 bytes of S09's files, verbatim, and of
a real ``SYSTEM.LOG1`` transaction log, which carries the hive signature and must not be taken for a hive.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from nexus.langgraph import tool_lane as tl

FIXTURES = Path(__file__).parent / "fixtures"


def _batches(monkeypatch, tmp_path):
    monkeypatch.setattr(tl, "_find_recmd_batch", lambda: tmp_path / "kroll.reb")
    monkeypatch.setattr(tl, "_find_recmd_user_batch", lambda: tmp_path / "user.reb")


def _by_tool(jobs):
    return {j.tool: j for j in jobs if j.status == "PENDING"}


def test_a_hive_is_known_by_its_base_block_and_its_kind_by_the_name_it_records(tmp_path):
    reg = tmp_path / "Registry"
    shutil.copytree(FIXTURES / "d279_hives", reg)
    assert [tl._hive_kind(reg / n) for n in ("SYSTEM_clean", "SOFTWARE_clean", "NTUSER.DAT_clean")] == [
        "system", "software", "ntuser"]
    assert tl._hive_kind(reg / "SYSTEM.LOG1") == "", "a transaction log is not a hive"
    assert all(tl.is_host_evidence(reg / n) for n in ("SYSTEM_clean", "SOFTWARE_clean", "NTUSER.DAT_clean"))


def test_an_exported_hive_gets_the_jobs_its_kind_gets(tmp_path, monkeypatch):
    _batches(monkeypatch, tmp_path)
    reg = tmp_path / "Registry"
    shutil.copytree(FIXTURES / "d279_hives", reg)
    system = _by_tool(tl._plan_single_artifact(reg / "SYSTEM_clean", tmp_path / "x"))
    assert system["recmd"].argv[system["recmd"].argv.index("--bn") + 1] == str(tmp_path / "kroll.reb")
    assert "appcompatcacheparser" in system, "SYSTEM_clean needs the Shimcache parse as much as SYSTEM does"
    user = _by_tool(tl._plan_single_artifact(reg / "NTUSER.DAT_clean", tmp_path / "x"))
    assert user["recmd"].argv[user["recmd"].argv.index("--bn") + 1] == str(tmp_path / "user.reb")
    assert "recmd" not in _by_tool(tl._plan_single_artifact(reg / "SYSTEM.LOG1", tmp_path / "x"))


def test_a_folder_of_exported_hives_is_dispatched_hive_by_hive(tmp_path, monkeypatch):
    _batches(monkeypatch, tmp_path)
    reg = tmp_path / "Registry"
    shutil.copytree(FIXTURES / "d279_hives", reg)
    jobs = [j for j in tl._plan_single_artifact(reg, tmp_path / "x") if j.tool == "recmd" and j.status == "PENDING"]
    assert sorted(Path(j.argv[j.argv.index("-f") + 1]).name for j in jobs) == [
        "NTUSER.DAT_clean", "SOFTWARE_clean", "SYSTEM_clean"]


def test_a_mail_store_registered_on_its_own_is_parsed(tmp_path, monkeypatch):
    monkeypatch.setattr(tl, "_windows_tool_available", lambda key: key == "pff-ost")
    ost = tmp_path / "Email" / "mailbox.ost"
    ost.parent.mkdir()
    shutil.copy(FIXTURES / "d280_mailbox.ost", ost)
    assert tl.is_host_evidence(ost), "the importer pass has no reader for a mail store"
    job = _by_tool(tl._plan_single_artifact(ost, tmp_path / "x"))["pff-ost"]
    assert job.argv[1] == str(ost) and Path(job.argv[2]).parent == tmp_path / "x" / "email"
    monkeypatch.setattr(tl, "_windows_tool_available", lambda key: False)
    [blocked] = tl._plan_single_artifact(ost, tmp_path / "x")
    assert (blocked.tool, blocked.status) == ("pff-ost", "BLOCKED")
