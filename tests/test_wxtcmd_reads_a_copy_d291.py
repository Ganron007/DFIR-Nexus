"""D291: WxTCmd reads a staged copy of the Timeline database, and the evidence keeps its log files (2026-10-18).

WxTCmd deletes the -wal and -shm files of the ActivitiesCache.db it opens, and the lane gave it the evidence path.
The test copies a real database with its companions (the ES-Mapping evidence folder) to a temporary "evidence"
folder, plans the job, runs it as planned, and checks the "evidence" byte for byte afterwards. It skips where the
database or the tool is absent.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from nexus.langgraph import tool_lane as tl

REPO = Path(__file__).resolve().parents[1]
REAL = REPO / "Evidence-files" / "ES-Mapping" / "evidence" / "activitiescache" / "AAD.d1a7c039-6175-4ddb-bcdb-a8de45cf1678"


def _state(folder: Path) -> dict[str, str]:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in folder.iterdir() if p.is_file()}


@pytest.mark.skipif(not (REAL / "ActivitiesCache.db-shm").is_file(), reason="the real Timeline database is not here")
def test_wxtcmd_is_planned_on_a_copy_and_the_evidence_is_unchanged(tmp_path):
    evidence = tmp_path / "evidence" / "AAD"
    shutil.copytree(REAL, evidence)
    before = _state(evidence)
    db = evidence / "ActivitiesCache.db"
    [job] = [j for j in tl._plan_single_artifact(db, tmp_path / "x") if j.tool == "wxtcmd"]
    staged = Path(job.argv[job.argv.index("-f") + 1])
    assert staged.is_relative_to(tmp_path / "x" / "_staged") and job.source == str(db)
    assert {p.name for p in staged.parent.iterdir()} == set(before), "the copy carries the log files"
    exe = tl._windows_tool_path("wxtcmd")
    if not exe:
        pytest.skip("WxTCmd is not installed here")
    proc = subprocess.run([exe, *job.argv[1:]], capture_output=True, text=True, timeout=600)
    assert proc.returncode == 0, proc.stdout[-400:]
    assert _state(evidence) == before, "the evidence keeps its -wal and -shm, byte for byte"
    assert list((tmp_path / "x" / "wxtcmd").rglob("*.csv")), "WxTCmd wrote its output from the copy"
