"""D383 (2026-10-25): every job the lane plans is one the case-pipeline guard will run.

D381 and D382 were one class of defect: the planner and the guard each built their own idea of "this case's
evidence", and only the planner knew the lane's archive expansion, so T22's 15 Volatility jobs were planned and then
refused after the lane had run. Both now read ``case.evidence_roots``. This test plans each staged tiny case as the
lane plans it (its registered paths and their expansions; Windows jobs and memory jobs) with the guard's own roots
(``tools.windows._case_pipeline_roots``) and asserts nothing would be refused. No tool runs; the planner only stages
copies into the test's own extractions folder.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from nexus.case.evidence_roots import expansion_root, registered_evidence_paths
from nexus.config import settings
from nexus.langgraph import tool_lane as tl
from nexus.tools import windows

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "Docs" / "internal" / "eval" / "tiny-cases.yaml"
CASES = REPO / "cases"


def _staged_cases() -> list[tuple[str, str]]:
    if not MANIFEST.is_file():
        return []
    entries = (yaml.safe_load(MANIFEST.read_text(encoding="utf-8")) or {}).get("cases") or {}
    return sorted((tid, e["case_id"]) for tid, e in entries.items()
                  if e.get("case_id") and (CASES / e["case_id"]).is_dir())


@pytest.mark.parametrize("tid,case_id", _staged_cases() or [pytest.param("-", "-", marks=pytest.mark.skip(
    reason="the tiny cases are not on this host"))])
def test_every_planned_job_passes_the_guard(tid, case_id, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "cases_root", CASES)  # read-only: the guard resolves the real case
    case_dir = CASES / case_id
    expanded = expansion_root(case_dir)
    paths = [str(p) for p in registered_evidence_paths(case_dir)]
    if expanded.is_dir():
        paths += [str(p) for p in sorted(expanded.iterdir()) if p.is_dir()]
    extractions = tmp_path / "runs" / "RUN-PLAN-CHECK" / "extractions"
    jobs: list[tl.ToolJob] = []
    for path in paths:
        jobs += tl.plan_windows_triage(path, extractions)
    jobs += tl._memory_image_jobs(paths, extractions)
    jobs += tl._memory_vol3_jobs(paths, extractions)
    roots = [*(windows._case_pipeline_roots(case_id) or []), extractions]  # the lane adds the run's extractions
    refused = [(j.tool, j.purpose, why) for j, why in tl._guard_refusals(jobs, roots)]
    assert refused == [], f"{tid}: planned jobs the guard would refuse: {refused[:3]}"


def test_the_check_would_have_caught_d382(tmp_path, monkeypatch):
    """With the guard's old roots (the registered paths only, no archive expansion), T22's memory jobs are flagged."""
    cases = dict(_staged_cases())
    if "T22" not in cases or not expansion_root(CASES / cases["T22"]).is_dir():
        pytest.skip("T22's lane expansion is not on this host")
    case_dir = CASES / cases["T22"]
    paths = [str(p) for p in sorted(expansion_root(case_dir).iterdir()) if p.is_dir()]
    jobs = tl._memory_vol3_jobs(paths, tmp_path / "extractions")
    old_roots = [*registered_evidence_paths(case_dir), case_dir / "extractions", tmp_path / "extractions"]
    flagged = tl._guard_refusals(jobs, old_roots)
    assert jobs and len(flagged) == len(jobs)
