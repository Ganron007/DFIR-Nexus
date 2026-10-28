"""A run whose node failed is recorded failed, even when the graph went on to the approval interrupt.

T22-R1z3c Mode 1 (2026-10-28, run d4cc7f9b): the interpret loop failed and finalized the run `failed`; the graph
continued to `await_approval`, and the unfinished-run finaliser overwrote the record as "interrupted: awaiting
approval at await_approval" with nothing staged. The review read a failed run as a paused one.
"""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

ERROR = ("interpret: the interpret loop failed: RuntimeError: the orient reply could not be read as a plan "
         "(5976 chars, after one corrective retry); see analysis/interpret_rounds/round-0-orient.json")


class _Paused:
    """The compiled graph as it stood after that run: waiting on the approval node."""

    async def aget_state(self, cfg):
        return SimpleNamespace(next=("await_approval",))


@pytest.mark.parametrize(("error", "status"), [(ERROR, "failed"), ("", "interrupted")])
def test_a_node_error_decides_the_record_over_the_approval_pause(error, status):
    from nexus.config import settings
    from nexus.langgraph.llm_pipeline import _finalize_if_unfinished
    from nexus.langgraph.pipeline_runs import create_run

    case = settings.cases_root / "CASE-FAILED-RUN"
    case.mkdir(parents=True)
    run = create_run(case, mode="interpret")
    result = {"case_id": case.name, "run_id": run.run_id, "error": error,
              "draft_finding_ids": [] if error else ["F-1"]}
    asyncio.run(_finalize_if_unfinished({"case_id": case.name}, result, compiled=_Paused(), cfg={}))
    manifest = json.loads((run.path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == status
    if error:
        assert manifest["error"].startswith("interpret: the interpret loop failed")
    else:
        assert manifest["error"] == "awaiting approval at await_approval (1 DRAFT finding(s) staged)"
