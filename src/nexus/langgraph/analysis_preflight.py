"""One preflight for every analysis run (Modes 1, 2 and 3), on every surface.

Before this, the Mode 2 and Mode 3 CLIs checked the lane gate, the busy guard and the SIFT
preflight; `nexus interpret` (Mode 1) checked none of them; and the portal kept its own
copies. Every entry point now asks this module, so the CLIs and the portal cannot disagree
about whether a case may start an analysis run (D133).
"""
from __future__ import annotations

from pathlib import Path


def sift_blocks_analysis(case_dir: Path | str) -> str:
    """The SIFT refusal for an analysis run, or "".

    SIFT is an optional lane (operator, 2026-10-13). An analysis run reads the case's own
    index and never calls SIFT, so the host matters only while the lane still has work
    waiting on it. A finished case is analysed with the SIFT VM off (D141).
    """
    from nexus.case.sift_preflight import sift_preflight_message
    from nexus.langgraph.lane_gate import read_lane_gate

    if not (read_lane_gate(case_dir).get("waiting_sift") or []):
        return ""
    return sift_preflight_message(Path(case_dir))


def analysis_preflight(case_dir: Path | str, *, own_run_id: str = "") -> str:
    """Why an analysis run may not start on this case now, or "" when it may."""
    from nexus.langgraph.lane_gate import gate_message, lane_gate_blocked
    from nexus.langgraph.pipeline_runs import reap_dead_runs
    from nexus.modes.multi_role import busy_message, busy_runs

    case_dir = Path(case_dir)
    # A run left 'running' by a process that has exited is recorded as interrupted first.
    reap_dead_runs(case_dir)
    gate = lane_gate_blocked(case_dir)
    if gate:
        return gate_message(gate)
    busy = busy_runs(case_dir, own_run_id=own_run_id)
    if busy:
        return busy_message(busy)
    return sift_blocks_analysis(case_dir)
