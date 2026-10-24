"""D384 (2026-10-25): a Windows Volatility list-walk that returned nothing is a coverage gap, as on SIFT.

WO-V6's ``reconcile_process_list_coverage`` turns an empty list-walk plugin into a WARN with a coverage gap when psscan
saw processes. The lane called it with the SIFT jobs only, written when Volatility ran there; since memory runs on
Windows (D85), T22's R1z2 lane recorded 11 of 15 plugins OK with empty output while psscan listed 134 processes. The
outputs read here are that run's own (vol3 2.28.2 on T22's image); the test skips where the run is absent.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus.langgraph import tool_lane as tl

REPO = Path(__file__).resolve().parents[1]
T22 = REPO / "cases" / "CASE-4387EB47"


def _r1z2_vol_rows() -> list[dict]:
    runs = sorted(p for p in (T22 / "runs").glob("*-tools-*") if (p / "ledger" / "_tool_lane_ledger.json").is_file()) \
        if (T22 / "runs").is_dir() else []
    for run in reversed(runs):
        rows = [r for r in json.loads((run / "ledger" / "_tool_lane_ledger.json").read_text(encoding="utf-8"))
                if r.get("tool") == "vol" and r.get("status") == "OK" and r.get("output_saved_to")]
        if len(rows) == 15 and all(Path(r["output_saved_to"]).is_file() for r in rows):
            return rows
    return []


@pytest.mark.skipif(not _r1z2_vol_rows(), reason="T22's R1z2 lane run is not on this host")
def test_t22_empty_windows_list_walks_become_coverage_warns(tmp_path):
    rows = _r1z2_vol_rows()
    jobs = [tl.ToolJob(host="windows", tool="vol", argv=list(r["argv"]), purpose=r["purpose"], status="OK",
                       output_saved_to=r["output_saved_to"]) for r in rows]
    ledger = [{"host": "windows", "tool": "vol", "purpose": r["purpose"], "status": "OK", "reason": ""} for r in rows]
    case_dir = tmp_path / "CASE-D384"
    (case_dir / "analysis").mkdir(parents=True)
    warned = tl.reconcile_process_list_coverage(jobs, case_dir, ledger, run_id="RUN-D384")
    plugins = {tl.vol_plugin_name(j.argv) for j in warned}
    assert {"windows.pslist", "windows.pstree", "windows.cmdline", "windows.dlllist", "windows.handles",
            "windows.envars", "windows.malfind", "windows.ldrmodules"} <= plugins
    assert all(j.status == "WARN" and "134" in j.reason for j in warned if tl.vol_plugin_name(j.argv) != "windows.registry.printkey")
    by_purpose = {r["purpose"]: r for r in ledger}
    assert all(by_purpose[j.purpose]["status"] == "WARN" for j in warned)
    scans = {tl.vol_plugin_name(j.argv): j.status for j in jobs}
    assert scans["windows.psscan"] == "OK" and scans["windows.netscan"] == "OK"  # rows came back: untouched
