"""One engine per plugin per image (operator decision 2026-10-11): a SIFT plugin the Windows run holds is not run again.

On CASE-C5B04D31 the same 15 Volatility 3 plugins ran on Windows and on SIFT, and both sets were indexed: 88,965
documents each. The Windows run is the lane's memory product, so a pending SIFT plugin that Windows plans or holds
is skipped, and the row says so. A SIFT row that already has its OK record is kept as it is.
"""

from __future__ import annotations

from nexus.langgraph.tool_lane import ToolJob, _one_engine_per_plugin, _vol_token


def _windows(plugin: str, status: str = "PENDING") -> ToolJob:
    return ToolJob(host="windows", tool="vol", argv=["vol3", "-f", "img", plugin],
                   purpose=f"Volatility3 {plugin} (Windows, 2.28.0)", status=status)


def _sift(plugin: str, status: str = "PENDING") -> ToolJob:
    return ToolJob(host="sift", tool="vol", argv=["vol", "-f", "img", plugin],
                   purpose=f"Volatility3 {plugin}", status=status)


def test_the_plugin_is_read_the_same_way_from_either_engines_purpose():
    assert _vol_token("Volatility3 windows.pslist (Windows, 2.28.0)") == "windows.pslist"
    assert _vol_token("Volatility3 windows.pslist") == "windows.pslist"
    assert _vol_token("Volatility3 registry.printkey Run (Windows, 2.28.0)") == "registry.printkey Run"
    assert _vol_token("Volatility3 registry.printkey Run") == "registry.printkey Run"
    assert _vol_token("MFT parse (CSV)") == ""


def test_a_pending_sift_plugin_the_windows_run_plans_is_skipped():
    jobs = [_windows("windows.pslist"), _sift("windows.pslist")]
    _one_engine_per_plugin(jobs)
    assert jobs[1].status == "SKIP"
    assert "one engine per plugin per image" in jobs[1].reason


def test_a_pending_sift_plugin_the_windows_run_already_holds_is_skipped():
    jobs = [_windows("windows.netscan", status="OK"), _sift("windows.netscan")]
    _one_engine_per_plugin(jobs)
    assert jobs[1].status == "SKIP"


def test_a_sift_row_that_already_has_its_ok_record_is_kept():
    jobs = [_windows("windows.pslist"), _sift("windows.pslist", status="OK")]
    _one_engine_per_plugin(jobs)
    assert jobs[1].status == "OK"


def test_a_sift_plugin_with_no_windows_counterpart_still_runs():
    jobs = [_windows("windows.pslist"), _sift("windows.cmdline")]
    _one_engine_per_plugin(jobs)
    assert jobs[1].status == "PENDING"


def test_a_failed_windows_plugin_leaves_the_sift_run_as_the_fallback():
    jobs = [_windows("windows.malfind", status="FAIL"), _sift("windows.malfind")]
    _one_engine_per_plugin(jobs)
    assert jobs[1].status == "PENDING"
