"""G7 round-2 fixes: SleuthKit `-o` offset flag + SIFT-only run resolution.

- `fls -o 2048` must pass the SIFT-side flag gate: for SleuthKit tools `-o`
  is a partition offset, not an in-place/exec flag.
- A run whose only products are under `sift/extractions` is NOT data-less:
  the resolver must pick it, or the indexer walks nothing (0 docs).
"""
from __future__ import annotations

import json

import pytest


def test_fls_offset_flag_allowed_for_sleuthkit_tools():
    from nexus.tools.sift import _sanitize_extra_args

    assert _sanitize_extra_args(["-o", "2048"], "fls") == ["-o", "2048"]
    assert _sanitize_extra_args(["-o", "2048"], "icat") == ["-o", "2048"]
    assert _sanitize_extra_args(["-o", "2048"], "blkls") == ["-o", "2048"]


def test_offset_flag_still_blocked_for_other_tools():
    from nexus.tools.sift import _sanitize_extra_args

    with pytest.raises(ValueError):
        _sanitize_extra_args(["-o", "x"], "grep")
    with pytest.raises(ValueError):
        _sanitize_extra_args(["-e", "x"], "fls")


def test_sift_only_run_resolves_for_the_index(tmp_path):
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions

    case = tmp_path / "CASE-SIFT"
    run = case / "runs" / "RUN-TEST-sift-1"
    (run / "extractions").mkdir(parents=True)
    (run / "extractions" / "_tool_lane_ledger.json").write_text("[]", encoding="utf-8")
    (run / "sift" / "extractions" / "vol").mkdir(parents=True)
    (run / "sift" / "extractions" / "vol" / "1_vol_out.json").write_text(
        "[{}]", encoding="utf-8"
    )
    (run / "manifest.json").write_text(json.dumps({"mode": "tools"}), encoding="utf-8")
    (case / "active_runs.json").write_text(
        json.dumps({"tools": "RUN-TEST-sift-1"}), encoding="utf-8"
    )

    resolved = resolve_tools_extractions(case)

    assert resolved == run / "extractions"
