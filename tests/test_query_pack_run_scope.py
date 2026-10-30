"""A named report must not take metadata from a previous completed tools run."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from nexus.langgraph import pipeline_runs, query_pack


@pytest.fixture
def open_native_lane(tmp_path):
    captured = json.loads((Path(__file__).parent / "fixtures" / "d513_t01_lane_ledger_scope.json").read_text(encoding="utf-8"))
    case = tmp_path / "CASE-REPORT-SCOPE"
    runs = {}
    for key in ("previous", "current"):
        item = captured[key]
        run = pipeline_runs.create_run(case, "tools", run_id=item["run_id"])
        (run.extractions / "_tool_lane_ledger.json").write_text(
            json.dumps(item["ledger"]), encoding="utf-8",
        )
        # Verbatim parsed output provides real data to the native resolver.
        output = run.extractions / "evtxecmd"
        output.mkdir()
        shutil.copyfile(Path(__file__).parent / "fixtures" / "cs1b_evtx_real_rows.csv", output / "events.csv")
        if key == "previous":
            pipeline_runs.finalize_run(run, "completed")
        runs[key] = run
    return case, runs, captured


def test_named_query_pack_uses_its_own_ledger_and_extras(open_native_lane, monkeypatch):
    case, runs, captured = open_native_lane
    monkeypatch.setenv("NEXUS_N4_BACKEND", "csv")
    selected = []
    original = pipeline_runs.resolve_tools_extractions

    def observe(*args, **kwargs):
        root = original(*args, **kwargs)
        selected.append(root)
        return root

    monkeypatch.setattr(pipeline_runs, "resolve_tools_extractions", observe)
    report = query_pack.build_query_pack_markdown(
        case, intake={"question": "Compromise suspected."}, run_id=runs["current"].run_id,
    )
    ledger = captured["current"]["ledger"]
    assert f"## Ledger OK rows: {sum(r['status'] == 'OK' for r in ledger)} / {len(ledger)}" in report
    assert selected
    assert all(root == runs["current"].extractions for root in selected)
    # The default reader intentionally retains its committed-run recovery rule.
    assert original(case) == runs["previous"].extractions


def test_requested_extra_is_not_credited_from_a_previous_run(open_native_lane):
    case, runs, _ = open_native_lane
    # Folder presence is a parser-output lifecycle control, not invented evidence rows.
    (runs["previous"].extractions / "email").mkdir()
    notes = query_pack.extras_gap_notes(
        case, {"extras": "email"}, run_id=runs["current"].run_id,
    )
    assert any("`email` requested — artifact not present" in line for line in notes)
    assert not any("`email` ran" in line for line in notes)
