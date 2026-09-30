"""WO-A5 (WP 10.41): evidence freshness — automatic re-verify at lane
start/end, the FAIL row for a mid-lane modification, indexed-source digests
with ``nexus index verify``, and the summary surface field."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture()
def case_dir(tmp_path, monkeypatch) -> Path:
    from nexus.case.manager import CaseManager
    from nexus.case.schemas import FindingSeverity
    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", tmp_path)
    monkeypatch.setenv("NEXUS_EXAMINER", "freshness_test")
    root = tmp_path / "CASE-FRESH-0001"
    root.mkdir()
    # evidence registration needs the case in the SQLite registry
    mgr = CaseManager(settings.cases_root / "cases.db")
    mgr.create_case(
        name="Freshness Fixture", description="WO-A5 fixture",
        severity=FindingSeverity.LOW, created_by="freshness_test",
        metadata={"synthetic": True}, case_id=root.name,
    )
    mgr.close()
    return root


def _register(case_dir: Path, name: str, content: bytes) -> Path:
    """Register one evidence file through the real evidence service."""
    from nexus.case.evidence_service import register_evidence

    p = case_dir / "evidence" / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    register_evidence(
        case_dir, str(p), description="freshness fixture",
        examiner="freshness_test",
    )
    return p


def test_freshness_shape_ok_case(case_dir: Path):
    """A case whose registered evidence is intact verifies as ok, with the
    state file written where the surfaces read it."""
    _register(case_dir, "Security.evtx", b"FRESH-EVTX")
    from nexus.analysis.freshness import capture_freshness

    payload = capture_freshness(case_dir, "lane_start")
    assert payload["result"] == "ok"
    assert payload["phase"] == "lane_start"
    assert payload["verified_at"]
    assert len(payload["items"]) == 1 and payload["items"][0]["valid"] is True

    state = json.loads(
        (case_dir / "analysis" / "evidence_freshness.json").read_text(encoding="utf-8")
    )
    assert state["result"] == "ok"


def test_modified_and_missing_classified(case_dir: Path):
    from nexus.analysis.freshness import capture_freshness

    p = _register(case_dir, "prefetch.csv", b"row")
    capture_freshness(case_dir, "lane_start")

    p.write_bytes(b"TAMPERED")
    payload = capture_freshness(case_dir, "lane_end")
    assert payload["result"] == "modified"

    p.unlink()
    payload = capture_freshness(case_dir, "ad_hoc")
    assert payload["result"] == "missing"


def test_lane_end_fail_row_names_the_item(case_dir: Path):
    """The WO-A5 scenario: intact at lane start, modified at lane end — the
    regression names exactly that item (the lane appends it as a FAIL row)."""
    from nexus.analysis.freshness import (
        capture_freshness,
        freshness_regressions,
    )

    p = _register(case_dir, "Security.evtx", b"BEFORE")
    start = capture_freshness(case_dir, "lane_start")
    assert start["result"] == "ok"

    p.write_bytes(b"AFTER-TAMPER")
    end = capture_freshness(case_dir, "lane_end")

    regs = freshness_regressions(start, end)
    assert len(regs) == 1
    assert regs[0]["name"] == "Security.evtx"
    assert regs[0]["now"] == "not ok"


def test_run_tool_lane_appends_freshness_fail_row_to_the_gate(case_dir: Path):
    """Real-path: a full ``run_tool_lane`` pass on a case whose evidence is
    modified mid-lane writes a FAIL ledger row and the lane gate names it."""
    import asyncio

    from nexus.langgraph.tool_lane import run_tool_lane

    p = _register(case_dir, "notes.csv", b"a,b\n1,2\n")
    run_dir = case_dir / "runs" / "R-20261001-000000-fresh"
    run_dir.mkdir(parents=True)
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": "R-20261001-000000-fresh", "mode": "tools",
        "case_id": case_dir.name, "status": "running",
    }), encoding="utf-8")

    class FakeTool:
        async def ainvoke(self, args):
            return json.dumps({"success": True, "output": ""})

    async def run() -> dict:
        lane = await run_tool_lane(
            tools={"run_windows_command": FakeTool(), "run_command": FakeTool()},
            evidence_path=str(p),
            case_id=case_dir.name,
            run_id="R-20261001-000000-fresh",
            parse_result=json.loads,
            pipeline_mode="tools",
        )
        return lane

    def _tamper():
        # the lane runs quickly; tamper while it is between start and end by
        # flipping the file before the call returns — the lane-end capture
        # must see the modification regardless of timing
        p.write_bytes(b"a,b\n9,9\n")

    # deterministic: tamper before the lane starts? No — that is the
    # pre-existing class. The lane appends the FAIL row when the file changes
    # between ITS start and end captures, so mutate it right after the
    # lane-start capture lands (the freshness file is written synchronously
    # at the top of run_tool_lane).
    import threading

    tamper_once = threading.Event()

    import nexus.analysis.freshness as freshness_mod

    real_capture = freshness_mod.capture_freshness

    def spy(case_dir_, phase):
        result = real_capture(case_dir_, phase)
        if phase == "lane_start" and not tamper_once.is_set():
            tamper_once.set()
            p.write_bytes(b"a,b\n9,9\n")
        return result

    freshness_mod.capture_freshness = spy
    try:
        lane = asyncio.run(run())
    finally:
        freshness_mod.capture_freshness = real_capture

    ledger = lane.get("tool_run_ledger") if isinstance(lane, dict) else lane
    fail_rows = [
        r for r in ledger
        if isinstance(r, dict) and r.get("tool") == "evidence_freshness"
    ]
    assert fail_rows, f"no freshness FAIL row in the ledger: {ledger}"
    assert any(
        "notes.csv" in str(r.get("reason") or "") + str(r.get("purpose") or "")
        for r in fail_rows
    )

    gate = json.loads((case_dir / "analysis" / "lane_gate.json").read_text())
    assert any(
        "notes.csv" in str(u.get("purpose") or "")
        for u in gate.get("unprocessed") or []
    )


def test_index_state_records_source_digests_and_verify_detects_change(
    case_dir, monkeypatch, capsys
):
    """At index-build time every indexed source file's SHA-256 is stored;
    ``nexus index verify`` reports post-index modification with exit 1."""
    from typer.testing import CliRunner

    from nexus.langgraph.case_index import write_index_state

    ext = case_dir / "extractions"
    ext.mkdir(parents=True, exist_ok=True)
    (ext / "notes.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    write_index_state(case_dir, {"docs": 2, "index": "", "capped": False, "caps": {}})

    state = json.loads((case_dir / "analysis" / "index_state.json").read_text())
    # digest keys match the doc `file` convention: relative to the extraction root
    assert "notes.csv" in (state.get("file_sha256s") or {})

    from nexus.cli.index_cmd import app as index_app

    runner = CliRunner()
    ok = runner.invoke(index_app, ["verify", "--case", case_dir.name])
    assert ok.exit_code == 0, ok.output

    (ext / "notes.csv").write_text("a,b\nTAMPERED\n", encoding="utf-8")
    bad = runner.invoke(index_app, ["verify", "--case", case_dir.name])
    assert bad.exit_code == 1
    assert "MODIFIED" in bad.output
