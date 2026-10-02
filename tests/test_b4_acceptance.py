"""WO-B4 acceptance: a folder with raw EVTX, a pre-processed CSV, and a raw
$LogFile; the pairing is offered, confirming it clears the raw job, and the
report gate follows the gate.
"""
from nexus.case import evidence_service
from nexus.case.compat import get_sqlite_manager


def _case_dir(tmp_path, monkeypatch):
    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", tmp_path)
    mgr = get_sqlite_manager()
    case = mgr.create_case(name="b4", description="d", created_by="gate_bot")
    case_dir = tmp_path / case.to_dict()["id"]
    (case_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (case_dir / "CASE.yaml").write_text("id: " + case_dir.name + "\n", encoding="utf-8")
    return case_dir


def test_the_acceptance_folder_is_recognized_and_offered_for_pairing(tmp_path, monkeypatch):
    case_dir = _case_dir(tmp_path, monkeypatch)
    ingest = tmp_path / "evidence"
    ingest.mkdir()
    (ingest / "Security.evtx").write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    (ingest / "$LogFile").write_bytes(b"raw logfile bytes")
    (ingest / "LogFile.csv").write_text(
        "LSN,RedoOp,UndoOp,CurrentLSN\n1,2,3,4\n",
        encoding="utf-8",
    )

    recognized = []
    for path in sorted(ingest.iterdir()):
        out = evidence_service.register_evidence(case_dir, str(path), "", "gate_bot")
        recognized.append(out)
    placed = [r for r in recognized if r.get("recognized_family")]
    assert len(placed) == 1
    assert placed[0]["recognized_family"] == "logfileparser"
    assert placed[0]["placed_at"].endswith("ingest\\logfileparser\\LogFile.csv") or (
        placed[0]["placed_at"].endswith("ingest/logfileparser/LogFile.csv")
    )

    items = evidence_service.list_evidence(case_dir)
    from nexus.ingest.fingerprint import propose_pairs

    proposals = propose_pairs(items)
    assert any(
        p["raw_name"] == "$LogFile"
        and p["output_name"] == "LogFile.csv"
        and p["family"] == "logfileparser"
        for p in proposals
    ), proposals


def test_confirming_the_pairing_clears_the_raw_job(tmp_path):
    from nexus.dashboard.app import _lane_gate_error
    from nexus.langgraph.lane_gate import (
        confirm_preprocessed_pair,
        lane_gate_blocked,
        read_lane_gate,
        write_lane_gate,
    )

    case = tmp_path / "CASE-B4"
    (case / "analysis").mkdir(parents=True)
    write_lane_gate(case, "RUN-1", [
        {"tool": "$LogFile", "purpose": "$LogFile", "status": "FAIL",
         "reason": "raw logfile queued"},
        {"tool": "evtxecmd", "purpose": "Security.evtx", "family": "evtxecmd",
         "status": "OK"},
    ], ts="2026-10-02T00:00:00+00:00")
    assert lane_gate_blocked(case)
    assert _lane_gate_error(case) is not None

    gate = confirm_preprocessed_pair(
        case,
        raw_name="$LogFile",
        output_name="LogFile.csv",
        output_sha256="ab" * 32,
        examiner="gate_bot",
    )
    assert gate["status"] == "clear"
    assert len(gate["examiner_skips"]) == 1
    assert lane_gate_blocked(case) == {}
    assert _lane_gate_error(case) is None
    stored = read_lane_gate(case)
    assert stored["pairs"][0]["output"] == "LogFile.csv"
    # One audited skip for the raw job, and exactly one pairing record.
    skips = [s for s in stored["examiner_skips"] if s["tool"] == "$LogFile"]
    assert len(skips) == 1
    assert len(stored["pairs"]) == 1
    assert "pre-processed output supplied" in skips[0]["reason"]
