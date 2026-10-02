"""WO-B4: a family that lands after a run started is reported on that run."""
import json

from nexus.langgraph.lane_gate import write_lane_gate


def test_a_pending_family_that_is_now_processed_is_reported(tmp_path):
    from nexus.dashboard.app import late_evidence

    case = tmp_path / "CASE-LATE"
    case.mkdir()
    write_lane_gate(case, "RUN-2", [
        {"tool": "mft", "family": "mftecmd", "status": "OK"},
        {"tool": "evtx", "family": "evtxecmd", "status": "OK"},
    ], ts="2026-10-02T02:00:00+00:00")
    record = {
        "created_at": "2026-10-02T01:00:00+00:00",
        "evidence_coverage": {"status": "blocked", "pending": ["evtxecmd", "mftecmd"]},
    }
    out = late_evidence(case, record)
    assert out["count"] == 2
    assert out["families"] == ["evtxecmd", "mftecmd"]


def test_a_still_pending_family_is_not_reported_and_no_snapshot_cannot_claim_one(tmp_path):
    from nexus.dashboard.app import late_evidence

    case = tmp_path / "CASE-LATE2"
    case.mkdir()
    write_lane_gate(case, "RUN-2", [
        {"tool": "evtx", "family": "evtxecmd", "status": "FAIL"},
    ], ts="2026-10-02T02:00:00+00:00")
    still = {
        "created_at": "2026-10-02T01:00:00+00:00",
        "evidence_coverage": {"status": "blocked", "pending": ["evtxecmd"]},
    }
    assert late_evidence(case, still) == {}
    assert late_evidence(case, {"created_at": "x", "evidence_coverage": {}}) == {}


def test_run_record_write_carries_the_field(tmp_path):
    """The run record itself is JSON, so the field survives a reload."""
    case = tmp_path / "CASE-LATE3"
    (case / "analysis").mkdir(parents=True)
    record = {"run_id": "M2-1", "evidence_coverage": {"status": "blocked", "pending": ["mftecmd"]}}
    path = case / "analysis" / "mode2_runs" / "M2-1.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(record), encoding="utf-8")
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["evidence_coverage"]["pending"] == ["mftecmd"]
