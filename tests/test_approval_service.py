"""CLI and portal approve through one function."""
import json

from nexus.case.approval_service import commit_approval, commit_rejection
from nexus.case.records import load_records


def _case(tmp_path, finding):
    case = tmp_path / "CASE-AP"
    case.mkdir()
    (case / "findings.json").write_text(json.dumps([finding]), encoding="utf-8")
    return case


def _isolate_store(monkeypatch, tmp_path):
    monkeypatch.setattr("nexus.case.records.records_db_path", lambda: tmp_path / "cases.db")
    monkeypatch.setattr("nexus.transparency.TRANSPARENCY_DIR", tmp_path / "transparency")


def test_approval_writes_the_record_and_refuses_a_broken_seal(tmp_path, monkeypatch):
    _isolate_store(monkeypatch, tmp_path)
    case = _case(tmp_path, {"id": "F-1", "title": "encoded powershell", "status": "DRAFT"})
    approved = commit_approval(case, "F-1", "examiner", l1_verdict="PROVEN", note="seen")
    assert approved["status"] == "APPROVED"
    mirrored = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert mirrored[0]["status"] == "APPROVED"
    assert mirrored[0]["seal_state"] == "absent"
    stored = load_records(case, "finding")
    assert stored[0]["title"] == "encoded powershell"

    other = tmp_path / "CASE-BROKEN"
    other.mkdir()
    (other / "findings.json").write_text(
        json.dumps([{
            "id": "F-2",
            "title": "edited",
            "status": "DRAFT",
            "content_hash": "not-the-digest",
        }]),
        encoding="utf-8",
    )
    refused = commit_approval(other, "F-2", "examiner")
    assert refused["status"] == "error"
    assert "seal" in refused["error"]
    still = json.loads((other / "findings.json").read_text(encoding="utf-8"))
    assert still[0]["status"] == "DRAFT"


def test_rejection_uses_the_same_record_store(tmp_path, monkeypatch):
    _isolate_store(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "nexus.analysis.negative_space.record",
        lambda *args, **kwargs: None,
    )
    case = tmp_path / "CASE-RJ"
    case.mkdir()
    (case / "findings.json").write_text(
        json.dumps([{"id": "F-9", "status": "DRAFT", "title": "noise"}]),
        encoding="utf-8",
    )
    result = commit_rejection(case, "F-9", "examiner", "benign")
    assert result["status"] == "REJECTED"
    mirrored = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert mirrored[0]["rejection_reason"] == "benign"
    assert load_records(case, "finding")[0]["status"] == "REJECTED"
