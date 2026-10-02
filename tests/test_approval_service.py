"""CLI and portal approve through one function."""
import json

from nexus.case.approval_service import cited_event_ids, commit_approval, commit_rejection
from nexus.case.records import load_records, save_findings


def _case(tmp_path, finding):
    case = tmp_path / "CASE-AP"
    case.mkdir()
    (case / "findings.json").write_text(json.dumps([finding]), encoding="utf-8")
    return case


def _isolate_store(monkeypatch, tmp_path):
    monkeypatch.setattr("nexus.case.records.records_db_path", lambda: tmp_path / "cases.db")
    monkeypatch.setattr("nexus.transparency.TRANSPARENCY_DIR", tmp_path / "transparency")


def test_cited_event_ids_come_from_the_finding_and_its_artifacts():
    assert cited_event_ids({
        "event_ids": ["e1", "e1"],
        "artifacts": [{"event_id": "e2"}, {"path": "x"}],
    }) == ["e1", "e2"]
    assert cited_event_ids({"title": "no events"}) == []


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


def test_approval_refuses_a_non_proven_verdict_without_a_reason(tmp_path, monkeypatch):
    """The rule lives in the service, so every surface enforces it."""
    _isolate_store(monkeypatch, tmp_path)
    case = _case(tmp_path, {"id": "F-L1", "title": "inference only", "status": "DRAFT"})

    refused = commit_approval(case, "F-L1", "examiner", l1_verdict="INFERRED")
    assert refused["status"] == "error"
    assert "override_reason" in refused["error"]
    assert refused["l1_verdict"] == "INFERRED"
    assert refused["needs_override_reason"] is True
    still = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    assert still[0]["status"] == "DRAFT"

    # A PROVEN verdict needs no reason.
    approved = commit_approval(case, "F-L1", "examiner", l1_verdict="PROVEN")
    assert approved["status"] == "APPROVED"
    assert approved["l1_verdict"] == "PROVEN"


def test_the_override_reason_reaches_the_ledger(tmp_path, monkeypatch):
    _isolate_store(monkeypatch, tmp_path)
    from nexus.auth import read_verification_ledger

    case = _case(tmp_path, {"id": "F-OV", "title": "inference", "status": "DRAFT"})
    approved = commit_approval(
        case, "F-OV", "examiner",
        l1_verdict="INFERRED",
        override_reason="corroborated by two families in the lane",
        signing_key=b"0" * 32,
    )
    assert approved["status"] == "APPROVED"
    entries = read_verification_ledger(case.name)
    assert entries, "an approval with a signing key must write a ledger entry"
    assert entries[-1]["override_reason"] == "corroborated by two families in the lane"
    assert entries[-1]["l1_verdict_at_approval"] == "INFERRED"


def test_a_hand_edited_mirror_is_refused(tmp_path, monkeypatch):
    """findings.json is a generated mirror; an edit outside the store is a signal."""
    _isolate_store(monkeypatch, tmp_path)
    case = _case(tmp_path, {"id": "F-TAMPER", "title": "staged", "status": "DRAFT"})
    # Stage through the store so the record exists, then edit the mirror only.
    save_findings(case, [{"id": "F-TAMPER", "title": "staged", "status": "DRAFT"}])
    mirrored = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    mirrored[0]["title"] = "edited outside the store"
    (case / "findings.json").write_text(json.dumps(mirrored), encoding="utf-8")

    refused = commit_approval(case, "F-TAMPER", "examiner", l1_verdict="PROVEN")
    assert refused["status"] == "error"
    assert "mirror differs from the record store" in refused["error"]
    assert load_records(case, "finding")[0]["status"] == "DRAFT"


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
