"""Tests for D57 — evidence registry distinguishing examiner originals from tool extraction outputs (origin).
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.case.evidence_service import _serialize, list_evidence
from nexus.case_manager import CaseManager


class DummyEvidenceRecord:
    def __init__(self, eid, path, kind, collected_by="examiner"):
        self.id = eid
        self.file_path = path
        self.file_hash_sha256 = "dummyhash"
        self.description = "desc"
        self.collected_by = collected_by
        self.collected_at = None
        self.name = Path(path).name
        self.metadata = {"kind": kind}


def test_evidence_service_serialize_origin():
    # Examiner registered file
    rec1 = DummyEvidenceRecord("E-01", "/evidence/sample.evtx", "file")
    s1 = _serialize(rec1)
    assert s1["origin"] == "examiner"
    assert s1["kind"] == "file"

    # Examiner registered directory
    rec2 = DummyEvidenceRecord("E-02", "/evidence/triage_dir", "directory")
    s2 = _serialize(rec2)
    assert s2["origin"] == "examiner"

    # Tool extraction output (derived)
    rec3 = DummyEvidenceRecord("E-03", "/cases/C1/extractions/hayabusa/stdout.txt", "tool_extraction")
    s3 = _serialize(rec3)
    assert s3["origin"] == "derived"
    assert s3["kind"] == "tool_extraction"


def test_evidence_service_list_evidence_origin_filtering(tmp_path: Path, monkeypatch):
    case_dir = tmp_path / "CASE-D57"
    case_dir.mkdir(parents=True)

    records = [
        DummyEvidenceRecord("E-01", "/evidence/raw.img", "file"),
        DummyEvidenceRecord("E-02", "/evidence/extractions/evtxecmd/out.csv", "tool_extraction"),
    ]

    class MockManager:
        def list_evidence(self, case_id):
            return records

        def close(self):
            pass

    monkeypatch.setattr("nexus.case.evidence_service._manager", lambda: MockManager())

    all_items = list_evidence(case_dir)
    assert len(all_items) == 2

    examiner_items = list_evidence(case_dir, origin="examiner")
    assert len(examiner_items) == 1
    assert examiner_items[0]["id"] == "E-01"

    derived_items = list_evidence(case_dir, origin="derived")
    assert len(derived_items) == 1
    assert derived_items[0]["id"] == "E-02"


def test_case_manager_evidence_origin_tagging(tmp_path: Path):
    case_dir = tmp_path / "CASE-D57"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "evidence.json").write_text("[]", encoding="utf-8")
    (case_dir / "CASE.yaml").write_text("name: D57-Case\n", encoding="utf-8")

    cm = CaseManager()

    # Register an evidence file
    sample_file = tmp_path / "sample.evtx"
    sample_file.write_bytes(b"sample evtx content")

    res = cm.register_evidence(str(sample_file), description="raw evtx", case_dir=case_dir)
    assert res["status"] == "registered"

    items = cm.list_evidence(case_dir)
    assert len(items) == 1
    assert items[0]["origin"] == "examiner"

    # Add a mock tool extraction entry into evidence.json
    ev_path = case_dir / "evidence.json"
    ev_data = json.loads(ev_path.read_text(encoding="utf-8"))
    ev_data.append({
        "path": "/cases/extractions/tool_stdout.txt",
        "sha256": "abc",
        "kind": "tool_extraction",
        "name": "tool_stdout.txt",
    })
    ev_path.write_text(json.dumps(ev_data), encoding="utf-8")

    all_ev = cm.list_evidence(case_dir)
    assert len(all_ev) == 2

    examiner_ev = cm.list_evidence(case_dir, origin="examiner")
    assert len(examiner_ev) == 1
    assert examiner_ev[0]["origin"] == "examiner"

    derived_ev = cm.list_evidence(case_dir, origin="derived")
    assert len(derived_ev) == 1
    assert derived_ev[0]["origin"] == "derived"
