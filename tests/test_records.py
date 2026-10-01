"""Canonical findings records mirror the flat file."""
import json

from nexus.case.records import load_records, save_findings


def test_save_findings_round_trips_the_document(tmp_path):
    case = tmp_path / "CASE-R"
    case.mkdir()
    db = tmp_path / "cases.db"
    save_findings(
        case,
        [{"id": "F-1", "title": "encoded powershell", "status": "DRAFT"}],
        db_path=db,
    )
    mirrored = json.loads((case / "findings.json").read_text(encoding="utf-8"))
    stored = load_records(case, "finding", db_path=db)
    assert mirrored[0]["title"] == "encoded powershell"
    assert stored[0] == mirrored[0]
