"""Canonical findings records mirror the flat file."""
import json

from nexus.case.records import load_records, save_findings, save_iocs, save_timeline, save_todos


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


def test_timeline_todos_and_iocs_share_the_record_store(tmp_path):
    case = tmp_path / "CASE-R"
    case.mkdir()
    db = tmp_path / "cases.db"
    save_timeline(case, [{"event_id": "E-1", "timestamp": "2026-01-01T00:00:00Z"}], db_path=db)
    save_todos(case, [{"id": "T-1", "description": "review prefetch"}], db_path=db)
    save_iocs(case, [{"id": "I-1", "value": "10.1.1.5"}], db_path=db)
    assert load_records(case, "timeline_event", db_path=db)[0]["event_id"] == "E-1"
    assert load_records(case, "todo", db_path=db)[0]["description"] == "review prefetch"
    assert (case / "iocs.json").is_file()
