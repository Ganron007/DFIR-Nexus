"""WO-8: the Task Scheduler XML importer, lane routing, projection, reconcile.

Corpus anchors (real files under ``Evidence-files/01-windows/tasks``):
the OneDrive task carries G1's hostname + first-admin SID, the Office task
carries a ``RegistrationInfo/Date`` (a real timestamp, not the file mtime),
the .NET NGEN tasks carry ComHandler class ids, and the Edge tasks carry
typed triggers.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
TASKS = REPO / "Evidence-files" / "01-windows" / "tasks" / "system32-tasks"
ONEDRIVE = TASKS / "OneDrive Standalone Update Task-S-1-5-21-1787238638-995825184-2828871149-500"
EDGE = TASKS / "MicrosoftEdgeUpdateTaskMachineCore"
OFFICE = TASKS / "Microsoft" / "Office" / "Office Automatic Updates 2.0"
NGEN = TASKS / "Microsoft" / "Windows" / ".NET Framework" / ".NET Framework NGEN v4.0.30319"

pytestmark = pytest.mark.skipif(not TASKS.is_dir(), reason="task corpus missing")


def test_onedrive_task_carries_hostname_and_sid_anchors():
    from nexus.ingest.df.scheduled_tasks import ScheduledTasksImporter, parse_task_record

    rec = parse_task_record(ONEDRIVE)
    assert rec["author"] == "Microsoft Corporation"
    assert rec["principal_user_id"] == "WIN-7LFOBBPCFKB\\Administrator"
    assert rec["run_level"] == "LeastPrivilege"
    assert rec["logon_type"] == "InteractiveToken"
    assert rec["hidden"] is False
    assert rec["enabled"] is True
    assert rec["actions"][0]["command"].endswith("OneDriveStandaloneUpdater.exe")
    assert rec["triggers"][0]["type"] == "TimeTrigger"
    assert rec["triggers"][0]["start_boundary"] == "1992-05-01T07:00:00"
    assert rec["triggers"][0]["repetition"] == "P1D"

    art = list(ScheduledTasksImporter().parse(ONEDRIVE))[0]
    assert art.source.value == "scheduled_tasks"
    assert art.command_line.endswith("OneDriveStandaloneUpdater.exe")
    # This task has no RegistrationInfo/Date -> mtime fallback, flagged.
    assert art.ts_synthesized is True


def test_registration_date_becomes_the_timestamp():
    from nexus.ingest.df.scheduled_tasks import ScheduledTasksImporter, parse_task_record

    rec = parse_task_record(OFFICE)
    assert rec["registration_date"].startswith("2017-08-05T12:13:18")
    art = list(ScheduledTasksImporter().parse(OFFICE))[0]
    assert art.ts_synthesized is False
    assert (art.timestamp.year, art.timestamp.month) == (2017, 8)


def test_com_handler_class_id_and_typed_triggers():
    from nexus.ingest.df.scheduled_tasks import parse_task_record

    ngen = parse_task_record(NGEN)
    assert ngen["com_handler_class_id"].startswith("{")
    assert ngen["actions"] == []

    edge = parse_task_record(EDGE)
    types = [t["type"] for t in edge["triggers"]]
    assert "CalendarTrigger" in types
    assert any(t["start_boundary"] for t in edge["triggers"])


def test_utf8_export_parses_and_malformed_returns_none(tmp_path):
    from nexus.ingest.df.scheduled_tasks import parse_task_record

    text = ONEDRIVE.read_text(encoding="utf-16-le")
    utf8 = tmp_path / "task.xml"
    utf8.write_text(text.lstrip("\ufeff"), encoding="utf-8")
    assert parse_task_record(utf8)["principal_user_id"] == "WIN-7LFOBBPCFKB\\Administrator"

    broken = tmp_path / "broken-task"
    broken.write_text("<Task> not closed", encoding="utf-8")
    assert parse_task_record(broken) is None


def test_lane_routes_parsable_to_importer_and_unparsable_to_strings(tmp_path):
    from nexus.langgraph.tool_lane import _task_xml_kind, _task_xml_parses, is_host_evidence

    assert _task_xml_kind(ONEDRIVE) == "task"
    assert _task_xml_parses(ONEDRIVE) is True
    assert is_host_evidence(ONEDRIVE) is False  # the importer lane owns it

    broken_dir = tmp_path / "tasks"
    broken_dir.mkdir()
    broken = broken_dir / "broken-task"
    broken.write_text(
        "<Task xmlns='http://schemas.microsoft.com/windows/2004/02/mit/task'>broken",
        encoding="utf-8",
    )
    assert _task_xml_kind(broken) == "task"
    assert _task_xml_parses(broken) is False
    assert is_host_evidence(broken) is True  # strings stays the fallback


def test_single_artifact_plan_skips_parsable_and_keeps_the_fallback(tmp_path):
    from nexus.langgraph.tool_lane import _plan_single_artifact

    jobs = _plan_single_artifact(ONEDRIVE, tmp_path / "extractions")
    assert len(jobs) == 1
    assert jobs[0].status == "SKIP"
    assert "importer lane" in jobs[0].reason

    broken_dir = tmp_path / "tasks"
    broken_dir.mkdir()
    broken = broken_dir / "broken-task"
    broken.write_text(
        "<Task xmlns='http://schemas.microsoft.com/windows/2004/02/task'>broken",
        encoding="utf-8",
    )
    fallback = _plan_single_artifact(broken, tmp_path / "extractions2")
    assert len(fallback) == 1
    assert fallback[0].status != "SKIP"
    assert fallback[0].tool == "strings"
    assert "strings fallback" in fallback[0].purpose


def _seed_case(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    case = tmp_path / "cases" / "CASE-WO8TASK"
    (case / "analysis").mkdir(parents=True)
    (case / "CASE.yaml").write_text("name: wo8\nstatus: active\n", encoding="utf-8")
    return case


def test_ingest_and_index_projection_carry_the_typed_fields(tmp_path, monkeypatch):
    case = _seed_case(tmp_path, monkeypatch)
    from nexus.langgraph.timeline_merge import ingest_into_case

    res = ingest_into_case(ONEDRIVE, case, audit=False)
    assert res["success"] and res["artifacts"] == 1

    from nexus.langgraph.case_index import iter_index_docs

    docs = [d for d in iter_index_docs(case) if d.get("family") == "scheduled_tasks"]
    assert len(docs) == 1
    fields = docs[0].get("fields") or {}
    assert fields.get("task_uri", "").endswith("OneDrive Standalone Update Task-S-1-5-21-1787238638-995825184-2828871149-500")
    assert fields.get("task_author") == "Microsoft Corporation"
    assert fields.get("principal_user_id") == "WIN-7LFOBBPCFKB\\Administrator"
    assert fields.get("run_level") == "LeastPrivilege"
    assert fields.get("action_command", "").endswith("OneDriveStandaloneUpdater.exe")
    assert fields.get("trigger_type") == "TimeTrigger"
    assert fields.get("trigger_start_boundary") == "1992-05-01T07:00:00"


def test_reconciliation_is_exact_for_the_task_store(tmp_path, monkeypatch):
    case = _seed_case(tmp_path, monkeypatch)
    from nexus.langgraph.timeline_merge import ingest_into_case

    ingest_into_case(ONEDRIVE, case, audit=False)
    (case / "analysis" / "es_index.json").write_text(
        json.dumps(
            {
                "docs": 1,
                "file_counts": {"ingest/artifacts.jsonl": {"docs": 1, "deduped": 0}},
            }
        ),
        encoding="utf-8",
    )
    from nexus.analysis.reconciliation import reconcile_case

    rec = reconcile_case(case)
    row = next(f for f in rec["files"] if f["file"] == "ingest/artifacts.jsonl")
    assert row["source_records"] == 1
    assert row["delta"] == 0
    assert row["status"] == "match"
