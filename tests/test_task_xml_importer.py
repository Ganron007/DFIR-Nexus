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
    # D197: the folder above the task ("system32-tasks") is not a machine.
    assert art.host is None


def test_registration_date_becomes_the_timestamp():
    from nexus.ingest.df.scheduled_tasks import ScheduledTasksImporter, parse_task_record

    rec = parse_task_record(OFFICE)
    assert rec["registration_date"].startswith("2017-08-05T12:13:18")
    art = list(ScheduledTasksImporter().parse(OFFICE))[0]
    assert art.ts_synthesized is False
    assert (art.timestamp.year, art.timestamp.month) == (2017, 8)


def test_naive_registration_date_uses_recorded_system_zone_and_dst(tmp_path, monkeypatch):
    from nexus.ingest import windows_timezones
    from nexus.ingest.df.scheduled_tasks import parse_task_record
    from nexus.ingest.windows_timezones import record_case_host_timezones, windows_path_root

    case = _seed_case(tmp_path, monkeypatch)
    recmd = case / "runs" / "RUN-D240-REAL-RECMD" / "extractions" / "recmd"
    output = recmd / "20261011110620"
    output.mkdir(parents=True)
    fixtures = REPO / "tests" / "fixtures" / "d240_timezone"
    (output / "20261011110620_TimeZoneInfo__SYSTEM.csv").write_bytes(
        (fixtures / "20261011110620_TimeZoneInfo__SYSTEM.csv").read_bytes()
    )
    (recmd / "20261011T110631_recmd_meta.json").write_bytes(
        (fixtures / "20261011T110631_recmd_meta.json").read_bytes()
    )

    zones = record_case_host_timezones(case)
    assert len(zones) == 1
    zone = zones[0]
    assert zone["windows_timezone"] == "Eastern Standard Time"
    assert zone["iana_timezone"] == "America/New_York"
    assert zone["bias_minutes"] == 300
    assert zone["daylight_bias_minutes"] == -60
    assert zone["source_sha256"]
    assert zone["mapping_sha256"]
    assert zone["timezone_data_version"] == "2026.5"
    assert len(zone["timezone_data_sha256"]) == 64
    persisted = json.loads((case / "analysis" / "host_timezones.json").read_text(encoding="utf-8"))
    assert persisted["records"] == zones

    task_path = (
        tmp_path / "evidence" / "host1" / "Windows" / "System32" / "Tasks" / OFFICE.name
    )
    task_path.parent.mkdir(parents=True)
    task_path.write_bytes(OFFICE.read_bytes())
    task = parse_task_record(task_path)
    # The captured SYSTEM command names H:\C, while this real task XML lives in
    # the project corpus. Scope the proven zone to this fixture path to exercise
    # the normal ingest-to-index context handoff; H:\C matching is tested below.
    scoped_zone = {**zone, "evidence_root": windows_path_root(task_path)}
    monkeypatch.setattr(
        windows_timezones,
        "record_case_host_timezones",
        lambda _case_dir: [scoped_zone],
    )
    assert task["registration_date"] == "2017-08-05T12:13:18.0043321"

    from nexus.langgraph.case_index import iter_index_docs
    from nexus.langgraph.timeline_merge import ingest_into_case

    result = ingest_into_case(task_path, case, audit=False)
    assert result["success"] is True
    assert result["artifacts"] == 1
    doc = next(d for d in iter_index_docs(case) if d.get("family") == "scheduled_tasks")
    assert doc["ts"] == "2017-08-05T16:13:18Z"
    assert "ts_tz_assumed" not in doc
    # D399: a flag is written in the form a `boolean` column holds (`str()` wrote "False", which it rejects).
    assert doc["fields"]["ts_tz_assumed"] == "false"
    assert doc["fields"]["task_timezone_key_name"] == "Eastern Standard Time"
    assert doc["fields"]["task_timezone_iana"] == "America/New_York"


def test_c5_system_zone_is_matched_only_to_its_evidence_root(tmp_path, monkeypatch):
    from nexus.ingest.windows_timezones import record_case_host_timezones, timezone_for_task

    case = _seed_case(tmp_path, monkeypatch)
    recmd = case / "runs" / "RUN-D240-REAL-RECMD" / "extractions" / "recmd"
    output = recmd / "20261011110620"
    output.mkdir(parents=True)
    fixtures = REPO / "tests" / "fixtures" / "d240_timezone"
    (output / "20261011110620_TimeZoneInfo__SYSTEM.csv").write_bytes(
        (fixtures / "20261011110620_TimeZoneInfo__SYSTEM.csv").read_bytes()
    )
    (recmd / "20261011T110631_recmd_meta.json").write_bytes(
        (fixtures / "20261011T110631_recmd_meta.json").read_bytes()
    )
    zones = record_case_host_timezones(case)

    assert timezone_for_task(r"H:\C\Windows\System32\Tasks\SRL Update Service", zones) == zones[0]
    assert timezone_for_task(r"J:\D\Windows\System32\Tasks\another host task", zones) is None


def test_naive_registration_without_matching_zone_stays_flagged(tmp_path, monkeypatch):
    from datetime import UTC, datetime

    from nexus.ingest.df.scheduled_tasks import ScheduledTasksImporter

    artifact = list(ScheduledTasksImporter().parse(OFFICE))[0]
    assert artifact.timestamp == datetime(2017, 8, 5, 12, 13, 18, 4332, tzinfo=UTC)
    assert artifact.ts_tz_assumed is True
    assert artifact.raw["timezone_assumed"] is True

    case = _seed_case(tmp_path, monkeypatch)
    from nexus.langgraph.case_index import iter_index_docs
    from nexus.langgraph.timeline_merge import append_ingest_artifacts

    append_ingest_artifacts(case, [artifact])
    doc = next(d for d in iter_index_docs(case) if d.get("family") == "scheduled_tasks")
    assert doc["ts"] == "2017-08-05T12:13:18Z"
    assert doc["ts_tz_assumed"] is True
    assert doc["fields"]["ts_tz_assumed"] == "true"
    assert doc["fields"]["task_timezone_assumed"] == "true"


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
