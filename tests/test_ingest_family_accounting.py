"""Imported rows count per family, and scheduled tasks are one of them (WO-TA item 4, check 5).

Reproduced on SC1 (2026-10-10): the importer put 237 scheduled-task rows in
``ingest/artifacts.jsonl``, and the index counted that whole store as one file. No
``tasks`` or ``scheduled_tasks`` count existed, so the coverage probe read zero task
documents. The importer also rejected five real tasks whose names contain dots.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.analysis.reconciliation import reconcile_case
from nexus.ingest.df.scheduled_tasks import ScheduledTasksImporter
from nexus.langgraph.case_index import iter_index_doc_batches


def _store_row(source: str, text: str) -> str:
    return json.dumps({
        "source": source, "artifact_type": "x", "timestamp": "2026-10-10T00:00:00+00:00",
        "description": text,
    })


def _case_with_store(tmp_path: Path, rows: list[str]) -> Path:
    case = tmp_path / "CASE-FAM0001"
    (case / "ingest").mkdir(parents=True)
    (case / "ingest" / "artifacts.jsonl").write_text("\n".join(rows) + "\n", encoding="utf-8")
    return case


def test_the_store_is_counted_per_family(tmp_path):
    case = _case_with_store(tmp_path, [
        _store_row("scheduled_tasks", "task one"),
        _store_row("scheduled_tasks", "task two"),
        _store_row("amcache", "an entry"),
    ])
    stats: dict = {}

    for _batch in iter_index_doc_batches(case, stats=stats):
        pass

    counts = stats["file_counts"]
    assert counts["scheduled_tasks/artifacts.jsonl"]["docs"] == 2
    assert counts["amcache/artifacts.jsonl"]["docs"] == 1
    assert "ingest/artifacts.jsonl" not in counts, "no whole-store key once families are counted"


def test_the_reconciler_checks_a_family_against_its_own_rows(tmp_path):
    case = _case_with_store(tmp_path, [
        _store_row("scheduled_tasks", "task one"),
        _store_row("scheduled_tasks", "task two"),
        _store_row("amcache", "an entry"),
    ])
    analysis = case / "analysis"
    analysis.mkdir()
    (analysis / "es_index.json").write_text(json.dumps({
        "docs": 3,
        "file_counts": {
            "scheduled_tasks/artifacts.jsonl": {"docs": 2, "deduped": 0},
            "amcache/artifacts.jsonl": {"docs": 1, "deduped": 0},
        },
    }), encoding="utf-8")

    report = reconcile_case(case)

    by_file = {row["file"]: row for row in report["files"]}
    assert by_file["scheduled_tasks/artifacts.jsonl"]["source_records"] == 2
    assert by_file["scheduled_tasks/artifacts.jsonl"]["status"] == "match"
    assert by_file["amcache/artifacts.jsonl"]["source_records"] == 1


def test_a_dotted_task_name_in_a_tasks_folder_is_a_task(tmp_path):
    # Verbatim shape of a real SC1 task: UTF-16 with a BOM, and a dotted name with no extension.
    task = tmp_path / "Windows" / "System32" / "Tasks" / ".NET Framework NGEN v4.0.30319"
    task.parent.mkdir(parents=True)
    task.write_bytes("﻿<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task version=\"1.2\"/>".encode("utf-16"))

    assert ScheduledTasksImporter.can_handle(task)


def test_a_file_outside_a_tasks_folder_is_not_a_task(tmp_path):
    other = tmp_path / "Users" / "x" / "notes.bin"
    other.parent.mkdir(parents=True)
    other.write_bytes(b"<Task version=\"1.2\"/>")

    assert not ScheduledTasksImporter.can_handle(other)
