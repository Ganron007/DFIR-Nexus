"""Tests for response playbook — IR checklist and templates."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from nexus.case.playbook import (
    create_ir_playbook,
    create_ransomware_playbook,
    Playbook,
    PlaybookTask,
    TaskStatus,
    TaskPriority,
)


class TestPlaybook:
    def test_ir_playbook_has_phases(self) -> None:
        pb = create_ir_playbook()
        assert pb.name == "Standard Incident Response"
        assert len(pb.phases) == 5
        assert "contain" in pb.phases
        assert "investigate" in pb.phases
        assert "eradicate" in pb.phases
        assert "recover" in pb.phases
        assert "lessons_learned" in pb.phases

    def test_ir_playbook_has_tasks(self) -> None:
        pb = create_ir_playbook()
        assert len(pb.tasks) >= 20

    def test_ransomware_playbook(self) -> None:
        pb = create_ransomware_playbook()
        assert pb.name == "Ransomware Incident Response"
        assert len(pb.tasks) >= 10
        critical = [t for t in pb.tasks if t.priority == TaskPriority.CRITICAL]
        assert len(critical) >= 3

    def test_task_completion(self) -> None:
        task = PlaybookTask(id="T-001", title="Test task")
        assert task.status == TaskStatus.PENDING
        task.complete("Done")
        assert task.status == TaskStatus.COMPLETED
        assert task.completed_at is not None
        assert "Done" in task.notes

    def test_progress_tracking(self) -> None:
        pb = create_ir_playbook()
        initial = pb.progress
        assert initial["completed"] == 0
        assert initial["total"] == len(pb.tasks)
        pb.tasks[0].complete()
        pb.tasks[1].complete()
        progress = pb.progress
        assert progress["completed"] == 2
        assert progress["percent_complete"] > 0

    def test_save_load_roundtrip(self) -> None:
        pb = create_ir_playbook()
        pb.tasks[0].complete("test note")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "playbook.json"
            pb.save(path)
            loaded = Playbook.load(path)
            assert loaded.name == pb.name
            assert len(loaded.tasks) == len(pb.tasks)
            assert loaded.tasks[0].status == TaskStatus.COMPLETED

    def test_to_dict(self) -> None:
        pb = create_ir_playbook()
        d = pb.to_dict()
        assert "name" in d
        assert "tasks" in d
        assert "progress" in d
        assert "phases" in d
        assert len(d["tasks"]) == len(pb.tasks)
