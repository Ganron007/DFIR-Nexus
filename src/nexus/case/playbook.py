"""Response playbook — trackable IR checklist with templates.

Provides pre-built incident response playbooks (Contain → Investigate →
Eradicate → Recover) and custom playbook creation. Each task has:
- status: pending / in_progress / completed / blocked / skipped
- priority: critical / high / medium / low
- assignee: optional examiner name
- due: optional datetime
- notes: free-text

Inspired by DFIR-Companion's playbook.ts.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class TaskStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


class TaskPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PlaybookTask:
    """A single task in a response playbook."""
    id: str
    title: str
    description: str = ""
    status: TaskStatus = TaskStatus.PENDING
    priority: TaskPriority = TaskPriority.MEDIUM
    assignee: str = ""
    due: datetime | None = None
    notes: list[str] = field(default_factory=list)
    phase: str = ""
    completed_at: datetime | None = None

    def complete(self, note: str = "") -> None:
        self.status = TaskStatus.COMPLETED
        self.completed_at = datetime.now(UTC)
        if note:
            self.notes.append(note)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "priority": self.priority.value,
            "assignee": self.assignee,
            "due": self.due.isoformat() if self.due else None,
            "notes": self.notes,
            "phase": self.phase,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PlaybookTask:
        d = dict(data)
        d["status"] = TaskStatus(d.get("status", "pending"))
        d["priority"] = TaskPriority(d.get("priority", "medium"))
        if isinstance(d.get("due"), str):
            d["due"] = datetime.fromisoformat(d["due"])
        if isinstance(d.get("completed_at"), str):
            d["completed_at"] = datetime.fromisoformat(d["completed_at"])
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class Playbook:
    """A response playbook with phases and tasks."""
    name: str
    description: str = ""
    tasks: list[PlaybookTask] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def phases(self) -> list[str]:
        return list(dict.fromkeys(t.phase for t in self.tasks if t.phase))

    @property
    def progress(self) -> dict[str, Any]:
        total = len(self.tasks)
        completed = sum(1 for t in self.tasks if t.status == TaskStatus.COMPLETED)
        in_progress = sum(1 for t in self.tasks if t.status == TaskStatus.IN_PROGRESS)
        blocked = sum(1 for t in self.tasks if t.status == TaskStatus.BLOCKED)
        return {
            "total": total,
            "completed": completed,
            "in_progress": in_progress,
            "blocked": blocked,
            "pending": total - completed - in_progress - blocked,
            "percent_complete": (completed / total * 100) if total > 0 else 0,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "tasks": [t.to_dict() for t in self.tasks],
            "progress": self.progress,
            "phases": self.phases,
            "created_at": self.created_at.isoformat(),
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, default=str))

    @classmethod
    def load(cls, path: Path) -> Playbook:
        data = json.loads(path.read_text(encoding="utf-8"))
        tasks = [PlaybookTask.from_dict(t) for t in data.get("tasks", [])]
        return cls(
            name=data.get("name", "Unnamed"),
            description=data.get("description", ""),
            tasks=tasks,
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(UTC),
        )


def create_ir_playbook() -> Playbook:
    """Create a standard Incident Response playbook.

    Phases: Contain → Investigate → Eradicate → Recover → Lessons Learned.
    """
    tasks = []
    task_num = 0

    phases = {
        "contain": [
            ("Isolate affected hosts from network", TaskPriority.CRITICAL),
            ("Disable compromised accounts", TaskPriority.CRITICAL),
            ("Block known-bad IPs/domains at firewall", TaskPriority.HIGH),
            ("Preserve volatile evidence (memory, process list)", TaskPriority.HIGH),
            ("Disable remote access for affected systems", TaskPriority.HIGH),
        ],
        "investigate": [
            ("Identify initial access vector", TaskPriority.HIGH),
            ("Map attacker lateral movement", TaskPriority.HIGH),
            ("Determine data exfiltrated", TaskPriority.CRITICAL),
            ("Identify persistence mechanisms", TaskPriority.HIGH),
            ("Build complete timeline of attacker activity", TaskPriority.HIGH),
            ("Correlate with threat intelligence", TaskPriority.MEDIUM),
        ],
        "eradicate": [
            ("Remove malware/backdoors from all systems", TaskPriority.CRITICAL),
            ("Remove unauthorized accounts and credentials", TaskPriority.HIGH),
            ("Patch exploited vulnerabilities", TaskPriority.HIGH),
            ("Reset compromised credentials", TaskPriority.HIGH),
            ("Remove attacker persistence (scheduled tasks, services, registry)", TaskPriority.HIGH),
        ],
        "recover": [
            ("Restore systems from known-good backups", TaskPriority.HIGH),
            ("Rebuild compromised systems", TaskPriority.HIGH),
            ("Re-enable network access for recovered systems", TaskPriority.MEDIUM),
            ("Monitor for re-infection (72 hours)", TaskPriority.HIGH),
            ("Verify data integrity", TaskPriority.MEDIUM),
        ],
        "lessons_learned": [
            ("Document incident timeline and response actions", TaskPriority.MEDIUM),
            ("Identify detection gaps", TaskPriority.MEDIUM),
            ("Update detection rules for observed TTPs", TaskPriority.MEDIUM),
            ("Update incident response procedures", TaskPriority.LOW),
            ("Brief management on findings and recommendations", TaskPriority.MEDIUM),
        ],
    }

    for phase, items in phases.items():
        for title, priority in items:
            task_num += 1
            tasks.append(PlaybookTask(
                id=f"IR-{task_num:03d}",
                title=title,
                priority=priority,
                phase=phase,
            ))

    return Playbook(
        name="Standard Incident Response",
        description="Contain → Investigate → Eradicate → Recover → Lessons Learned",
        tasks=tasks,
    )


def create_ransomware_playbook() -> Playbook:
    """Create a ransomware-specific incident response playbook."""
    tasks = []
    task_num = 0

    items = [
        ("contain", "Isolate ALL affected endpoints immediately", TaskPriority.CRITICAL),
        ("contain", "Disable file shares and mapped drives", TaskPriority.CRITICAL),
        ("contain", "Identify ransomware variant from encryption pattern/notes", TaskPriority.HIGH),
        ("contain", "Preserve ransom note and encrypted file samples", TaskPriority.HIGH),
        ("investigate", "Determine patient zero (initial infection vector)", TaskPriority.HIGH),
        ("investigate", "Map spread across the network", TaskPriority.HIGH),
        ("investigate", "Check backup integrity (offline backups preferred)", TaskPriority.CRITICAL),
        ("investigate", "Identify data exfiltration (double extortion)", TaskPriority.CRITICAL),
        ("investigate", "Check for domain controller compromise", TaskPriority.CRITICAL),
        ("eradicate", "Rebuild affected systems from known-good images", TaskPriority.HIGH),
        ("eradicate", "Reset ALL domain credentials (krbtgt twice)", TaskPriority.CRITICAL),
        ("eradicate", "Patch exploited vulnerabilities", TaskPriority.HIGH),
        ("recover", "Restore from verified clean backups", TaskPriority.HIGH),
        ("recover", "Monitor for re-infection for 7 days", TaskPriority.HIGH),
        ("recover", "Notify affected parties per regulatory requirements", TaskPriority.CRITICAL),
        ("lessons_learned", "Document attack chain and response timeline", TaskPriority.MEDIUM),
        ("lessons_learned", "Update detection rules for observed IOCs/TTPs", TaskPriority.MEDIUM),
    ]

    for phase, title, priority in items:
        task_num += 1
        tasks.append(PlaybookTask(
            id=f"RW-{task_num:03d}",
            title=title,
            priority=priority,
            phase=phase,
        ))

    return Playbook(
        name="Ransomware Incident Response",
        description="Ransomware-specific containment, investigation, and recovery playbook",
        tasks=tasks,
    )
