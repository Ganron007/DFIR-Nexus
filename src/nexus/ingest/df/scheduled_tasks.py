r"""Scheduled Tasks XML importer.

Parses Windows scheduled task definitions from ``C:\Windows\System32\Tasks\``
(UTF-16, no file extension) and their UTF-8/XML exports. These are the standard
task scheduler format used by schtasks.exe and the Task Scheduler service.

WO-8: one record per task with the fields the lane's ``strings64`` pass could
never produce — ``uri``, ``author``, ``registration_date`` (a real timestamp),
``principal_user_id``/``run_level``/``logon_type``, ``hidden``/``enabled``,
every Exec action (command / arguments / working directory), ComHandler class
ids and typed triggers — so the index carries typed fields instead of flat
strings, and the task's own registration time replaces the file mtime.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar
from xml.etree import ElementTree as ET

from nexus.ingest.base import Importer
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)


def _local(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag


def _child_text(element: ET.Element | None, name: str) -> str:
    if element is None:
        return ""
    for child in element:
        if _local(child.tag) == name:
            return (child.text or "").strip()
    return ""


def _find_element(root: ET.Element, name: str) -> ET.Element | None:
    return next((el for el in root.iter() if _local(el.tag) == name), None)


def _find_text(root: ET.Element, name: str) -> str:
    el = _find_element(root, name)
    return (el.text or "").strip() if el is not None else ""


def _truthy_text(text: str) -> bool | None:
    value = (text or "").strip().lower()
    if not value:
        return None
    return value in ("true", "1", "yes")


def _parse_task_root(path: Path) -> ET.Element | None:
    """Parse the task document, trying each encoding until the XML parses.

    A UTF-16-LE decode of arbitrary bytes rarely raises, so encoding fallback
    must be driven by the parse result, not by decode success — otherwise a
    UTF-8 task file "decodes" as UTF-16 garbage and is dropped.
    """
    for encoding in ("utf-16", "utf-16-le", "utf-16-be", "utf-8-sig", "utf-8"):
        try:
            text = path.read_text(encoding=encoding, errors="strict")
        except (UnicodeDecodeError, UnicodeError, OSError):
            continue
        try:
            return ET.fromstring(text)
        except ET.ParseError:
            continue
    return None


def parse_task_record(path: Path) -> dict[str, Any] | None:
    """One JSON-ready task record, or None when the XML cannot be parsed.

    ``registration_date`` stays a raw ISO string here; the artifact timestamp
    is derived from it by the importer (falling back to the file mtime, flagged
    synthesized, only when the task carries no registration time).
    """
    p = Path(path)
    root = _parse_task_root(p)
    if root is None:
        return None

    reg = _find_element(root, "RegistrationInfo")
    uri = _child_text(reg, "URI") or _find_text(root, "URI")
    author = _child_text(reg, "Author") or _find_text(root, "Author")
    registration_date = _child_text(reg, "Date")
    description = _child_text(reg, "Description") or _find_text(root, "Description")

    principal = _find_element(root, "Principal")
    principal_user_id = _child_text(principal, "UserId")
    run_level = _child_text(principal, "RunLevel")
    logon_type = _child_text(principal, "LogonType")

    actions: list[dict[str, str]] = []
    com_handler_class_id = ""
    for el in root.iter():
        local = _local(el.tag)
        if local == "Exec":
            actions.append({
                "command": _child_text(el, "Command"),
                "arguments": _child_text(el, "Arguments"),
                "working_directory": _child_text(el, "WorkingDirectory"),
            })
        elif local == "ComHandler" and not com_handler_class_id:
            com_handler_class_id = _child_text(el, "ClassId")

    triggers: list[dict[str, Any]] = []
    for el in root.iter():
        local = _local(el.tag)
        if not local.endswith("Trigger"):
            continue
        repetition_el = next(
            (c for c in el if _local(c.tag) == "Repetition"), None
        )
        repetition = " ".join(
            part for part in (
                _child_text(repetition_el, "Interval"),
                _child_text(repetition_el, "Duration"),
            ) if part
        )
        enabled_text = _child_text(el, "Enabled")
        triggers.append({
            "type": local,
            "start_boundary": _child_text(el, "StartBoundary"),
            "enabled": _truthy_text(enabled_text) if enabled_text else None,
            "repetition": repetition,
        })

    settings = _find_element(root, "Settings")
    hidden = _truthy_text(_child_text(settings, "Hidden")) if settings is not None else None
    enabled = _truthy_text(_child_text(settings, "Enabled")) if settings is not None else None

    return {
        "name": p.stem,
        "uri": uri,
        "author": author,
        "registration_date": registration_date,
        "description": description,
        "principal_user_id": principal_user_id,
        "run_level": run_level,
        "logon_type": logon_type,
        "hidden": hidden,
        "enabled": enabled,
        "actions": actions,
        "com_handler_class_id": com_handler_class_id,
        "triggers": triggers,
        "source_file": str(p),
    }


def _registration_datetime(record: dict[str, Any]) -> datetime | None:
    raw = str(record.get("registration_date") or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


class ScheduledTasksImporter(Importer):
    """Parser for Windows Scheduled Task XML files.

    Output: one Artifact per scheduled task carrying the structured record in
    ``raw`` (typed through the field registry). Tasks that execute scripts or
    binaries from suspicious locations are flagged.
    """

    # Suspicious command patterns that warrant elevated severity
    SUSPICIOUS_PATTERNS: ClassVar[list[str]] = [
        r"(?i)\.ps1\b",
        r"(?i)\.vbs\b",
        r"(?i)\.js\b",
        r"(?i)\.hta\b",
        r"(?i)\.bat\b",
        r"(?i)\.cmd\b",
        r"(?i)\.wsf\b",
        r"(?i)powershell",
        r"(?i)cmd\.exe",
        r"(?i)wscript",
        r"(?i)cscript",
        r"(?i)mshta",
        r"(?i)rundll32",
        r"(?i)regsvr32",
        r"(?i)certutil",
        r"(?i)bitsadmin",
        r"(?i)wmic\b",
        r"(?i)\\temp\\",
        r"(?i)\\appdata\\",
        r"(?i)\\downloads\\",
        r"(?i)\\programdata\\",
    ]

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.SCHEDULED_TASKS

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: file in Tasks directory OR contains Task XML."""
        if not path.is_file():
            return False
        name_lower = path.name.lower()
        # File in C:\Windows\System32\Tasks\ — no extension by default
        if "tasks" in str(path).lower() and path.suffix == "":
            return True
        # Or explicitly named .xml with task namespace
        if name_lower.endswith(".xml") or name_lower.endswith(".job"):
            try:
                head = path.read_text(encoding="utf-16-le", errors="ignore")[:500]
                if "<Task" in head or "<?xml" in head:
                    return True
            except OSError:
                pass
        return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact from a scheduled task XML."""
        record = parse_task_record(path)
        if record is None:
            log.debug("Could not parse task XML: %s", path)
            return

        ts = _registration_datetime(record)
        ts_synthesized = ts is None
        if ts is None:
            try:
                ts = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
            except OSError:
                ts = datetime.now(UTC)

        severity = self._compute_severity(record)

        actions = [a for a in (record.get("actions") or []) if isinstance(a, dict)]
        cmd_str = "; ".join(
            f"{a.get('command', '')} {a.get('arguments', '')}".strip()
            for a in actions[:3]
        )
        task_name = str(record.get("name") or Path(path).stem)
        desc = f"Scheduled Task: {task_name}"
        if cmd_str:
            desc += f" → {cmd_str}"
        if record.get("author"):
            desc += f" (by {record['author']})"

        technique_ids: list[str] = []
        joined = " ".join(
            f"{a.get('command', '')} {a.get('arguments', '')}".lower()
            for a in actions
        )
        if any(
            pattern in joined
            for pattern in ("powershell", "cmd.exe", "wscript", "mshta", "regsvr32")
        ):
            technique_ids.append("T1053.005")  # Scheduled Task
        author = str(record.get("author") or "")
        if author and "\\" not in author and "@" not in author:
            technique_ids.append("T1547.002")  # Authentication Package or similar
        if not technique_ids:
            technique_ids.append("T1053.005")  # Default

        yield Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.PROCESS,
            source=ArtifactSource.SCHEDULED_TASKS,
            timestamp=ts,
            ts_synthesized=ts_synthesized,
            severity=severity,
            host=path.parent.parent.name if path.parent.parent else None,
            command_line=cmd_str,
            description=desc,
            raw=record,
            technique_ids=technique_ids,
            tags=["scheduled_task", f"author.{record.get('author') or 'unknown'}"],
        )

    def _compute_severity(self, record: dict[str, Any]) -> Severity:
        """Compute severity from the actions + principal the record carries."""
        severity = Severity.INFORMATIONAL
        joined = " ".join(
            f"{a.get('command', '')} {a.get('arguments', '')}"
            for a in (record.get("actions") or [])
            if isinstance(a, dict)
        )
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, joined):
                severity = Severity.HIGH
                break
        principal = str(record.get("principal_user_id") or "").upper()
        if severity == Severity.INFORMATIONAL and "SYSTEM" in principal:
            severity = Severity.LOW  # SYSTEM tasks are normal but worth noting
        return severity
