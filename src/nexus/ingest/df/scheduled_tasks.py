r"""Scheduled Tasks XML importer.

Parses Windows scheduled task XML files from `C:\Windows\System32\Tasks\`.
These are the standard task scheduler format used by schtasks.exe and
Task Scheduler service.
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


class ScheduledTasksImporter(Importer):
    """Parser for Windows Scheduled Task XML files.

    Output: one Artifact per scheduled task, with author, triggers, actions,
    and last run time. Tasks that execute scripts/binaries from suspicious
    locations are flagged.
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
        """Yield Artifact objects from a scheduled task XML."""
        # Try UTF-16 (Windows default for tasks) then UTF-8
        text = None
        for enc in ("utf-16-le", "utf-16-be", "utf-8-sig", "utf-8"):
            try:
                text = path.read_text(encoding=enc, errors="strict")
                break
            except (UnicodeDecodeError, UnicodeError):
                continue
        if text is None:
            log.warning("Could not decode task file: %s", path)
            return

        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            log.debug("XML parse error in %s: %s", path, e)
            return

        task_name = path.stem  # File name without extension is the task name
        # Gather info
        info = {
            "name": task_name,
            "uri": self._get_text(root, "*/{*}URI"),
            "author": self._get_text(root, "RegistrationInfo/Author"),
            "description": self._get_text(root, "RegistrationInfo/Description"),
            "triggers": self._extract_triggers(root),
            "actions": self._extract_actions(root),
            "principals": self._extract_principals(root),
            "settings": self._extract_settings(root),
        }

        # Severity
        severity = self._compute_severity(info)
        # Last run time
        last_run = None
        # Try to get mtime as last run proxy
        try:
            last_run = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        except OSError:
            last_run = datetime.now(UTC)

        # Description
        actions = list(info["actions"])
        cmd_str = "; ".join(actions[:3]) if actions else ""
        desc = f"Scheduled Task: {task_name}"
        if cmd_str:
            desc += f" → {cmd_str}"
        if info["author"]:
            desc += f" (by {info['author']})"

        # Technique IDs
        technique_ids = []
        if actions and any(
            p in actions[0].lower()
            for p in ["powershell", "cmd.exe", "wscript", "mshta", "regsvr32"]
        ):
            technique_ids.append("T1053.005")  # Scheduled Task
        if info["author"] and "\\" not in info["author"] and "@" not in info["author"]:
            # Possibly suspicious author
            technique_ids.append("T1547.002")  # Authentication Package or similar
        if not technique_ids:
            technique_ids.append("T1053.005")  # Default

        yield Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.PROCESS,
            source=ArtifactSource.UNKNOWN,
            timestamp=last_run,
            severity=severity,
            host=path.parent.parent.name if path.parent.parent else None,
            file_path=str(path),
            command_line=cmd_str,
            description=desc,
            raw=info,
            technique_ids=technique_ids,
            tags=["scheduled_task", f"author.{info['author'] or 'unknown'}"],
        )

    @staticmethod
    def _get_text(element: ET.Element, path: str) -> str:
        """Get the text of the first matching element."""
        ns_strip = path.replace("{*}", "")
        for el in element.iter():
            if el.tag.endswith(ns_strip.split("/")[-1]) or el.tag == path:
                return (el.text or "").strip()
        # Fallback: try without namespace
        for el in element.iter():
            local = el.tag.split("}")[-1] if "}" in el.tag else el.tag
            parts = path.replace("{*}", "").split("/")
            if local == parts[-1]:
                return (el.text or "").strip()
        return ""

    def _extract_triggers(self, root: ET.Element) -> list[str]:
        """Extract trigger descriptions."""
        triggers = []
        for trig in root.iter():
            local = trig.tag.split("}")[-1] if "}" in trig.tag else trig.tag
            if local == "Trigger":
                kind = ""
                for child in trig:
                    child_local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if child_local != "Enabled" and child_local != "StartBoundary" and child_local != "Repetition":
                        kind += f"{child_local} "
                triggers.append(kind.strip())
        return triggers

    def _extract_actions(self, root: ET.Element) -> list[str]:
        """Extract action commands."""
        actions = []
        for action in root.iter():
            local = action.tag.split("}")[-1] if "}" in action.tag else action.tag
            if local in ("Exec", "Command"):
                cmd = (action.text or "").strip()
                args = ""
                for arg in action:
                    arg_local = arg.tag.split("}")[-1] if "}" in arg.tag else arg.tag
                    if arg_local == "Arguments":
                        args = (arg.text or "").strip()
                if cmd:
                    actions.append(f"{cmd} {args}".strip())
        return actions

    def _extract_principals(self, root: ET.Element) -> list[str]:
        """Extract principal info."""
        principals = []
        for principal in root.iter():
            local = principal.tag.split("}")[-1] if "}" in principal.tag else principal.tag
            if local == "Principal":
                user = self._get_text(principal, "UserId")
                run_level = self._get_text(principal, "RunLevel")
                logon_type = self._get_text(principal, "LogonType")
                principals.append(f"{user} (run={run_level}, logon={logon_type})")
        return principals

    def _extract_settings(self, root: ET.Element) -> dict[str, str]:
        """Extract task settings."""
        settings = {}
        for setting in root.iter():
            local = setting.tag.split("}")[-1] if "}" in setting.tag else setting.tag
            if local == "Settings":
                for child in setting:
                    child_local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if child.text:
                        settings[child_local] = (child.text or "").strip()
        return settings

    def _compute_severity(self, info: dict[str, Any]) -> Severity:
        """Compute severity based on action patterns and author."""
        # Default informational
        severity = Severity.INFORMATIONAL
        for action in info["actions"]:
            for pattern in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, action):
                    severity = Severity.HIGH
                    break
            if severity == Severity.HIGH:
                break
        # SYSTEM-level or NULL author can be suspicious
        if any("SYSTEM" in p for p in info["principals"]) and severity == Severity.INFORMATIONAL:
            severity = Severity.LOW  # SYSTEM tasks are normal but worth noting
        return severity
