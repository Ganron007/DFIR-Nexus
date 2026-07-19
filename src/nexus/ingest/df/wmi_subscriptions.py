"""WMI Event Subscription parser.

Parses WMI Event Subscriptions (EventConsumer + EventFilter + FilterToConsumerBinding),
which are a well-known malware persistence technique (T1546.013).

Two modes:
1. **MOF mode**: Parse the MOF (Managed Object Format) export from `mofcomp` / WMI repository dumps
2. **CSV mode**: Pre-exported CSV from WMI tools (e.g., Sysinternals, KAPE)
"""

from __future__ import annotations

import csv
import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from nexus.ingest.base import Importer
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)


class WMISubscriptionsImporter(Importer):
    """Parser for WMI Event Subscriptions (EventFilter / EventConsumer / Binding)."""

    SUSPICIOUS_CONSUMER_PATTERNS: ClassVar[list[str]] = [
        r"(?i)powershell",
        r"(?i)cmd\.exe",
        r"(?i)\.vbs",
        r"(?i)\.js\b",
        r"(?i)\.ps1",
        r"(?i)mshta",
        r"(?i)rundll32",
        r"(?i)regsvr32",
        r"(?i)wmic",
        r"(?i)bitsadmin",
        r"(?i)\\temp\\",
        r"(?i)\\appdata\\",
    ]

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.WMI_SUBSCRIPTIONS

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: contains WMI subscription keywords."""
        if not path.is_file():
            return False
        name_lower = path.name.lower()
        if name_lower in {"wmi_subscriptions.csv", "wmi_subscriptions.mof", "subscriptions.csv", "wmi.csv"}:
            return True
        if name_lower.endswith((".mof", ".csv")):
            try:
                head = path.read_text(encoding="utf-8", errors="replace")[:4096]
            except OSError:
                return False
            return any(
                kw in head
                for kw in [
                    "EventFilter", "EventConsumer", "FilterToConsumerBinding",
                    "__EventFilter", "__EventConsumer", "CommandLineEventConsumer",
                ]
            )
        return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a WMI subscriptions export."""
        if path.suffix.lower() == ".mof":
            yield from self._parse_mof(path)
        else:
            yield from self._parse_csv(path)

    # ----- CSV mode -----

    def _parse_csv(self, path: Path) -> Iterator[Artifact]:
        """Parse CSV with WMI subscriptions (EventConsumer + EventFilter rows)."""
        try:
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    record = {k: (str(v) if v is not None else "") for k, v in row.items()}
                    yield self._record_to_artifact(record, str(path))
        except OSError as e:
            log.warning("Could not read %s: %s", path, e)

    def _record_to_artifact(self, record: dict[str, Any], source_path: str) -> Artifact:
        """Map a WMI subscription record to an Artifact."""
        def get(*keys: str) -> str:
            for k in keys:
                for rk, rv in record.items():
                    if rk.lower() == k.lower() and rv:
                        return str(rv)
            return ""

        # EventConsumer fields
        consumer_name = get("Name", "ConsumerName", "__RELPATH")
        command_line = get(
            "CommandLineTemplate", "ScriptText", "Script", "Command",
            "ExecutablePath", "CommandLine",
        )
        # EventFilter fields
        filter_name = get("FilterName")
        query = get("Query", "QueryLanguage", "EventNamespace")
        query = str(query)
        # Binding

        # Decide artifact type
        artifact_type = ArtifactType.PROCESS
        if query or filter_name:
            artifact_type = ArtifactType.ALERT

        # Severity
        severity = Severity.INFORMATIONAL
        for pattern in self.SUSPICIOUS_CONSUMER_PATTERNS:
            if re.search(pattern, command_line):
                severity = Severity.HIGH
                break
        # Active timer-based filters with suspicious commands are CRITICAL
        if severity == Severity.HIGH and ("__TIMER" in query.upper() or "__INTERVAL" in query.upper()):
            severity = Severity.CRITICAL

        # Description
        if consumer_name:
            desc = f"WMI EventConsumer: {consumer_name}"
            if command_line:
                desc += f" -> {command_line[:200]}"
            elif filter_name:
                desc = f"WMI EventFilter: {filter_name}"
                if query:
                    desc += f" (query: {query[:200]})"
        else:
            desc = "WMI Subscription entry"
            if query:
                desc += f" query={query[:200]}"

        # Timestamp
        ts_str = get("Timestamp", "Created", "CreationTime")
        ts = self.normalize_timestamp(ts_str) if ts_str else None
        if ts is None:
            try:
                ts = datetime.fromtimestamp(Path(source_path).stat().st_mtime, tz=UTC)
            except OSError:
                ts = datetime.now(UTC)

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.UNKNOWN,
            timestamp=ts,
            severity=severity,
            description=desc,
            command_line=command_line or None,
            raw=record,
            technique_ids=["T1546.013"],
            tags=["wmi_subscription", f"consumer.{(consumer_name or 'unknown').lower()}"],
        )

    # ----- MOF mode -----

    MOF_CLASSES: ClassVar[set[str]] = {
        "EventFilter", "CommandLineEventConsumer", "ScriptEventConsumer",
        "ActiveScriptEventConsumer", "NTEventLogConsumer", "SMTPEventConsumer",
        "FilterToConsumerBinding", "__EventConsumer", "__EventFilter",
    }

    def _parse_mof(self, path: Path) -> Iterator[Artifact]:
        """Parse MOF (Managed Object Format) export."""
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            log.warning("Could not read %s: %s", path, e)
            return

        # MOF class instances look like:
        #   instance of __EventFilter {
        #       Name = "Something";
        #       Query = "SELECT * FROM __TimerEvent...";
        #   };
        # We extract each "instance of X" block.
        instance_blocks = re.findall(
            r"instance\s+of\s+(\w+)\s*\{([^}]*)\}",
            text,
            re.DOTALL | re.IGNORECASE,
        )
        for class_name, body in instance_blocks:
            if class_name not in self.MOF_CLASSES:
                continue
            record = {"Class": class_name}
            for line_match in re.finditer(r'^\s*(\w+)\s*=\s*"([^"]*)"\s*;', body, re.MULTILINE):
                record[line_match.group(1)] = line_match.group(2)
            yield self._record_to_artifact(record, str(path))
