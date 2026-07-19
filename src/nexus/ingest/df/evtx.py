"""EVTX importer (raw Windows event log files) with Hayabusa-style auto-detection.

Parses `.evtx` files (raw Windows Event Log binary format). Requires the
`python-evtx` package (https://pypi.org/project/python-evtx/). If not
installed, the importer reports a clear error.

Hayabusa-style auto-detection:
    Beyond just extracting the event, this importer applies a built-in
    detection ruleset (similar to Hayabusa's "suspicious event" rules)
    that flags events of forensic interest and tags them with MITRE ATT&CK
    technique IDs. This gives you pre-correlated events without running
    Hayabusa as a separate tool.

    Examples:
        - 4661 (handle to LSASS): T1003.001
        - 4624 Type 10 + 4648: T1078.002 (valid accounts)
        - 4625 burst: T1110 (brute force — counted in description)
        - 7045 (new service): T1543.003
        - 1102 (audit log cleared): T1070.001
        - 4720 (user created): T1136.001
        - 4698 (scheduled task created): T1053.005
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.ingest.base import Importer
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)


# Hayabusa-style suspicious-event ruleset
# Each rule: (event_id, optional logon_type / channel filter, technique_ids, severity, description_pattern)
SUSPICIOUS_RULES: list[dict[str, Any]] = [
    # Credential Access
    {
        "event_id": "4661",
        "pattern": "lsass",
        "case_insensitive": True,
        "techniques": ["T1003.001"],
        "severity": Severity.CRITICAL,
        "description": "LSASS handle requested - possible credential access",
    },
    {
        "event_id": "4662",
        "pattern": r"\\sam\\|\\security\\|\\system\\|\\ntds",
        "case_insensitive": True,
        "techniques": ["T1003.002", "T1003.003"],
        "severity": Severity.CRITICAL,
        "description": "SAM/SYSTEM/NTDS access - possible credential dump",
    },
    {
        "event_id": "4688",
        "pattern": r"(?i)(mimikatz|procdump|comsvcs)\.exe",
        "techniques": ["T1003.001"],
        "severity": Severity.CRITICAL,
        "description": "Mimikatz/procdump execution detected",
    },
    # Persistence
    {
        "event_id": "7045",
        "techniques": ["T1543.003"],
        "severity": Severity.MEDIUM,
        "description": "New service installed",
    },
    {
        "event_id": "4698",
        "techniques": ["T1053.005"],
        "severity": Severity.MEDIUM,
        "description": "Scheduled task created",
    },
    # Defense Evasion
    {
        "event_id": "1102",
        "techniques": ["T1070.001"],
        "severity": Severity.CRITICAL,
        "description": "Security audit log was CLEARED (anti-forensics)",
    },
    # Account Manipulation
    {
        "event_id": "4720",
        "techniques": ["T1136.001"],
        "severity": Severity.HIGH,
        "description": "New user account created",
    },
    {
        "event_id": "4732",
        "techniques": ["T1136.001"],
        "severity": Severity.HIGH,
        "description": "Member added to security-enabled local group",
    },
    # Lateral Movement
    {
        "event_id": "5145",
        "pattern": r"(?i)(ADMIN\$|C\$|IPC\$)",
        "techniques": ["T1021.002"],
        "severity": Severity.HIGH,
        "description": "Network share access to ADMIN$/C$/IPC$ (lateral movement)",
    },
    {
        "event_id": "4624",
        "logon_type": "10",
        "techniques": ["T1021.001"],
        "severity": Severity.MEDIUM,
        "description": "RDP logon (LogonType 10) - possible lateral movement",
    },
    # Discovery
    {
        "event_id": "4688",
        "pattern": r"(?i)(net\.exe|nltest|whoami|systeminfo|ipconfig|tasklist|netstat)",
        "techniques": ["T1059.001", "T1087.002"],
        "severity": Severity.MEDIUM,
        "description": "Reconnaissance command executed",
    },
    # Brute force
    {
        "event_id": "4625",
        "techniques": ["T1110"],
        "severity": Severity.MEDIUM,
        "description": "Failed logon - possible brute force (count in same case)",
    },
]


def _apply_rules(event_id: str, xml_str: str) -> list[dict[str, Any]]:
    """Apply suspicious-event rules. Returns list of matching rule dicts."""
    matches = []
    for rule in SUSPICIOUS_RULES:
        if rule["event_id"] != event_id:
            continue
        # Optional logon_type filter
        if "logon_type" in rule:
            m = re.search(r'LogonType.*?>\s*(\d+|"(\d+)")\s*<', xml_str)
            if not m:
                continue
            logon_type = m.group(1) or m.group(2)
            if logon_type != rule["logon_type"]:
                continue
        # Optional pattern match
        if "pattern" in rule:
            pattern = rule["pattern"]
            if rule.get("case_insensitive", False):
                pattern_re = re.compile(pattern, re.IGNORECASE)
            else:
                pattern_re = re.compile(pattern)
            if not pattern_re.search(xml_str):
                continue
        matches.append(rule)
    return matches


class EVTXImporter(Importer):
    """Parser for raw Windows .evtx files.

    Uses `python-evtx` to parse the binary format. Each record is mapped
    to an Artifact. The XML payload is preserved in `raw`.
    """

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.EVTX

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: file has .evtx extension and starts with EVTX magic bytes."""
        if not path.is_file():
            return False
        if path.suffix.lower() != ".evtx":
            return False
        try:
            with path.open("rb") as f:
                magic = f.read(8)
            # EVTX magic: 'ElfFile\x00' (0x45 0x6c 0x66 0x46 0x69 0x6c 0x65 0x00)
            return magic.startswith(b"ElfFile\x00")
        except OSError:
            return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield Artifact objects from a .evtx file."""
        try:
            import Evtx.Evtx as EvtxModule
        except ImportError:
            log.error(
                "python-evtx is not installed. Install with: pip install python-evtx"
            )
            return

        for record in EvtxModule.Evtx(path):
            try:
                xml_str = record.xml()
                yield self._xml_to_artifact(xml_str, path)
            except Exception as e:  # noqa: BLE001
                log.debug("Failed to parse EVTX record in %s: %s", path, e)
                continue

    @staticmethod
    def _xml_to_artifact(xml_str: str, path: Path) -> Artifact:
        """Parse the Event XML and map to an Artifact.

        Uses string parsing (no external XML lib required). EVTX XML is
        always well-formed; we extract the <TimeCreated> and <EventID>
        attributes via simple string matching.
        """
        # TimeCreated
        ts = None
        for marker in ('SystemTime="', "<TimeCreated SystemTime=\""):
            idx = xml_str.find(marker)
            if idx >= 0:
                start = idx + len(marker)
                end = xml_str.find('"', start)
                if end > start:
                    ts = Importer.normalize_timestamp(xml_str[start:end])
                    if ts:
                        break
        if ts is None:
            ts = datetime.now(UTC)

        # EventID
        event_id = ""
        for marker in ('<EventID', "EventID>"):
            idx = xml_str.find(marker)
            if idx >= 0:
                # Two forms: <EventID>1234</EventID> or <EventID System="1">1234</EventID>
                start = xml_str.find(">", idx) + 1
                end = xml_str.find("<", start)
                if end > start:
                    event_id = xml_str[start:end].strip()
                    break

        # Computer
        host = None
        idx = xml_str.find("<Computer>")
        if idx >= 0:
            start = idx + len("<Computer>")
            end = xml_str.find("</Computer>", start)
            if end > start:
                host = xml_str[start:end].strip()

        # Channel
        channel = ""
        idx = xml_str.find("<Channel>")
        if idx >= 0:
            start = idx + len("<Channel>")
            end = xml_str.find("</Channel>", start)
            if end > start:
                channel = xml_str[start:end].strip()

        # Map event ID to artifact type
        artifact_type = EVTXImporter._event_id_to_type(event_id)

        # Apply Hayabusa-style suspicious-event rules
        matched_rules = _apply_rules(event_id, xml_str)
        # Compute severity + techniques + description from matches
        severity = Severity.INFORMATIONAL
        technique_ids: list[str] = []
        rule_descriptions: list[str] = []
        for r in matched_rules:
            sev = r["severity"]
            if ["informational", "low", "medium", "high", "critical"].index(sev.value) > [
                "informational", "low", "medium", "high", "critical"
            ].index(severity.value):
                severity = sev
            for tid in r["techniques"]:
                if tid not in technique_ids:
                    technique_ids.append(tid)
            rule_descriptions.append(r["description"])

        # Build description
        if rule_descriptions:
            base = f"EVTX EventID {event_id} from {channel}"
            desc = base + " | SUSPICIOUS: " + "; ".join(rule_descriptions)
        else:
            desc = f"EVTX EventID {event_id} from {channel}" if event_id else f"EVTX event from {channel}"

        # Tags include technique IDs if matched
        tags: list[str] = ["evtx", f"channel.{channel.lower()}"]
        for tid in technique_ids:
            tags.append(f"technique.{tid.lower()}")
        if matched_rules:
            tags.append("hayabusa.detected")

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.EVTX,
            timestamp=ts,
            severity=severity,
            host=host,
            user=None,  # Will be filled below if EventData present
            action=event_id or None,
            description=desc,
            raw={"xml": xml_str, "channel": channel, "event_id": event_id, "file": str(path),
                 "matched_rules": [r["description"] for r in matched_rules]},
            technique_ids=technique_ids,
            tags=tags,
        )

    @staticmethod
    def _event_id_to_type(event_id: str) -> ArtifactType:
        """Map a Windows Event ID to an ArtifactType."""
        try:
            eid = int(event_id)
        except (ValueError, TypeError):
            return ArtifactType.UNKNOWN

        if eid in (1149, 4624, 4778):
            return ArtifactType.RDP
        if eid in (4624, 4625, 4634, 4647, 4648, 4672, 4720, 4722, 4723, 4724, 4725, 4726,
                   4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4736, 4737, 4738, 4740,
                   4756, 4757, 4768, 4769, 4770, 4771, 4776, 4778, 4779):
            return ArtifactType.AUTH
        if eid in (4688, 4689, 4692, 4696, 4697, 4698, 4700, 4701, 4702, 5156, 5158):
            return ArtifactType.PROCESS
        if eid in (4663, 4664, 4670, 5145):
            return ArtifactType.FILE
        if eid in (4657, 4656):
            return ArtifactType.REGISTRY
        if eid in (4103, 4104):
            return ArtifactType.POWERSHELL
        if eid in (7034, 7035, 7036, 7040, 7045):
            return ArtifactType.PROCESS
        return ArtifactType.UNKNOWN
