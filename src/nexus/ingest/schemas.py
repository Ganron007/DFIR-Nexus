"""Common schemas for the Ingest Layer.

The Artifact is the normalized representation of an event or piece of evidence
imported from a third-party forensic tool. Every importer converts its native
format to one or more Artifacts so that downstream analysis modules can
operate on a uniform schema.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class ArtifactType(StrEnum):
    """The kind of forensic event an Artifact represents."""

    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    REGISTRY = "registry"
    AUTH = "auth"
    ALERT = "alert"
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"
    SMTP = "smtp"
    SSH = "ssh"
    RDP = "rdp"
    POWERSHELL = "powershell"
    MALWARE = "malware"
    IOC = "ioc"
    THREAT_INTEL = "threat_intel"
    HUNT_RESULT = "hunt_result"
    UNKNOWN = "unknown"


class ArtifactSource(StrEnum):
    """The forensic tool or system the Artifact was imported from."""

    SURICATA = "suricata"
    ZEEK = "zeek"
    ELASTIC = "elastic"
    SPLUNK = "splunk"
    SENTINEL = "sentinel"
    DEFENDER = "defender"
    CROWDSTRIKE = "crowdstrike"
    CARBON_BLACK = "carbon_black"
    HAYABUSA = "hayabusa"
    PLASO = "plaso"
    KAPE = "kape"
    PREFETCH = "prefetch"
    VELOCIRAPTOR = "velociraptor"
    EVTX = "evtx"
    MISP = "misp"
    OTX = "otx"
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    THREATFOX = "threatfox"
    SHODAN = "shodan"
    GREYNOISE = "greynoise"
    THEHIVE = "thehive"
    WIRESHARK = "wireshark"
    VOLATILITY = "volatility"
    CLOUDTRAIL = "cloudtrail"
    AZURE = "azure"
    GCP = "gcp"
    AUDITD = "auditd"
    SYSLOG = "syslog"
    AUTHLOG = "authlog"
    BASH_HISTORY = "bash_history"
    BROWSER_HISTORY = "browser_history"
    LNK = "lnk"
    GENERIC_JSONL = "generic_jsonl"
    GENERIC_CSV = "generic_csv"
    AMCACHE = "amcache"
    WINDOWS_REGISTRY = "windows_registry"
    SCHEDULED_TASKS = "scheduled_tasks"
    WINDOWS_SERVICES = "windows_services"
    WMI_SUBSCRIPTIONS = "wmi_subscriptions"
    SECURITY_ONION = "security_onion"
    CYBERTRIAGE = "cybertriage"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    """How serious the event is."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @classmethod
    def normalize(cls, value: str | int | None) -> Severity:
        """Map arbitrary inputs (e.g. Suricata's 1-3, Splunk's 1-5) to the enum."""
        if value is None:
            return cls.INFORMATIONAL
        if isinstance(value, int):
            mapping = {1: cls.CRITICAL, 2: cls.HIGH, 3: cls.MEDIUM, 4: cls.LOW}
            return mapping.get(value, cls.INFORMATIONAL)
        s = str(value).strip().lower()
        if s in {"critical", "crit", "1"}:
            return cls.CRITICAL
        if s in {"high", "error", "2"}:
            return cls.HIGH
        if s in {"medium", "med", "warning", "warn", "3"}:
            return cls.MEDIUM
        if s in {"low", "4"}:
            return cls.LOW
        if s in {"informational", "info", "5", "0"}:
            return cls.INFORMATIONAL
        return cls.INFORMATIONAL


class NetworkProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    SMB = "smb"
    RDP = "rdp"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    UNKNOWN = "unknown"


class FileSystemAction(StrEnum):
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    RENAME = "rename"
    READ = "read"
    EXECUTE = "execute"


class ProcessAction(StrEnum):
    CREATE = "create"
    TERMINATE = "terminate"
    INJECT = "inject"
    OPEN_HANDLE = "open_handle"
    REMOTE_THREAD = "remote_thread"


class AuthAction(StrEnum):
    LOGON_SUCCESS = "logon_success"
    LOGON_FAILURE = "logon_failure"
    LOGOFF = "logoff"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    KERBEROS_TGT = "kerberos_tgt"
    KERBEROS_TGS = "kerberos_tgs"
    NTLM_AUTH = "ntlm_auth"


class AlertSeverity(StrEnum):
    """Alert-specific severity (separate from event severity)."""

    EMERGENCY = "emergency"
    ALERT = "alert"
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    NOTICE = "notice"
    INFORMATIONAL = "informational"
    DEBUG = "debug"


@dataclass
class TimelineEntry:
    """A timeline entry extracted from an artifact for ordering events."""

    timestamp: datetime
    artifact_id: str
    artifact_type: ArtifactType
    description: str
    severity: Severity
    host: str | None = None
    user: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    technique_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dict."""
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["artifact_type"] = self.artifact_type.value
        d["severity"] = self.severity.value
        return d


@dataclass
class Artifact:
    """A normalized forensic artifact.

    An Artifact represents a single event or piece of evidence. It carries
    enough context (timestamps, host, user, IPs, severity, MITRE mapping)
    that downstream analysis can correlate across importers.
    """

    id: str
    artifact_type: ArtifactType
    source: ArtifactSource
    timestamp: datetime
    severity: Severity
    host: str | None = None
    user: str | None = None
    source_ip: str | None = None
    source_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    protocol: NetworkProtocol | None = None
    process_name: str | None = None
    process_id: int | None = None
    parent_process: str | None = None
    command_line: str | None = None
    file_path: str | None = None
    file_hash_md5: str | None = None
    file_hash_sha1: str | None = None
    file_hash_sha256: str | None = None
    registry_key: str | None = None
    registry_value: str | None = None
    action: str | None = None
    description: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    technique_ids: list[str] = field(default_factory=list)
    tactic_ids: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    ingested_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @staticmethod
    def new_id() -> str:
        """Generate a new artifact ID."""
        return str(uuid.uuid4())

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dict."""
        d = asdict(self)
        d["artifact_type"] = self.artifact_type.value
        d["source"] = self.source.value
        d["severity"] = self.severity.value
        d["protocol"] = self.protocol.value if self.protocol else None
        d["timestamp"] = self.timestamp.isoformat()
        d["ingested_at"] = self.ingested_at.isoformat()
        return d

    def to_json(self) -> str:
        """Serialize to a JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Artifact:
        """Construct an Artifact from a dict (inverse of to_dict)."""
        d = dict(data)
        d["artifact_type"] = ArtifactType(d["artifact_type"])
        d["source"] = ArtifactSource(d["source"])
        d["severity"] = Severity(d["severity"])
        if d.get("protocol"):
            d["protocol"] = NetworkProtocol(d["protocol"])
        for key in ("timestamp", "ingested_at"):
            if isinstance(d.get(key), str):
                d[key] = datetime.fromisoformat(d[key])
        d.pop("ingested_at", None)
        d.setdefault("ingested_at", datetime.now(UTC))
        return cls(**d)
