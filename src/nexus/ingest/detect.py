"""Auto-format detection for forensic file imports.

Inspects file content (first N bytes) to determine which importer should
handle it. Dispatches to the matching registered importer. This is the
"single import button" — one entry point that routes to the correct parser.

Inspired by DFIR-Companion's importDetect.ts pattern.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from nexus.ingest.schemas import ArtifactSource

log = logging.getLogger(__name__)

_SNIFF_BYTES = 8192


def detect_format(path: Path) -> ArtifactSource | None:
    """Sniff a file and return the best-matching ArtifactSource.

    Checks in order:
    1. Filename-based hints (fast path)
    2. Content signature matching (JSON keys, CSV headers, magic bytes)
    3. Falls back to registry autodetect

    Returns None if no importer can handle the file.
    """
    if not path.is_file():
        return None

    name_lower = path.name.lower()

    # --- Filename-based fast path ---
    _FILENAME_HINTS: dict[str, ArtifactSource] = {
        "evtx": ArtifactSource.EVTX,
        ".evtx": ArtifactSource.EVTX,
        "prefetch": ArtifactSource.PREFETCH,
        ".pf": ArtifactSource.PREFETCH,
        "amcache": ArtifactSource.AMCACHE,
        "amcache.hve": ArtifactSource.AMCACHE,
        "shimcache": ArtifactSource.AMCACHE,
        "lnk": ArtifactSource.LNK,
        ".lnk": ArtifactSource.LNK,
        "ntuser.dat": ArtifactSource.WINDOWS_REGISTRY,
        "system": ArtifactSource.WINDOWS_REGISTRY,
        "software": ArtifactSource.WINDOWS_REGISTRY,
        "sam": ArtifactSource.WINDOWS_REGISTRY,
        "security": ArtifactSource.WINDOWS_REGISTRY,
        "syslog": ArtifactSource.SYSLOG,
        "messages": ArtifactSource.SYSLOG,
        "auth.log": ArtifactSource.AUTHLOG,
        "secure": ArtifactSource.AUTHLOG,
        ".bash_history": ArtifactSource.BASH_HISTORY,
        "audit.log": ArtifactSource.AUDITD,
        "suricata": ArtifactSource.SURICATA,
        "eve.json": ArtifactSource.SURICATA,
        "conn.log": ArtifactSource.ZEEK,
        "dns.log": ArtifactSource.ZEEK,
        "http.log": ArtifactSource.ZEEK,
        "tls.log": ArtifactSource.ZEEK,
        "cloudtrail": ArtifactSource.CLOUDTRAIL,
        "thehive": ArtifactSource.THEHIVE,
        "hayabusa": ArtifactSource.HAYABUSA,
        "kape": ArtifactSource.KAPE,
        "velociraptor": ArtifactSource.VELOCIRAPTOR,
        "volatility": ArtifactSource.VOLATILITY,
    }

    for hint, source in _FILENAME_HINTS.items():
        if hint in name_lower:
            return source

    # --- Extension-based hints ---
    suffix = path.suffix.lower()
    _EXT_HINTS: dict[str, ArtifactSource] = {
        ".evtx": ArtifactSource.EVTX,
        ".pf": ArtifactSource.PREFETCH,
        ".lnk": ArtifactSource.LNK,
        ".hve": ArtifactSource.AMCACHE,
    }
    if suffix in _EXT_HINTS:
        return _EXT_HINTS[suffix]

    # --- Content signature matching ---
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:_SNIFF_BYTES]
    except OSError:
        return None

    if not head.strip():
        return None

    # JSON-based formats (check most-specific first)
    if head.lstrip().startswith("{") or head.lstrip().startswith("["):
        try:
            sample = json.loads(head)
            if isinstance(sample, dict):
                return _detect_json_format(sample, name_lower)
            elif isinstance(sample, list) and sample:
                if isinstance(sample[0], dict):
                    return _detect_json_format(sample[0], name_lower)
        except json.JSONDecodeError:
            pass

    # CSV/TSV-based formats
    if "\t" in head[:2000] and "\n" in head[:2000]:
        return _detect_tsv_format(head, name_lower)
    if "," in head[:2000] and "\n" in head[:2000]:
        return _detect_csv_format(head, name_lower)

    # XML-based formats
    if head.lstrip().startswith("<?xml") or head.lstrip().startswith("<Task"):
        if "<Task" in head or "<Exec" in head:
            return ArtifactSource.SCHEDULED_TASKS

    # Syslog/Authlog pattern
    import re
    if re.match(r"^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+", head):
        auth_filename = any(kw in name_lower for kw in ("auth", "secure"))
        if auth_filename and any(kw in head for kw in ("sshd", "sudo", "su[", "login", "pam_unix")):
            return ArtifactSource.AUTHLOG
        return ArtifactSource.SYSLOG

    # Fallback to registry autodetect
    from nexus.ingest.registry import get_registry
    registry = get_registry()
    cls = registry.autodetect(path)
    if cls is not None:
        return cls.source_class()

    return None


def _detect_json_format(sample: dict, name: str) -> ArtifactSource | None:
    """Detect format from JSON object keys."""
    keys = set(sample.keys())

    # Velociraptor: has Artifact field (check before CloudTrail)
    if "Artifact" in keys or "ArtifactName" in keys:
        return ArtifactSource.VELOCIRAPTOR

    # CloudTrail: has Records array (non-empty)
    if "Records" in keys and isinstance(sample.get("Records"), list) and sample.get("Records"):
        return ArtifactSource.CLOUDTRAIL

    # Azure: has operationName or caller
    if "operationName" in keys or "caller" in keys:
        return ArtifactSource.AZURE

    # Suricata: has event_type and alert
    if "event_type" in keys and "alert" in keys:
        return ArtifactSource.SURICATA

    # Elastic: has _source wrapper
    if "_source" in keys:
        return ArtifactSource.ELASTIC

    # TheHive: has case/tlm fields
    if "tlp" in keys and ("title" in keys or "case" in keys):
        return ArtifactSource.THEHIVE

    # Hayabusa: has RuleTitle or Level
    if "RuleTitle" in keys or "Level" in keys:
        return ArtifactSource.HAYABUSA

    # VirusTotal: has data.attributes
    if "data" in keys and isinstance(sample.get("data"), dict):
        return ArtifactSource.VIRUSTOTAL

    # OTX: has pulse_info
    if "pulse_info" in keys:
        return ArtifactSource.OTX

    # AbuseIPDB: has abuseConfidenceScore
    if "abuseConfidenceScore" in keys or "data" in keys:
        return ArtifactSource.ABUSEIPDB

    # MISP: has Event or Attribute
    if "Event" in keys or "Attribute" in keys:
        return ArtifactSource.MISP

    # ThreatFox: has id and ioc_type
    if "id" in keys and "ioc_type" in keys:
        return ArtifactSource.THREATFOX

    # Generic JSONL
    return ArtifactSource.GENERIC_JSONL


def _detect_csv_format(head: str, name: str) -> ArtifactSource | None:
    """Detect format from CSV header row."""
    first_line = head.split("\n")[0].lower()

    if "fullpath" in first_line or "sha1" in first_line:
        return ArtifactSource.AMCACHE
    if "timestamp" in first_line and "hostname" in first_line:
        return ArtifactSource.HAYABUSA
    if "rule_level" in first_line or "rule.title" in first_line:
        return ArtifactSource.HAYABUSA
    if "eventid" in first_line or "event_id" in first_line:
        return ArtifactSource.EVTX
    if "sourceip" in first_line or "source_ip" in first_line:
        return ArtifactSource.SURICATA
    if "service_name" in first_line and "binary_path" in first_line:
        return ArtifactSource.WINDOWS_SERVICES
    if "taskname" in first_line or "author" in first_line:
        return ArtifactSource.SCHEDULED_TASKS
    if "consumer" in first_line and "filter" in first_line:
        return ArtifactSource.WMI_SUBSCRIPTIONS
    if "_time" in first_line and "sourcetype" in first_line:
        return ArtifactSource.SPLUNK
    if "timestamp" in first_line and "source" in first_line and "host" in first_line:
        return ArtifactSource.PLASO

    return ArtifactSource.GENERIC_CSV


def _detect_tsv_format(head: str, name: str) -> ArtifactSource | None:
    """Detect format from TSV header row."""
    first_line = head.split("\n")[0].lower()

    if "#separator" in head[:200]:
        return ArtifactSource.ZEEK
    if "uid" in first_line and "id.orig_h" in first_line:
        return ArtifactSource.ZEEK
    if "ts" in first_line and "uid" in first_line:
        return ArtifactSource.ZEEK

    return ArtifactSource.GENERIC_CSV


def ingest_auto(path: Path) -> dict[str, Any]:
    """Auto-detect format and import a file. Returns result summary.

    This is the "single import button" — the main entry point for
    importing any forensic file without knowing its format upfront.
    """
    from nexus.ingest.registry import get_registry

    path = Path(path)
    source = detect_format(path)

    if source is None:
        return {
            "success": False,
            "error": f"Could not detect format for {path.name}",
            "path": str(path),
        }

    registry = get_registry()
    try:
        result = registry.import_path(path, source=source)
        return {
            "success": result.success,
            "source": result.source.value,
            "artifacts": len(result.artifacts),
            "errors": result.errors[:5],
            "path": str(path),
        }
    except KeyError:
        return {
            "success": False,
            "error": f"No importer registered for source: {source.value}",
            "path": str(path),
        }
