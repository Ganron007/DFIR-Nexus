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

    # --- Extension-based hints (unambiguous formats first) ---
    suffix = path.suffix.lower()
    _EXT_HINTS: dict[str, ArtifactSource] = {
        ".evtx": ArtifactSource.EVTX,
        ".lnk": ArtifactSource.LNK,
        ".hve": ArtifactSource.AMCACHE,
        # Shared lanes — registry.resolve() disambiguates via can_handle()
        ".eml": ArtifactSource.GENERIC_JSONL,
        ".msg": ArtifactSource.GENERIC_JSONL,
        ".zip": ArtifactSource.GENERIC_JSONL,  # ArchiveImporter.source_class()
        ".tar": ArtifactSource.GENERIC_JSONL,
        ".tgz": ArtifactSource.GENERIC_JSONL,
        ".gz": ArtifactSource.GENERIC_JSONL,
    }
    if suffix in _EXT_HINTS:
        return _EXT_HINTS[suffix]
    if name_lower.endswith(".tshark.json"):
        return ArtifactSource.WIRESHARK
    # Volatility 3 plugin dumps: windows.psscan.json / windows.pslist.txt
    if name_lower.startswith("windows.") and suffix in {".json", ".jsonl", ".txt", ".log"}:
        return ArtifactSource.VOLATILITY
    if name_lower in {"history", "places.sqlite", "chrome-history", "edge-history"} \
            or (name_lower.endswith("-history") and suffix == ""):
        return ArtifactSource.BROWSER_HISTORY
    if name_lower.endswith((".tar.gz", ".tar.xz", ".tar.bz2")):
        return ArtifactSource.GENERIC_JSONL

    # --- Exact filename hints ---
    # NOTE: exact match only. Substring matching misroutes files whose names
    # merely contain a hint token (e.g. "cloudtrail-*sample*.json" contains
    # "sam" and was routed to the Windows registry importer).
    _EXACT_NAME_HINTS: dict[str, ArtifactSource] = {
        "eve.json": ArtifactSource.SURICATA,
        "conn.log": ArtifactSource.ZEEK,
        "dns.log": ArtifactSource.ZEEK,
        "http.log": ArtifactSource.ZEEK,
        "tls.log": ArtifactSource.ZEEK,
        "ssl.log": ArtifactSource.ZEEK,
        "notice.log": ArtifactSource.ZEEK,
        "ssh.log": ArtifactSource.ZEEK,
        "weird.log": ArtifactSource.ZEEK,
        "kerberos.log": ArtifactSource.ZEEK,
        "files.log": ArtifactSource.ZEEK,
        "smtp.log": ArtifactSource.ZEEK,
        "ftp.log": ArtifactSource.ZEEK,
        "audit.log": ArtifactSource.AUDITD,
        "auth.log": ArtifactSource.AUTHLOG,
        "secure": ArtifactSource.AUTHLOG,
        "syslog": ArtifactSource.SYSLOG,
        "messages": ArtifactSource.SYSLOG,
        "journal.json": ArtifactSource.SYSLOG,
        "sam": ArtifactSource.WINDOWS_REGISTRY,
        "system": ArtifactSource.WINDOWS_REGISTRY,
        "software": ArtifactSource.WINDOWS_REGISTRY,
        "security": ArtifactSource.WINDOWS_REGISTRY,
        "ntuser.dat": ArtifactSource.WINDOWS_REGISTRY,
        "usrclass.dat": ArtifactSource.WINDOWS_REGISTRY,
        "wmi_subscriptions.csv": ArtifactSource.WMI_SUBSCRIPTIONS,
        "wmi_subscriptions.mof": ArtifactSource.WMI_SUBSCRIPTIONS,
        ".bash_history": ArtifactSource.BASH_HISTORY,
        "bash_history": ArtifactSource.BASH_HISTORY,
    }
    if name_lower in _EXACT_NAME_HINTS:
        return _EXACT_NAME_HINTS[name_lower]
    if name_lower.startswith("eve.json."):
        return ArtifactSource.SURICATA
    # Zeek rotated spool: conn-20260803.log / kerberos-20260804.log
    _ZEEK_ROTATED = (
        "conn-", "dns-", "http-", "tls-", "ssl-", "notice-", "ssh-",
        "weird-", "kerberos-", "files-", "smtp-", "ftp-",
    )
    if name_lower.endswith(".log") and name_lower.startswith(_ZEEK_ROTATED):
        return ArtifactSource.ZEEK

    # --- Prefix hints (long distinctive tokens + separator) ---
    _PREFIX_HINTS: list[tuple[str, ArtifactSource]] = [
        ("cloudtrail", ArtifactSource.CLOUDTRAIL),
        ("hayabusa", ArtifactSource.HAYABUSA),
        ("velociraptor", ArtifactSource.VELOCIRAPTOR),
        ("volatility", ArtifactSource.VOLATILITY),
        ("thehive", ArtifactSource.THEHIVE),
        ("kape", ArtifactSource.KAPE),
        ("plaso", ArtifactSource.PLASO),
        ("cybertriage", ArtifactSource.CYBERTRIAGE),
        ("suricata", ArtifactSource.SURICATA),
        ("security_onion", ArtifactSource.SECURITY_ONION),
        ("socrates", ArtifactSource.SURICATA),
        ("sysdig", ArtifactSource.SURICATA),
        ("falco", ArtifactSource.SURICATA),
        ("zeek", ArtifactSource.ZEEK),
        ("bro", ArtifactSource.ZEEK),
        ("wazuh", ArtifactSource.ELASTIC),
        ("elastic", ArtifactSource.ELASTIC),
        ("splunk", ArtifactSource.SPLUNK),
        ("azure", ArtifactSource.AZURE),
        ("m365", ArtifactSource.AZURE),
        ("o365", ArtifactSource.AZURE),
        ("entra", ArtifactSource.AZURE),
        ("misp", ArtifactSource.MISP),
        ("otx", ArtifactSource.OTX),
        ("threatfox", ArtifactSource.THREATFOX),
        ("journal", ArtifactSource.SYSLOG),
        ("iris", ArtifactSource.THEHIVE),
        ("sandbox", ArtifactSource.CROWDSTRIKE),
        ("cape", ArtifactSource.CROWDSTRIKE),
    ]
    for token, source in _PREFIX_HINTS:
        if name_lower.startswith(token + "-") or name_lower.startswith(token + "_") \
                or name_lower.startswith(token + "."):
            return source

    # --- Content signature matching ---
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:_SNIFF_BYTES]
    except OSError:
        return None

    if not head.strip():
        return None

    # Binary content: skip all text-format branches and fall straight to
    # registry autodetect (prevents CSV/JSON importers from chewing on
    # PCAPs and other binary blobs).
    is_binary = "\x00" in head[:4096]

    if not is_binary:
        # JSON-based formats (check most-specific first). For NDJSON the
        # whole head is not valid JSON — sniff the first non-empty line.
        stripped = head.lstrip()
        if stripped.startswith("{") or stripped.startswith("["):
            sample = None
            try:
                sample = json.loads(head)
            except json.JSONDecodeError:
                first_line = next((ln for ln in head.splitlines() if ln.strip()), "")
                try:
                    sample = json.loads(first_line)
                except json.JSONDecodeError:
                    sample = None
            if isinstance(sample, dict):
                return _detect_json_format(sample, name_lower)
            elif isinstance(sample, list) and sample and isinstance(sample[0], dict):
                return _detect_json_format(sample[0], name_lower)
            # Truncated pretty-printed JSON array (vol3 / tshark). Do not
            # fall through to CSV just because the snippet contains commas.
            if stripped.startswith("["):
                first_obj = _first_json_object(head)
                if isinstance(first_obj, dict):
                    detected = _detect_json_format(first_obj, name_lower)
                    if detected:
                        return detected
                return ArtifactSource.GENERIC_JSONL

        # tshark / Wireshark JSON export — pretty-printed, so the whole-head
        # parse above usually fails on truncation; sniff the shape directly.
        if '"_source"' in head and '"layers"' in head:
            return ArtifactSource.WIRESHARK

        # CSV/TSV-based formats
        if "\t" in head[:2000] and "\n" in head[:2000]:
            return _detect_tsv_format(head, name_lower)
        if "," in head[:2000] and "\n" in head[:2000]:
            return _detect_csv_format(head, name_lower)

        # XML-based formats
        stripped_head = head.lstrip()
        if (stripped_head.startswith("<?xml") or stripped_head.startswith("<Task")) \
                and ("<Task" in head or "<Exec" in head):
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


def _first_json_object(text: str) -> dict | None:
    """Best-effort first object from a truncated JSON array dump."""
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_str = False
    escape = False
    for i, ch in enumerate(text[start:], start=start):
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    return None
                return obj if isinstance(obj, dict) else None
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

    # M365 Unified Audit Log: RecordType + UserId (shared AZURE lane —
    # registry.resolve() picks M365Importer via can_handle)
    if "RecordType" in keys and "UserId" in keys:
        return ArtifactSource.AZURE

    # Azure: has operationName or caller
    if "operationName" in keys or "caller" in keys:
        return ArtifactSource.AZURE

    # Zeek 8+ JSON logging (CADRE monitor default)
    if "uid" in keys and ("id.orig_h" in keys or "id.resp_h" in keys or "id.orig_p" in keys):
        return ArtifactSource.ZEEK

    # Security Onion ECS
    event_obj = sample.get("event")
    if isinstance(event_obj, dict) and (
        "severity_label" in event_obj or event_obj.get("kind") == "alert"
    ):
        return ArtifactSource.SECURITY_ONION

    # Suricata: has event_type and alert
    if "event_type" in keys and "alert" in keys:
        return ArtifactSource.SURICATA

    # Elastic: has _source wrapper
    if "_source" in keys:
        return ArtifactSource.ELASTIC

    # TheHive: has case/tlm fields
    if "tlp" in keys and ("title" in keys or "case" in keys):
        return ArtifactSource.THEHIVE

    # DFIR-IRIS: case + iocs (shared THEHIVE lane — resolve() picks IRIS)
    if "iocs" in keys and ("case" in keys or "cases" in keys):
        return ArtifactSource.THEHIVE

    # Sandbox report (CAPE-style): score + signatures + target/behavior
    # (shared CROWDSTRIKE lane — resolve() picks SandboxImporter)
    if "score" in keys and "signatures" in keys and ("target" in keys or "behavior" in keys):
        return ArtifactSource.CROWDSTRIKE

    # Hayabusa: has RuleTitle or Level
    if "RuleTitle" in keys or "Level" in keys:
        return ArtifactSource.HAYABUSA

    # AbuseIPDB: data wrapper carrying abuseConfidenceScore (check before VT —
    # both use a top-level "data" dict)
    data = sample.get("data")
    if isinstance(data, dict) and "abuseConfidenceScore" in data:
        return ArtifactSource.ABUSEIPDB

    # VirusTotal: has data.attributes
    if isinstance(data, dict):
        return ArtifactSource.VIRUSTOTAL

    # OTX: has pulse_info, or the export shape with indicators + name
    if "pulse_info" in keys or ("indicators" in keys and "name" in keys):
        return ArtifactSource.OTX

    # MISP: has Event or Attribute
    if "Event" in keys or "Attribute" in keys:
        return ArtifactSource.MISP

    # ThreatFox: has id and ioc_type
    if "id" in keys and "ioc_type" in keys:
        return ArtifactSource.THREATFOX

    # Volatility 3 JSON renderer (windows.pslist / psscan / cmdline / malfind)
    vol_keys = {k.lower() for k in keys}
    if {"pid", "imagefilename"} <= vol_keys or {"pid", "ppid", "offset(v)"} <= vol_keys:
        return ArtifactSource.VOLATILITY
    if "malfind" in name or ("protection" in vol_keys and "commit_charge" in vol_keys):
        return ArtifactSource.VOLATILITY

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


def resolve_ingest_source(
    path: Path, source: ArtifactSource | str | None = None
) -> tuple[ArtifactSource | None, str | None]:
    """Resolve an importer source. ``source`` overrides sniffing when set.

    Returns ``(resolved, error)``. ``error`` is set when the override is
    not a known ``ArtifactSource`` value.
    """
    path = Path(path)
    if source is None or source == "":
        return detect_format(path), None
    if isinstance(source, ArtifactSource):
        return source, None
    raw = str(source).strip().lower().replace("-", "_")
    try:
        return ArtifactSource(raw), None
    except ValueError:
        known = ", ".join(sorted(s.value for s in ArtifactSource))
        return None, f"Unknown source {source!r}. Known: {known}"


def ingest_auto(
    path: Path, source: ArtifactSource | str | None = None
) -> dict[str, Any]:
    """Auto-detect format and import a file. Returns result summary.

    This is the "single import button" — the main entry point for
    importing any forensic file without knowing its format upfront.
    Pass ``source`` to skip sniffing (CLI ``--source`` / MCP override).
    """
    from nexus.ingest.registry import get_registry

    path = Path(path)
    resolved, err = resolve_ingest_source(path, source)
    if err:
        return {"success": False, "error": err, "path": str(path)}

    if resolved is None:
        return {
            "success": False,
            "error": f"Could not detect format for {path.name}",
            "path": str(path),
        }

    registry = get_registry()
    try:
        result = registry.import_path(path, source=resolved)
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
            "error": f"No importer registered for source: {resolved.value}",
            "path": str(path),
        }
