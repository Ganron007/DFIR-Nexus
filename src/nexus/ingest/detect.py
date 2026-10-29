"""Auto-format detection for forensic file imports.

Inspects file content (first N bytes) to determine which importer should
handle it. Dispatches to the matching registered importer. This is the
"single import button" — one entry point that routes to the correct parser.

Inspired by DFIR-Companion's importDetect.ts pattern.
"""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import Any

from nexus.ingest.schemas import ArtifactSource

log = logging.getLogger(__name__)

_SNIFF_BYTES = 8192


#: Raw disk/memory containers: the SIFT (or imaging) lane's job, never the
#: importer lane's (D51).
_RAW_CONTAINER_SUFFIXES = {
    ".img", ".dd", ".raw", ".vmdk", ".vhd", ".vhdx", ".qcow2",
    ".e01", ".ex01", ".mem", ".dmp", ".lime", ".avml", ".s01",
}
_RAW_CONTAINER_MAGICS = (
    b"KDMV", b"QFI\xfb", b"conectix", b"vhdx", b"LIME", b"EMiL",
    b"MDMP", b"PAGEDU64", b"PAGEDUMP",
)


def is_raw_container(path: Path) -> bool:
    """True for raw disk/memory containers (suffix or bounded magic sniff).

    `detect_format` on the G7 dmz-www image (20 GiB) burned CPU for minutes
    with no output; the importer lane must refuse these up front.
    """
    if path.suffix.lower() in _RAW_CONTAINER_SUFFIXES:
        return True
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return False
    return any(head.startswith(m) for m in _RAW_CONTAINER_MAGICS)


def _syslog_shape(head: str, name_lower: str) -> ArtifactSource | None:
    """SYSLOG (or AUTHLOG) when most leading lines are RFC 3164 / RFC 5424 syslog lines, else None.

    The line shapes are the syslog importer's own, so what is detected here is what it parses.
    """
    from nexus.ingest.linux.syslog import SyslogImporter

    lines = [ln for ln in head.splitlines()[:20] if ln.strip()]
    if len(lines) > 1 and not head.endswith("\n"):
        lines = lines[:-1]  # the last line of the sniffed head may be cut
    if not lines:
        return None
    shaped = sum(1 for ln in lines if SyslogImporter.RFC3164_RE.match(ln) or SyslogImporter.RFC5424_RE.match(ln))
    if not (SyslogImporter.RFC3164_RE.match(lines[0]) or SyslogImporter.RFC5424_RE.match(lines[0])):
        return None
    if shaped * 2 <= len(lines):
        return None
    auth_filename = any(kw in name_lower for kw in ("auth", "secure"))
    if auth_filename and any(kw in head for kw in ("sshd", "sudo", "su[", "login", "pam_unix")):
        return ArtifactSource.AUTHLOG
    return ArtifactSource.SYSLOG


def _confirmed(source: ArtifactSource, path: Path) -> bool:
    """Whether an importer registered for ``source`` recognises the file's content (its ``can_handle``)."""
    from nexus.ingest.registry import get_registry

    for cls in get_registry().candidates(source):
        try:
            if cls.can_handle(path):
                return True
        except Exception:  # noqa: BLE001 - an importer that cannot look is not a confirmation
            continue
    return False


def _confirmed_or_generic(source: ArtifactSource | None, path: Path) -> ArtifactSource | None:
    """A header-detected source when its importer recognises the file, else the generic CSV reader."""
    if source in (None, ArtifactSource.GENERIC_CSV) or _confirmed(source, path):
        return source
    return ArtifactSource.GENERIC_CSV


def _confirmed_json_source(source: ArtifactSource | None, path: Path) -> ArtifactSource | None:
    """Return a JSON source only when its importer recognises the file.

    Content signatures and filename hints narrow the candidates; they are not
    proof that the selected parser can read the file. JSONL is the fallback
    only when its importer confirms the line-oriented shape.
    """
    if source is not None and _confirmed(source, path):
        return source
    if source != ArtifactSource.GENERIC_JSONL and _confirmed(ArtifactSource.GENERIC_JSONL, path):
        return ArtifactSource.GENERIC_JSONL
    return None


def has_importer(path: Path) -> bool:
    """Whether detection resolves to a source with a matching importer.

    Used by the evidence router to keep unsupported files inside a recognised
    Windows image on the host-tool lane instead of creating guaranteed FAIL
    rows in the importer lane.
    """
    source = detect_format(Path(path))
    return source is not None and _confirmed(source, Path(path))


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

    if is_raw_container(path):
        # Raw disk/memory images belong to the SIFT (or imaging) lane, never to
        # the importer lane: D51 - `detect_format` on the G7 20 GiB disk image
        # burned CPU for minutes with no output before the pipeline was
        # stopped. Say "no importer" instead of chewing the image.
        return None

    name_lower = path.name.lower()

    # Binary login accounting files have no text/CSV signature; identify their
    # fixed-record structure before decoding the sniff buffer as text.
    from nexus.ingest.linux.utmp import UtmpImporter

    if UtmpImporter.can_handle(path):
        return ArtifactSource.UTMP

    # --- Extension-based hints (unambiguous formats first) ---
    suffix = path.suffix.lower()
    _EXT_HINTS: dict[str, ArtifactSource] = {
        # NOTE: host-based raw artifacts (.evtx / .lnk / Amcache.hve / registry
        # hives / browser SQLite) have no ingest importer — they are processed in
        # the N-lane by EvtxECmd/Hayabusa, LECmd, AmcacheParser, RECmd, SQLECmd.
        # Shared lanes — registry.resolve() disambiguates via can_handle()
        ".eml": ArtifactSource.GENERIC_JSONL,
        ".msg": ArtifactSource.GENERIC_JSONL,
        ".zip": ArtifactSource.GENERIC_JSONL,  # ArchiveImporter.source_class()
        ".tar": ArtifactSource.GENERIC_JSONL,
        ".tgz": ArtifactSource.GENERIC_JSONL,
        # Note: bare ".gz" is handled below by name — most importers cannot
        # decompress, and a silent generic fallback used to "succeed" with 0
        # artifacts. Zeek rotated logs are gzip and ARE supported.
        # Raw packet captures — WIRESHARK lane; registry.resolve() picks the
        # PcapImporter (tshark conversion) vs the JSON importer via can_handle.
        ".pcap": ArtifactSource.WIRESHARK,
        ".pcapng": ArtifactSource.WIRESHARK,
        ".cap": ArtifactSource.WIRESHARK,
        # NetFlow captures (nfdump/nfcapd) — NETFLOW lane (EH-14b)
        ".nfcapd": ArtifactSource.NETFLOW,
        ".nfdump": ArtifactSource.NETFLOW,
    }
    if suffix in _EXT_HINTS:
        return _EXT_HINTS[suffix]
    # A workbook (an examiner's tool report, e.g. SRUM-DUMP's) is read when its importer can open it.
    if suffix in (".xlsx", ".xlsm") and _confirmed(ArtifactSource.SPREADSHEET, path):
        return ArtifactSource.SPREADSHEET
    # A Magnet AXIOM case database, when its tables say so.
    if suffix == ".mfdb" and _confirmed(ArtifactSource.AXIOM, path):
        return ArtifactSource.AXIOM
    if suffix == ".gz":
        if name_lower.endswith(".log.gz"):
            return ArtifactSource.ZEEK
        # The importer pass reads a gzipped file through its decompressed copy (D275); here a .gz is only a
        # Zeek log by name.
        return None
    if name_lower.endswith(".tshark.json"):
        return _confirmed_json_source(ArtifactSource.WIRESHARK, path)
    # Volatility 3 plugin dumps: windows.psscan.json / windows.pslist.txt
    if name_lower.startswith("windows.") and suffix in {".json", ".jsonl", ".txt", ".log"}:
        if _confirmed(ArtifactSource.VOLATILITY, path):
            return ArtifactSource.VOLATILITY
        if suffix in {".json", ".jsonl"}:
            return _confirmed_json_source(None, path)
        return None
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
        ".bash_history": ArtifactSource.BASH_HISTORY,
        "bash_history": ArtifactSource.BASH_HISTORY,
    }
    # A name is a hint that the hinted importer confirms on the content: a mail server's syslog named
    # smtp.log (sample S03, 2026-10-18) went to the Zeek importer by its name and gave 0 rows. When the
    # importer does not recognise the file, detection goes on to the content signatures below.
    if name_lower in _EXACT_NAME_HINTS and _confirmed(_EXACT_NAME_HINTS[name_lower], path):
        return _EXACT_NAME_HINTS[name_lower]
    if name_lower.startswith("eve.json.") and _confirmed(ArtifactSource.SURICATA, path):
        return ArtifactSource.SURICATA
    # Zeek rotated spool: conn-20260803.log / kerberos-20260804.log
    _ZEEK_ROTATED = (
        "conn-", "dns-", "http-", "tls-", "ssl-", "notice-", "ssh-",
        "weird-", "kerberos-", "files-", "smtp-", "ftp-",
    )
    if (name_lower.endswith(".log") and name_lower.startswith(_ZEEK_ROTATED)
            and _confirmed(ArtifactSource.ZEEK, path)):
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
            if suffix in {".json", ".jsonl", ".ndjson"}:
                confirmed = _confirmed_json_source(source, path)
                if confirmed is not None:
                    return confirmed
            else:
                return source

    # --- Content signature matching ---
    try:
        with path.open("rb") as fh:
            head_bytes = fh.read(_SNIFF_BYTES)
    except OSError:
        return None
    head = head_bytes.decode("utf-8", errors="replace")

    if not head.strip():
        return None

    # Binary content: skip all text-format branches and fall straight to
    # registry autodetect (prevents CSV/JSON importers from chewing on
    # PCAPs and other binary blobs).
    is_binary = b"\x00" in head_bytes[:4096]

    if not is_binary:
        # tshark / Wireshark JSON export — must be recognised BEFORE the
        # generic JSON branches (any `_source` object otherwise routes to
        # ELASTIC; a pretty-printed array short-circuits before the later
        # layers check).
        if '"_source"' in head and '"layers"' in head:
            return _confirmed_json_source(ArtifactSource.WIRESHARK, path)
        # Large CloudTrail files often exceed the bounded JSON decode window.
        # Their first event row still carries the specific eventTime/eventName
        # fields; the CloudTrail importer confirms the complete file shape.
        if '"eventTime"' in head and '"eventName"' in head:
            cloudtrail = _confirmed_json_source(ArtifactSource.CLOUDTRAIL, path)
            if cloudtrail is not None:
                return cloudtrail
        # Bracketed Apache/Anaconda timestamps are not JSON arrays. Confirm
        # their line grammar before the generic '[' JSON branch can short-circuit.
        from nexus.ingest.linux.logs import LinuxLogImporter

        if LinuxLogImporter.can_handle(path):
            return ArtifactSource.LINUX_LOG
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
                return _confirmed_json_source(_detect_json_format(sample, name_lower), path)
            elif isinstance(sample, list) and sample and isinstance(sample[0], dict):
                return _confirmed_json_source(_detect_json_format(sample[0], name_lower), path)
            # Truncated pretty-printed JSON array (vol3 / tshark). Do not
            # fall through to CSV just because the snippet contains commas.
            if stripped.startswith("["):
                first_obj = _first_json_object(head)
                if isinstance(first_obj, dict):
                    detected = _detect_json_format(first_obj, name_lower)
                    if detected:
                        return _confirmed_json_source(detected, path)
                return _confirmed_json_source(ArtifactSource.GENERIC_JSONL, path)
            # A large or truncated JSON object must not fall through to the
            # comma-based CSV detector. Keep it only if the line-oriented JSON
            # importer confirms a record; otherwise report no importer.
            if stripped.startswith("{"):
                return _confirmed_json_source(ArtifactSource.GENERIC_JSONL, path)

        # Mid-stream NDJSON — `tail` captures begin inside a JSON object and
        # logs sometimes carry a preamble. Route by the first line that
        # parses as a JSON object instead of falling through to CSV.
        if not (stripped.startswith("{") or stripped.startswith("[")):
            sample = _first_json_line(head)
            if sample is not None:
                detected = _detect_json_format(sample, name_lower)
                return _confirmed_json_source(detected or ArtifactSource.GENERIC_JSONL, path)

        # tshark / Wireshark JSON export — pretty-printed, so the whole-head
        # parse above usually fails on truncation; sniff the shape directly.
        if '"_source"' in head and '"layers"' in head:
            return _confirmed_json_source(ArtifactSource.WIRESHARK, path)

        # Syslog lines before the delimited branches: a message holds commas, and a comma anywhere in the
        # head made a mail server's syslog a CSV whose first line was its header (sample S03, 2026-10-18).
        syslog_source = _syslog_shape(head, name_lower)
        if syslog_source is not None:
            return syslog_source
        # A BIND query log has no importer by name or extension, only by its lines.
        from nexus.ingest.network.bind import BindQueryLogImporter

        if BindQueryLogImporter.can_handle(path):
            return ArtifactSource.BIND
        # An OSSEC alerts.log, or the Windows events an OSSEC agent forwards, by its lines.
        from nexus.ingest.siem.ossec import OssecAlertsImporter

        if OssecAlertsImporter.can_handle(path):
            return ArtifactSource.OSSEC
        # A file saved as base64 text (a mail attachment) is identified by what it decodes to.
        from nexus.ingest.generic.encoded import Base64FileImporter

        if Base64FileImporter.can_handle(path):
            return ArtifactSource.ENCODED_FILE
        # AWS logs read by their lines: an S3 access log's user agent holds commas, a VPC flow log is a header line.
        from nexus.ingest.cloud.aws_s3_access import S3AccessLogImporter
        from nexus.ingest.cloud.aws_vpc_flow import VpcFlowLogImporter

        if S3AccessLogImporter.can_handle(path):
            return ArtifactSource.AWS_S3_ACCESS
        if VpcFlowLogImporter.can_handle(path):
            return ArtifactSource.AWS_VPC_FLOW

        # CSV/TSV-based formats. A header word is a hint the hinted importer confirms on the content, as a name
        # is: RECmd's TaskCache CSV has an Author column, went to the task-XML importer by it, and gave 0 rows
        # (sample S09, 2026-10-18). An importer that does not recognise the file leaves it to the generic reader.
        if "\t" in head[:2000] and "\n" in head[:2000]:
            return _confirmed_or_generic(_detect_tsv_format(head, name_lower), path)
        if "," in head[:2000] and "\n" in head[:2000]:
            return _confirmed_or_generic(_detect_csv_format(head, name_lower), path)

        # XML-based formats
        stripped_head = head.lstrip()
        if (stripped_head.startswith("<?xml") or stripped_head.startswith("<Task")) \
                and ("<Task" in head or "<Exec" in head):
            return ArtifactSource.SCHEDULED_TASKS

        # Syslog classification was already attempted by _syslog_shape above.
        # Do not classify on timestamp alone: Yum transaction logs also begin
        # with month/day/time but have no RFC 3164 host/process/message fields.

    # Fallback to registry autodetect
    from nexus.ingest.registry import get_registry
    registry = get_registry()
    cls = registry.autodetect(path)
    if cls is not None:
        return cls.source_class()

    return None


def _first_json_line(text: str, max_lines: int = 60) -> dict | None:
    """First line in ``text`` that parses as a JSON object (NDJSON sniff)."""
    for line in text.splitlines()[:max_lines]:
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj:
            return obj
        if isinstance(obj, list) and obj and isinstance(obj[0], dict):
            return obj[0]
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
    # A CloudTrail record exported on its own (or the first row of a large
    # Records array) is also supported by CloudTrailImporter.
    if {"eventTime", "eventName"} <= keys:
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

    # Suricata EVE: event_type + network fields (alert may be absent on
    # http/dns/tls/flow events — a tail capture often starts on one).
    if "event_type" in keys and (
        "src_ip" in keys or "dest_ip" in keys or "flow_id" in keys or "alert" in keys
    ):
        return ArtifactSource.SURICATA

    # Wireshark/tshark packet export (checked before the Elastic `_source`
    # wrapper — tshark also uses `_source`).
    source_obj = sample.get("_source")
    if isinstance(source_obj, dict) and "layers" in source_obj:
        return ArtifactSource.WIRESHARK

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

    # An audit log search export (D487), by the one header test its importer confirms with.
    from nexus.ingest.cloud.m365 import audit_export_layout

    if audit_export_layout(next(csv.reader([head.split("\n")[0].rstrip("\r")]), [])):
        return ArtifactSource.AZURE
    if "fullpath" in first_line or "sha1" in first_line:
        return ArtifactSource.AMCACHE
    if "timestamp" in first_line and "hostname" in first_line:
        return ArtifactSource.HAYABUSA
    if "rule_level" in first_line or "rule.title" in first_line:
        return ArtifactSource.HAYABUSA
    # EvtxECmd/Kansa event CSVs have no ingest importer (host artifacts are
    # N-lane: EvtxECmd/Hayabusa); they fall through to generic_csv.
    if "sourceip" in first_line or "source_ip" in first_line:
        return ArtifactSource.SURICATA
    if "service_name" in first_line and "binary_path" in first_line:
        return ArtifactSource.WINDOWS_SERVICES
    if "taskname" in first_line or "author" in first_line:
        return ArtifactSource.SCHEDULED_TASKS
    if "_time" in first_line and "sourcetype" in first_line:
        return ArtifactSource.SPLUNK
    if "timestamp" in first_line and "source" in first_line and "host" in first_line:
        return ArtifactSource.PLASO
    from nexus.ingest.fingerprint import family_for_csv_header

    family = family_for_csv_header(head)
    if family == "evtxecmd":
        return ArtifactSource.EVTX
    if family == "plaso":
        return ArtifactSource.PLASO
    # nfdump -o csv NetFlow export (EH-14b): distinctive header even when the
    # file is just called flows.csv — never let it fall into generic_csv.
    try:
        from nexus.ingest.network.nfdump import looks_like_nfdump_csv_header

        if looks_like_nfdump_csv_header(first_line.split(",")):
            return ArtifactSource.NETFLOW
    except Exception:  # noqa: BLE001 — detection must not hard-fail
        pass

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


def lane_routing_hint(path: Path) -> str | None:
    """Routing hint when a raw HOST artifact reaches the ingest lane.

    Host-based raw artifacts are processed by the N-lane forensic tools; the
    ingest lane consumes their CSV/JSON output. Returns a human hint or None.
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(16)  # 16 bytes: SQLite magic is exactly 16
    except OSError:
        return None
    if head.startswith(b"regf"):
        if path.name.lower() in {"amcache.hve", "amcache"}:
            return ("raw Amcache hive — process it in the N-lane (AmcacheParser) "
                    "and ingest the CSV output")
        return ("raw registry hive — process it in the N-lane (RECmd) and "
                "ingest the CSV output")
    if head.startswith(b"ElfFile\x00"):
        return ("raw EVTX — process it in the N-lane (EvtxECmd / Hayabusa) and "
                "ingest the CSV/JSON output")
    if path.suffix.lower() == ".lnk" and head[:4] == b"\x4c\x00\x00\x00":
        return ("raw LNK — process it in the N-lane (LECmd) and ingest the CSV output")
    if head.startswith(b"SQLite format 3\x00"):
        return ("raw SQLite (browser/OS) — process it in the N-lane "
                "(SQLECmd / Hindsight) and ingest the output")
    if path.name.lower().endswith("objects.data"):
        return ("raw WMI repository — process it in the N-lane (RECmd) and "
                "ingest the CSV output")
    return None


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
        hint = lane_routing_hint(path)
        return {
            "success": False,
            "error": f"Could not detect format for {path.name}"
                     + (f" — {hint}" if hint else ""),
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
        hint = lane_routing_hint(path)
        return {
            "success": False,
            "error": f"No importer registered for source: {resolved.value}"
                     + (f" — {hint}" if hint else ""),
            "path": str(path),
        }
