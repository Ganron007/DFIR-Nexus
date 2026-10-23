"""Content-validated parsers for common Linux service and installer logs."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from nexus.ingest.base import Importer, ImporterError
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    NetworkProtocol,
    Severity,
)

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_YUM = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<action>Installed|Updated|Erased|Obsoleted|Obsoleting|Downgraded|"
    r"Reinstalled|Dep-Install|Install|Update|Erase):?\s+(?P<package>\S.*)$",
    re.IGNORECASE,
)
_ANACONDA = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)\]\s+"
    r"(?P<level>[A-Za-z0-9_]+)\s*:\s*(?P<message>.*)$"
)
_DRACUT = re.compile(
    r"^(?P<weekday>[A-Z][a-z]{2})\s+(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<zone>[A-Z]{2,5})\s+(?P<year>\d{4})\s+"
    r"(?P<level>[A-Za-z]+):\s*(?P<message>.*)$"
)
_APACHE_ACCESS = re.compile(
    r'^(?P<client>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+(?P<size>\d+|-)(?:\s+.*)?$'
)
_APACHE_REQUEST = re.compile(
    r'^\[(?P<ts>[^\]]+)\]\s+(?P<client>\S+)\s+(?P<tls>\S+)\s+'
    r'(?P<cipher>\S+)\s+"(?P<request>[^"]*)"\s+(?P<size>\d+|-)(?:\s+.*)?$'
)
_APACHE_ERROR = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+\[(?P<level>[^\]]+)\]"
    r"(?P<context>(?:\s+\[[^\]]+\])*)\s+(?P<message>.+)$"
)
_CLIENT_CONTEXT = re.compile(r"\[client\s+([^\]]+)\]", re.IGNORECASE)
_PID_CONTEXT = re.compile(r"\[pid\s+(\d+)\]", re.IGNORECASE)
_REQUEST = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<target>\S+)(?:\s+(?P<version>HTTP/\S+))?$")
_WHICH_MISSING = re.compile(
    r"^which: no (?P<command>\S+) in \((?P<search_path>[^)]*)\)$"
)
_DRACUT_ZONES = {
    "UTC": 0,
    "GMT": 0,
    "EST": -300,
    "EDT": -240,
    "CST": -360,
    "CDT": -300,
    "MST": -420,
    "MDT": -360,
    "PST": -480,
    "PDT": -420,
}


class LinuxLogImporter(Importer):
    """Parse explicit Apache, Yum, Anaconda, dracut and VBox log shapes."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.LINUX_LOG

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        if not path.is_file():
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as stream:
                lines = []
                for line in stream:
                    if line.strip():
                        lines.append(line.rstrip("\r\n"))
                    if len(lines) >= 40:
                        break
        except OSError:
            return False
        if not lines:
            return False
        classified = [cls._classify(line)[0] for line in lines]
        if not all(classified):
            return False
        kinds = set(classified)
        if len(kinds) == 1:
            return True
        return kinds <= {"apache_error", "which_missing"} and "apache_error" in kinds

    @classmethod
    def _classify(cls, line: str) -> tuple[str | None, re.Match[str] | None]:
        clean = _ANSI.sub("", line).strip()
        for kind, pattern in (
            ("apache_access", _APACHE_ACCESS),
            ("apache_request", _APACHE_REQUEST),
            ("apache_error", _APACHE_ERROR),
            ("yum", _YUM),
            ("anaconda", _ANACONDA),
            ("dracut", _DRACUT),
            ("which_missing", _WHICH_MISSING),
        ):
            match = pattern.match(clean)
            if match:
                return kind, match
        if "VirtualBox Guest Additions installation, Window System and desktop setup" in clean:
            return "vbox_install_note", None
        if re.match(r"^(?:Starting|Stopping|Removing)\b.*VirtualBox\b", clean, re.IGNORECASE) \
                and re.search(r"\[\s*OK\s*\]$", clean):
            return "vbox_service", None
        return None, None

    def parse(self, path: Path) -> Iterator[Artifact]:
        for line_number, line in self.read_lines(path):
            kind, match = self._classify(line)
            if not kind:
                raise ImporterError(f"Unrecognized non-empty Linux log line {line_number}")
            yield self._artifact(path, line_number, line, kind, match)

    def _artifact(
        self,
        path: Path,
        line_number: int,
        line: str,
        kind: str,
        match: re.Match[str] | None,
    ) -> Artifact:
        raw: dict[str, object] = {
            "format": kind,
            "source_file": str(path),
            "source_line": line_number,
            "line": line,
        }
        artifact_type = ArtifactType.UNKNOWN
        severity = Severity.INFORMATIONAL
        process_name: str | None = None
        process_id: int | None = None
        source_ip: str | None = None
        action: str | None = None
        protocol: NetworkProtocol | None = None
        timestamp_text: str | None = None
        timestamp = None
        ts_synthesized = False
        ts_year_assumed = False
        ts_tz_assumed = False
        description = line

        if kind == "apache_access" and match:
            timestamp_text = match.group("ts")
            timestamp = datetime.strptime(timestamp_text, "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
            source_ip = _as_ip(match.group("client"))
            request = match.group("request")
            request_match = _REQUEST.match(request)
            action = request
            status = match.group("status")
            if status.isdigit():
                raw["http_status"] = int(status)
            raw["response_bytes"] = None if match.group("size") == "-" else int(match.group("size"))
            raw["http_user"] = None if match.group("user") == "-" else match.group("user")
            if request_match:
                artifact_type = ArtifactType.HTTP
                protocol = NetworkProtocol.HTTP
                raw["http_method"] = request_match.group("method")
                raw["http_target"] = request_match.group("target")
            description = f"HTTP {request}; status={status}"
            process_name = "httpd"
        elif kind == "apache_request" and match:
            timestamp_text = match.group("ts")
            timestamp = datetime.strptime(timestamp_text, "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
            source_ip = _as_ip(match.group("client"))
            request = match.group("request")
            request_match = _REQUEST.match(request)
            action = request
            protocol = NetworkProtocol.HTTPS
            artifact_type = ArtifactType.HTTP if request_match else ArtifactType.TLS
            raw.update({"tls_version": match.group("tls"), "tls_cipher": match.group("cipher")})
            raw["response_bytes"] = None if match.group("size") == "-" else int(match.group("size"))
            if request_match:
                raw["http_method"] = request_match.group("method")
                raw["http_target"] = request_match.group("target")
            description = f"TLS request {request}; bytes={match.group('size')}"
            process_name = "httpd"
        elif kind == "apache_error" and match:
            timestamp_text = match.group("ts")
            timestamp = datetime.strptime(timestamp_text, "%a %b %d %H:%M:%S %Y").replace(tzinfo=UTC)
            ts_tz_assumed = True
            context = match.group("context")
            client_match = _CLIENT_CONTEXT.search(context)
            source_ip = _as_ip(client_match.group(1)) if client_match else None
            pid_match = _PID_CONTEXT.search(context)
            process_id = int(pid_match.group(1)) if pid_match else None
            action = match.group("level").lower()
            severity = _severity(action)
            description = match.group("message")
            process_name = "httpd"
        elif kind == "yum" and match:
            timestamp_text = match.group("ts")
            timestamp, _synth, ts_year_assumed = self.resolve_timestamp_ex(timestamp_text)
            ts_tz_assumed = True
            action = match.group("action").lower()
            package = match.group("package")
            raw["package"] = package
            description = f"Yum {action}: {package}"
            process_name = "yum"
            artifact_type = ArtifactType.PROCESS
        elif kind == "anaconda" and match:
            timestamp_text = match.group("ts")
            timestamp = datetime.strptime(timestamp_text, "%Y-%m-%d %H:%M:%S,%f").replace(tzinfo=UTC)
            ts_tz_assumed = True
            action = match.group("level").lower()
            severity = _severity(action)
            description = match.group("message")
            process_name = "anaconda"
        elif kind == "dracut" and match:
            timestamp_text = (
                f"{match.group('weekday')} {match.group('month')} {match.group('day')} "
                f"{match.group('clock')} {match.group('zone')} {match.group('year')}"
            )
            offset = _DRACUT_ZONES.get(match.group("zone"))
            if offset is None:
                raise ImporterError(f"Unsupported dracut timezone {match.group('zone')!r}")
            local = datetime.strptime(
                f"{match.group('weekday')} {match.group('month')} {match.group('day')} "
                f"{match.group('clock')} {match.group('year')}",
                "%a %b %d %H:%M:%S %Y",
            )
            timestamp = local.replace(tzinfo=timezone(timedelta(minutes=offset))).astimezone(UTC)
            action = match.group("level").lower()
            severity = _severity(action)
            description = match.group("message")
            process_name = "dracut"
        elif kind == "vbox_service":
            clean = _ANSI.sub("", line).strip()
            action = clean.split(None, 1)[0].lower()
            timestamp, ts_synthesized, _ = self.resolve_timestamp_ex(None)
            raw["timestamp_text"] = None
            description = clean
            process_name = "VBoxGuestAdditions"
            artifact_type = ArtifactType.PROCESS
        elif kind == "vbox_install_note":
            timestamp, ts_synthesized, _ = self.resolve_timestamp_ex(None)
            raw["timestamp_text"] = None
            action = "installation_note"
            description = line.strip()
            process_name = "VBoxGuestAdditions"
            artifact_type = ArtifactType.PROCESS
        elif kind == "which_missing" and match:
            timestamp, ts_synthesized, _ = self.resolve_timestamp_ex(None)
            raw["timestamp_text"] = None
            raw["command"] = match.group("command")
            raw["search_path"] = match.group("search_path")
            raw["timestamp_note"] = "source line has no timestamp"
            action = "not_found"
            description = (
                f"which did not find {match.group('command')} in "
                f"{match.group('search_path')}"
            )
            process_name = "which"
            artifact_type = ArtifactType.PROCESS

        if timestamp is None:
            raise ImporterError(f"No event timestamp was produced for {kind} line {line_number}")
        if timestamp_text is not None:
            raw["timestamp_text"] = timestamp_text
        raw["timestamp_tz_assumed"] = ts_tz_assumed

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.LINUX_LOG,
            timestamp=timestamp,
            severity=severity,
            source_ip=source_ip,
            process_name=process_name,
            process_id=process_id,
            protocol=protocol,
            action=action,
            description=description[:500],
            raw=raw,
            tags=["linux_log", kind],
            ts_synthesized=ts_synthesized,
            ts_year_assumed=ts_year_assumed,
            ts_tz_assumed=ts_tz_assumed,
        )


def _as_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _severity(level: str) -> Severity:
    normalized = level.lower()
    if normalized in {"error", "crit", "critical", "alert", "emerg", "fatal"}:
        return Severity.MEDIUM
    if normalized in {"warn", "warning"}:
        return Severity.LOW
    return Severity.INFORMATIONAL
