"""Parser for glibc Linux utmp/wtmp/btmp and lastlog binary records."""

from __future__ import annotations

import ipaddress
import re
import struct
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from nexus.ingest.base import Importer, ImporterError
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity

_UTMP_SIZE = 384
_LASTLOG_SIZE = 292
_UTMP_TYPES = {
    1: "RUN_LVL",
    2: "BOOT_TIME",
    3: "NEW_TIME",
    4: "OLD_TIME",
    5: "INIT_PROCESS",
    6: "LOGIN_PROCESS",
    7: "USER_PROCESS",
    8: "DEAD_PROCESS",
    9: "ACCOUNTING",
}
_ROTATED = re.compile(r"^(?:wtmp|btmp)(?:[-.][A-Za-z0-9._-]+)?$", re.IGNORECASE)


class UtmpImporter(Importer):
    """Read standard 32-bit glibc utmp records without text conversion."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.UTMP

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        if not path.is_file():
            return False
        name = path.name.lower()
        try:
            size = path.stat().st_size
            if name == "lastlog":
                return size >= _LASTLOG_SIZE and size % _LASTLOG_SIZE == 0 \
                    and cls._has_populated_lastlog_record(path)
            if not _ROTATED.fullmatch(name) or size < _UTMP_SIZE or size % _UTMP_SIZE:
                return False
            with path.open("rb") as stream:
                for _ in range(min(size // _UTMP_SIZE, 64)):
                    record = stream.read(_UTMP_SIZE)
                    if len(record) != _UTMP_SIZE:
                        return False
                    if cls._valid_utmp_record(record):
                        return True
        except OSError:
            return False
        return False

    @staticmethod
    def _has_populated_lastlog_record(path: Path) -> bool:
        size = path.stat().st_size
        record_indexes = list(range(min(size // _LASTLOG_SIZE, 32768)))
        tail_start = max(0, size // _LASTLOG_SIZE - 32768)
        record_indexes.extend(range(tail_start, size // _LASTLOG_SIZE))
        with path.open("rb") as stream:
            for index in dict.fromkeys(record_indexes):
                stream.seek(index * _LASTLOG_SIZE)
                record = stream.read(_LASTLOG_SIZE)
                if len(record) != _LASTLOG_SIZE:
                    return False
                seconds = struct.unpack_from("<i", record, 0)[0]
                if seconds > 0 and any(record[4:]):
                    return True
        return False

    @staticmethod
    def _valid_utmp_record(record: bytes) -> bool:
        record_type = struct.unpack_from("<h", record, 0)[0]
        seconds, microseconds = struct.unpack_from("<ii", record, 340)
        if record_type < 0 or record_type > 9 or microseconds < 0 or microseconds >= 1_000_000:
            return False
        if seconds < 0:
            return False
        return record_type == 0 or seconds > 0 or any(record[8:332])

    def parse(self, path: Path) -> Iterator[Artifact]:
        if path.name.lower() == "lastlog":
            yield from self._parse_lastlog(path)
        else:
            yield from self._parse_utmp(path)

    def _parse_utmp(self, path: Path) -> Iterator[Artifact]:
        with path.open("rb") as stream:
            offset = 0
            while record := stream.read(_UTMP_SIZE):
                if len(record) != _UTMP_SIZE:
                    raise ImporterError(f"Truncated utmp record at byte offset {offset}")
                record_type = struct.unpack_from("<h", record, 0)[0]
                if record_type == 0 and not any(record):
                    self.skipped_lines += 1
                    offset += _UTMP_SIZE
                    continue
                if record_type not in _UTMP_TYPES:
                    raise ImporterError(
                        f"Invalid utmp record type {record_type} at byte offset {offset}"
                    )
                seconds, microseconds = struct.unpack_from("<ii", record, 340)
                if seconds <= 0 or microseconds < 0 or microseconds >= 1_000_000:
                    raise ImporterError(f"Invalid utmp time at byte offset {offset}")
                timestamp = datetime.fromtimestamp(seconds, tz=UTC).replace(
                    microsecond=microseconds
                )
                line = _fixed_text(record[8:40])
                identifier = _fixed_text(record[40:44])
                user = _fixed_text(record[44:76])
                remote = _fixed_text(record[76:332])
                pid = struct.unpack_from("<i", record, 4)[0]
                event_name = _UTMP_TYPES[record_type]
                artifact_type = (
                    ArtifactType.AUTH
                    if record_type in {5, 6, 7, 8}
                    else ArtifactType.PROCESS
                )
                detail = ", ".join(
                    value for value in (
                        f"user={user}" if user else "",
                        f"line={line}" if line else "",
                        f"host={remote}" if remote else "",
                    ) if value
                )
                yield Artifact(
                    id=Artifact.new_id(),
                    artifact_type=artifact_type,
                    source=ArtifactSource.UTMP,
                    timestamp=timestamp,
                    severity=Severity.INFORMATIONAL,
                    user=user or None,
                    source_ip=_as_ip(remote),
                    process_id=pid or None,
                    action=event_name.lower(),
                    description=f"utmp {event_name}" + (f": {detail}" if detail else ""),
                    raw={
                        "format": "utmp",
                        "source_file": str(path),
                        "record_offset": offset,
                        "ut_type": record_type,
                        "ut_type_name": event_name,
                        "ut_pid": pid,
                        "ut_line": line,
                        "ut_id": identifier,
                        "ut_user": user,
                        "ut_host": remote,
                        "ut_tv_sec": seconds,
                        "ut_tv_usec": microseconds,
                    },
                    tags=["linux_accounting", "utmp", event_name.lower()],
                )
                offset += _UTMP_SIZE

    def _parse_lastlog(self, path: Path) -> Iterator[Artifact]:
        with path.open("rb") as stream:
            uid = 0
            while record := stream.read(_LASTLOG_SIZE):
                offset = uid * _LASTLOG_SIZE
                if len(record) != _LASTLOG_SIZE:
                    raise ImporterError(f"Truncated lastlog record at byte offset {offset}")
                seconds = struct.unpack_from("<i", record, 0)[0]
                line = _fixed_text(record[4:36])
                remote = _fixed_text(record[36:292])
                if seconds == 0 and not line and not remote:
                    self.skipped_lines += 1
                    uid += 1
                    continue
                if seconds <= 0:
                    raise ImporterError(f"Invalid lastlog time at byte offset {offset}")
                timestamp = datetime.fromtimestamp(seconds, tz=UTC)
                yield Artifact(
                    id=Artifact.new_id(),
                    artifact_type=ArtifactType.AUTH,
                    source=ArtifactSource.UTMP,
                    timestamp=timestamp,
                    severity=Severity.INFORMATIONAL,
                    source_ip=_as_ip(remote),
                    action="lastlog",
                    description=(
                        f"lastlog uid={uid}"
                        + (f", line={line}" if line else "")
                        + (f", host={remote}" if remote else "")
                    ),
                    raw={
                        "format": "lastlog",
                        "source_file": str(path),
                        "record_offset": offset,
                        "uid": uid,
                        "ll_time": seconds,
                        "ll_line": line,
                        "ll_host": remote,
                    },
                    tags=["linux_accounting", "lastlog"],
                )
                uid += 1


def _fixed_text(value: bytes) -> str:
    return value.split(b"\0", 1)[0].decode("utf-8", errors="replace").strip()


def _as_ip(value: str) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None
