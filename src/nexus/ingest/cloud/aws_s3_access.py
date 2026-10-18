"""Amazon S3 server access log importer.

One request per line, space-separated, with the time in brackets and the request URI, referrer and user agent in
quotes (Amazon S3 User Guide, "Amazon S3 server access log format"): bucket owner, bucket, ``[time]``, remote IP,
requester, request ID, operation, key, ``"request-URI"``, HTTP status, error code, bytes sent, object size, total
time, turn-around time, ``"referrer"``, ``"user agent"``, version ID, host ID, signature version, cipher suite,
authentication type, host header, TLS version, and in later logs access point ARN and ACL required. ``-`` is an
unset field. The time is ``dd/Mon/yyyy:HH:MM:SS +0000``.

Before this importer the access logs of sample S07's four buckets were read by no importer (2026-10-18).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

from nexus.ingest.base import Importer
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity

FIELDS = (
    "bucket_owner", "bucket", "time", "remote_ip", "requester", "request_id", "operation", "key", "request_uri",
    "http_status", "error_code", "bytes_sent", "object_size", "total_time", "turn_around_time", "referrer",
    "user_agent", "version_id", "host_id", "signature_version", "cipher_suite", "authentication_type",
    "host_header", "tls_version", "access_point_arn", "acl_required",
)
_TOKEN = re.compile(r'\[[^\]]*\]|"(?:[^"\\]|\\.)*"|\S+')
_LINE = re.compile(r"^[0-9a-f]{64} \S+ \[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] ")


def _fields(line: str) -> dict[str, str] | None:
    tokens = _TOKEN.findall(line)
    if len(tokens) < 17 or not tokens[2].startswith("["):
        return None
    row: dict[str, str] = {}
    for name, token in zip(FIELDS, tokens, strict=False):
        if token.startswith("[") or token.startswith('"'):
            token = token[1:-1]
        if token != "-":
            row[name] = token
    return row


class S3AccessLogImporter(Importer):
    """Parser for Amazon S3 server access log files."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.AWS_S3_ACCESS

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        if not path.is_file():
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                return bool(_LINE.match(f.readline()))
        except OSError:
            return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        for _n, line in self.read_lines(path):
            row = _fields(line)
            if row is not None:
                yield self._artifact(row, line)

    @staticmethod
    def _artifact(row: dict[str, str], line: str) -> Artifact:
        try:
            ts, synthesized = datetime.strptime(row["time"], "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC), False
        except (KeyError, ValueError):
            ts, synthesized = datetime.now(UTC), True
        status = row.get("http_status", "-")
        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.HTTP,
            source=ArtifactSource.AWS_S3_ACCESS,
            timestamp=ts,
            ts_synthesized=synthesized,
            severity=Severity.INFORMATIONAL,
            source_ip=row.get("remote_ip"),
            user=row.get("requester"),
            action=row.get("operation"),
            file_path=f"s3://{row.get('bucket', '')}/{row['key']}" if row.get("key") else None,
            description=(f"S3 {row.get('operation', '-')} {row.get('bucket', '-')}/{row.get('key', '')} by "
                         f"{row.get('requester', '-')} from {row.get('remote_ip', '-')}: HTTP {status}"
                         + (f" {row['error_code']}" if row.get("error_code") else "")
                         + f" \"{row.get('request_uri', '')}\" UA \"{row.get('user_agent', '')}\""),
            raw={"line": line, **row},
            tags=["aws", "s3-access", f"status.{status}"],
        )
