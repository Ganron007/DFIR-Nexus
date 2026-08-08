"""AWS CloudTrail JSON importer.

Parses CloudTrail event records (the standard export from S3 or
`aws cloudtrail lookup-events`). Each record is a single event with
`eventTime`, `eventName`, `eventSource`, `userIdentity`, etc.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from nexus.ingest.base import Importer, ImporterError
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)


class CloudTrailImporter(Importer):
    """Parser for AWS CloudTrail JSON exports."""

    # Event names that indicate destructive / sensitive actions
    HIGH_SEVERITY_EVENTS: ClassVar[set[str]] = {
        "DeleteUser", "DeleteRole", "DeletePolicy", "DetachUserPolicy",
        "CreateUser", "AttachUserPolicy", "PutUserPolicy", "PutRolePolicy",
        "CreateAccessKey", "UpdateAccessKey", "DeleteAccessKey",
        "ConsoleLogin", "AssumeRole", "StopLogging", "DeleteTrail",
        "PutBucketPolicy", "DeleteBucket", "AuthorizeSecurityGroupIngress",
    }
    CRITICAL_EVENTS: ClassVar[set[str]] = {
        "StopLogging", "DeleteTrail", "DisableKey", "ScheduleKeyDeletion",
        "DeleteFlowLogs", "Disable*",
    }

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.CLOUDTRAIL

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: JSON file/dir with CloudTrail-shaped records."""
        if not path.exists():
            return False
        target: Path | None = path if path.is_file() else None
        if target is None:
            for f in path.rglob("*.json"):
                target = f
                break
        if target is None:
            return False
        try:
            with target.open("r", encoding="utf-8", errors="replace") as fp:
                head = fp.read(8192)
        except OSError:
            return False
        return (
            "Records" in head
            and ("eventTime" in head or "eventName" in head)
        ) or "eventSource" in head

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per CloudTrail record."""
        files = sorted(path.rglob("*.json")) if path.is_dir() else [path]
        for file in files:
            yield from self._parse_file(file)

    def _parse_file(self, file: Path) -> Iterator[Artifact]:
        """Parse a single CloudTrail JSON file."""
        try:
            with file.open("r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise ImporterError(f"Invalid JSON in {file.name}: {e}") from e
        records = self._extract_records(data)
        for record in records:
            if isinstance(record, dict):
                yield self._record_to_artifact(record, file)

    @staticmethod
    def _extract_records(data: Any) -> list[dict[str, Any]]:
        """Pull records from various CloudTrail export shapes."""
        if isinstance(data, dict):
            if "Records" in data and isinstance(data["Records"], list):
                return [r for r in data["Records"] if isinstance(r, dict)]
            # Single record
            if "eventTime" in data and "eventName" in data:
                return [data]
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        return []

    def _record_to_artifact(self, record: dict[str, Any], file: Path) -> Artifact:
        """Map a CloudTrail record to an Artifact."""
        ts = self.normalize_timestamp(record.get("eventTime"))
        if ts is None:
            ts = datetime.now(UTC)

        event_name = str(record.get("eventName", ""))
        event_source = str(record.get("eventSource", ""))
        aws_region = str(record.get("awsRegion", ""))
        source_ip = record.get("sourceIPAddress")

        # User identity
        user_identity = record.get("userIdentity", {})
        user_name = ""
        if isinstance(user_identity, dict):
            user_name = (
                user_identity.get("userName")
                or user_identity.get("principalId")
                or user_identity.get("arn", "")
            )
            if isinstance(user_name, str) and "/" in user_name:
                user_name = user_name.split("/")[-1]

        # Severity
        severity = Severity.INFORMATIONAL
        if event_name in self.HIGH_SEVERITY_EVENTS:
            severity = Severity.HIGH
        if event_name in self.CRITICAL_EVENTS or any(event_name.startswith(c.strip("*")) for c in self.CRITICAL_EVENTS):
            severity = Severity.CRITICAL
        error_code = record.get("errorCode")
        if error_code and error_code in ("AccessDenied", "UnauthorizedOperation"):
            severity = Severity.MEDIUM

        # Resource
        _resources = record.get("resources", [])

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.NETWORK,  # CloudTrail events are service calls
            source=ArtifactSource.CLOUDTRAIL,
            timestamp=ts,
            severity=severity,
            user=user_name,
            source_ip=source_ip,
            description=f"AWS {event_source.split('.')[0] if event_source else 'API'}.{event_name} in {aws_region}",
            raw=record,
            tags=[
                "cloudtrail",
                f"event.{event_name.lower()}" if event_name else "cloudtrail",
                f"source.{event_source.lower()}" if event_source else "cloudtrail",
                f"region.{aws_region}" if aws_region else "cloudtrail",
            ],
        )
