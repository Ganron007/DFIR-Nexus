"""Microsoft 365 / Entra ID UAL + Sign-In / Audit importer.

Parses JSON exports of:
- Unified Audit Log (UAL) records with an ``AuditData`` blob
- Entra ID (Azure AD) sign-in logs with ``UserPrincipalName`` / ``Status``
- Entra ID audit logs with ``ActivityDisplayName`` / ``Category``

All three share a similar JSON envelope; this importer detects and normalises
them into a single Artifact stream.

And the two CSV exports of an audit log search, recognised by their header row whatever the file is called
(D487: T10's ``UnifiedAuditLog.csv`` and ``AuditLog_<dates>.csv`` matched no name rule and were read as generic CSV):
- "Download all results": ``CreationDate, UserIds, Operations, AuditData``, AuditData holding the raw record as a JSON
  object (Microsoft Learn, "Export, configure, and view audit log records", Purview/audit-log-export-records.md at
  69554005e5bd; Search-UnifiedAuditLog's export writes RecordType in place of Operations);
- "Save loaded results": the displayed columns ``Date`` (UTC), ``IP address``, ``User``, ``Activity``, ``Item``,
  ``Detail``, plus ``More``, "more information from the audit log entry" (Microsoft Learn, "View custodian audit
  activity", Purview/ediscovery-view-custodian-activity.md at b2daca1adc7f).
"""

from __future__ import annotations

import csv
import json
import logging
from collections.abc import Iterable, Iterator
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

_OPERATION_CATEGORY_MAP: dict[str, ArtifactType] = {
    "userlogin": ArtifactType.AUTH,
    "login": ArtifactType.AUTH,
    "signin": ArtifactType.AUTH,
    "authentication": ArtifactType.AUTH,
    "adduser": ArtifactType.AUTH,
    "updateuser": ArtifactType.AUTH,
    "deleteuser": ArtifactType.AUTH,
    "mail": ArtifactType.ALERT,
    "dlp": ArtifactType.ALERT,
    "malware": ArtifactType.MALWARE,
    "threat": ArtifactType.THREAT_INTEL,
    "file": ArtifactType.FILE,
    "sharepoint": ArtifactType.FILE,
    "onedrive": ArtifactType.FILE,
    "exchange": ArtifactType.ALERT,
    "powershell": ArtifactType.POWERSHELL,
}

_SIGNIN_STATUS_SEVERITY: dict[str, Severity] = {
    "success": Severity.INFORMATIONAL,
    "succeeded": Severity.INFORMATIONAL,
    "failure": Severity.MEDIUM,
    "failed": Severity.MEDIUM,
    "interrupted": Severity.LOW,
}

_RAW_EXPORT = frozenset({"creationdate", "userids", "auditdata"})
_LOADED_EXPORT = frozenset({"date", "ip address", "user", "activity", "item", "more"})


def audit_export_layout(header: Iterable[str]) -> str | None:
    """Which documented audit-search CSV export a header row is (module docstring): "raw" (Download all results),
    "loaded" (Save loaded results), or None. The one test detection, ``can_handle`` and ``parse`` share."""
    cells = {str(cell).strip().lstrip("﻿").strip('"').lower() for cell in header}
    if cells >= _RAW_EXPORT and cells & {"operations", "recordtype"}:
        return "raw"
    if cells >= _LOADED_EXPORT and cells & {"detail", "details"}:
        return "loaded"
    return None


def _csv_header(path: Path) -> list[str]:
    try:
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            return next(csv.reader(fh), [])
    except (OSError, csv.Error):
        return []


class M365Importer(Importer):
    """Parser for M365 Unified Audit Log and Entra ID sign-in/audit JSON."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.AZURE

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        """Heuristic: filename contains 'm365'/'entra'/'unified_audit' or JSON
        has AuditData/UserPrincipalName keys."""
        if not path.is_file():
            return False
        if path.suffix.lower() == ".csv":
            # A CSV is one of the documented exports by its header, or not this importer's, whatever its name.
            return audit_export_layout(_csv_header(path)) is not None
        name = path.name.lower()
        if any(kw in name for kw in ("m365", "entra", "unified_audit", "o365", "exchange_online")):
            return True
        if not (name.endswith(".json") or name.endswith(".jsonl") or name.endswith(".ndjson")):
            return False
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                head = f.read(8192)
        except OSError:
            return False
        return "AuditData" in head or "UserPrincipalName" in head

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Yield one Artifact per M365/Entra record."""
        suffix = path.suffix.lower()
        if suffix == ".csv":
            yield from self._parse_csv(path)
            return
        if suffix in (".jsonl", ".ndjson"):
            for _line_num, record in self.read_jsonl(path):
                try:
                    yield self._record_to_artifact(record)
                except Exception:
                    log.debug(
                        "Skipping malformed M365 record at %s:%d",
                        path,
                        _line_num,
                        exc_info=True,
                    )
        else:
            try:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                log.debug("Cannot load JSON from %s", path, exc_info=True)
                return
            records = self._extract_records(data)
            for record in records:
                try:
                    yield self._record_to_artifact(record)
                except Exception:
                    log.debug("Skipping malformed M365 record", exc_info=True)

    def _parse_csv(self, path: Path) -> Iterator[Artifact]:
        """An audit-search CSV export: a raw row through the record path (its AuditData is the record), a loaded row
        by the columns Microsoft documents."""
        with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            layout = audit_export_layout(reader.fieldnames or [])
            if layout is None:
                return
            for line_num, row in enumerate(reader, start=2):
                try:
                    yield self._record_to_artifact(row) if layout == "raw" else self._loaded_row_to_artifact(row)
                except Exception:
                    log.debug("Skipping malformed M365 export row at %s:%d", path, line_num, exc_info=True)

    def _loaded_row_to_artifact(self, row: dict[str, Any]) -> Artifact:
        """A "Save loaded results" row, read by its documented columns; it carries no status, so no severity."""
        ts = self.normalize_timestamp(row.get("Date"))  # "The date and time (in UTC format)"
        activity = str(row.get("Activity") or "").strip()
        detail = row.get("Detail") or row.get("Details")
        parts = [str(part).strip() for part in (activity, row.get("Item"), detail) if str(part or "").strip()]
        return Artifact(
            id=Artifact.new_id(),
            artifact_type=self._extract_type({"Operation": activity}, {}),
            source=ArtifactSource.AZURE,
            timestamp=ts or datetime.now(UTC),
            ts_synthesized=ts is None,
            severity=Severity.INFORMATIONAL,
            user=str(row.get("User") or "").strip() or None,
            source_ip=str(row.get("IP address") or "").strip() or None,
            description=" - ".join(parts) or "M365 event",
            raw=row,
            tags=["m365"] + ([f"operation:{activity}"] if activity else []),
        )

    @staticmethod
    def _extract_records(data: Any) -> list[dict[str, Any]]:
        """Pull records from various M365 export shapes."""
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            for key in ("value", "records", "Results", "events"):
                if key in data and isinstance(data[key], list):
                    return [r for r in data[key] if isinstance(r, dict)]
            if "AuditData" in data or "UserPrincipalName" in data:
                return [data]
        return []

    def _record_to_artifact(self, record: dict[str, Any]) -> Artifact:
        """Map an M365/Entra record to an Artifact."""
        audit = self._extract_audit_data(record)
        ts, ts_synthesized = self._extract_timestamp(record, audit)
        severity = self._extract_severity(record, audit)
        artifact_type = self._extract_type(record, audit)
        user = self._extract_user(record, audit)
        source_ip = self._extract_source_ip(record, audit)
        description = self._extract_description(record, audit)

        return Artifact(
            id=Artifact.new_id(),
            artifact_type=artifact_type,
            source=ArtifactSource.AZURE,
            timestamp=ts,
            ts_synthesized=ts_synthesized,
            severity=severity,
            host=str(audit.get("WorkstationName") or audit.get("ClientIP") or "") or None,
            user=user,
            source_ip=source_ip,
            description=description,
            raw=record,
            tags=self._build_tags(record, audit),
        )

    def _extract_audit_data(self, record: dict[str, Any]) -> dict[str, Any]:
        """Unwrap AuditData JSON string if present."""
        raw_audit = record.get("AuditData")
        if isinstance(raw_audit, str):
            try:
                parsed = json.loads(raw_audit)
                if isinstance(parsed, dict):
                    return parsed
            except (ValueError, TypeError):
                pass
        if isinstance(raw_audit, dict):
            return raw_audit
        return {}

    def _extract_timestamp(
        self, record: dict[str, Any], audit: dict[str, Any]
    ) -> tuple[datetime, bool]:
        for key in (
            "CreationDate",
            "Timestamp",
            "EventTime",
            "@timestamp",
            "time",
        ):
            ts = self.normalize_timestamp(record.get(key))
            if ts:
                # D487: this returned the bare datetime, the caller's unpacking raised, and `parse` skipped every
                # record with a top-level CreationDate (every UAL record) as malformed.
                return ts, False
        for key in (
            "CreationTime",
            "EventTime",
            "Timestamp",
            "Date",
        ):
            ts = self.normalize_timestamp(audit.get(key))
            if ts:
                return ts, False
        return datetime.now(UTC), True

    def _extract_severity(
        self, record: dict[str, Any], audit: dict[str, Any]
    ) -> Severity:
        # Check sign-in result first
        status = (
            record.get("Status")
            or audit.get("Status")
            or audit.get("ResultStatus")
        )
        if status:
            norm = str(status).strip().lower()
            for key, sev in _SIGNIN_STATUS_SEVERITY.items():
                if key in norm:
                    return sev
        # Check risk level
        risk = audit.get("RiskLevel") or record.get("RiskLevel")
        if risk:
            norm = str(risk).strip().lower()
            if "high" in norm:
                return Severity.HIGH
            if "medium" in norm:
                return Severity.MEDIUM
            if "low" in norm:
                return Severity.LOW
        # Severity field
        sev = record.get("Severity") or audit.get("Severity")
        if sev:
            return Severity.normalize(sev)
        return Severity.INFORMATIONAL

    def _extract_type(
        self, record: dict[str, Any], audit: dict[str, Any]
    ) -> ArtifactType:
        # Entra sign-in logs
        if "UserPrincipalName" in record and "Status" in record:
            return ArtifactType.AUTH
        # UAL or audit log
        operation = str(
            record.get("Operation")
            or audit.get("Operation")
            or record.get("ActivityDisplayName")
            or ""
        ).lower().replace(" ", "").replace("-", "")
        category = str(
            record.get("RecordType")
            or audit.get("Category")
            or ""
        ).lower()
        for key, atype in _OPERATION_CATEGORY_MAP.items():
            if key in operation or key in category:
                return atype
        return ArtifactType.UNKNOWN

    def _extract_user(
        self, record: dict[str, Any], audit: dict[str, Any]
    ) -> str | None:
        for key in (
            "UserPrincipalName",
            "userPrincipalName",
            "UserId",
            "UserKey",
            "Actor",
        ):
            val = record.get(key) or audit.get(key)
            if val:
                return str(val)
        user_obj = audit.get("UserIdentity") or record.get("UserIdentity")
        if isinstance(user_obj, dict):
            return str(user_obj.get("UPN") or user_obj.get("Id") or "")
        return None

    def _extract_source_ip(
        self, record: dict[str, Any], audit: dict[str, Any]
    ) -> str | None:
        for key in (
            "ClientIP",
            "clientip",
            "IpAddress",
            "ipAddress",
            "ActorIpAddress",
        ):
            val = record.get(key) or audit.get(key)
            if val:
                return str(val)
        return None

    def _extract_description(
        self, record: dict[str, Any], audit: dict[str, Any]
    ) -> str:
        parts: list[str] = []
        operation = record.get("Operation") or audit.get("Operation") or record.get("ActivityDisplayName")
        if operation:
            parts.append(str(operation))
        status = record.get("Status") or audit.get("ResultStatus")
        if status:
            parts.append(str(status))
        result = audit.get("ResultStatus") or record.get("ResultStatus")
        if result and (not status or str(result) != str(status)):
            parts.append(str(result))
        return " - ".join(parts) or "M365 event"

    def _build_tags(
        self, record: dict[str, Any], audit: dict[str, Any]
    ) -> list[str]:
        tags = ["m365"]
        record_type = record.get("RecordType") or audit.get("RecordType")
        if record_type:
            tags.append(f"record_type:{record_type}")
        operation = record.get("Operation") or audit.get("Operation")
        if operation:
            tags.append(f"operation:{operation}")
        category = audit.get("Category") or record.get("Category")
        if category:
            tags.append(f"category:{category}")
        return tags
