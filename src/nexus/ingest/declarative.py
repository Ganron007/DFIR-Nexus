"""Declarative custom importers — user-authored JSON specs.

Allows users and LLM agents to teach DFIR-Nexus new file formats by
writing a JSON specification instead of Python code. The spec defines:
- File detection hints (filename patterns, content signatures)
- Field mappings (source field → Artifact field)
- Severity mapping
- MITRE technique extraction

Specs are loaded from `~/.nexus/custom_importers/*.json` and from
any path passed to `register_declarative()`.

Example spec:
{
  "name": "my_custom_tool",
  "source": "custom",
  "detect": {
    "filename_patterns": ["custom_scan.json", "*.custom"],
    "content_keys": ["scan_id", "findings"]
  },
  "format": "json",
  "records_path": "findings",
  "fields": {
    "timestamp": "detected_at",
    "host": "hostname",
    "source_ip": "src_ip",
    "description": "message",
    "severity": "risk_level",
    "file_hash_sha256": "sha256"
  },
  "severity_map": {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low"
  },
  "technique_field": "mitre_id",
  "ioc_fields": ["sha256", "src_ip", "domain"]
}
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.ingest.base import Importer, ImportResult
from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
    ArtifactType,
    Severity,
)

log = logging.getLogger(__name__)

_CUSTOM_IMPORTERS_DIR = Path.home() / ".nexus" / "custom_importers"


class DeclarativeImporter(Importer):
    """Importer driven by a JSON specification rather than Python code."""

    def __init__(self, spec: dict[str, Any]) -> None:
        self.spec = spec
        self._name = spec.get("name", "custom")
        self._source_str = spec.get("source", "custom")
        self._format = spec.get("format", "json")
        self._records_path = spec.get("records_path", "")
        self._field_map = spec.get("fields", {})
        self._severity_map = spec.get("severity_map", {})
        self._technique_field = spec.get("technique_field", "")
        self._ioc_fields = spec.get("ioc_fields", [])
        self._detect = spec.get("detect", {})

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.UNKNOWN

    def _custom_source(self) -> str:
        return self._source_str

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        return False

    def can_handle_spec(self, path: Path) -> bool:
        """Instance-level can_handle using the spec's detect hints."""
        if not path.is_file():
            return False

        name_lower = path.name.lower()

        # Filename patterns
        patterns = self._detect.get("filename_patterns", [])
        for pattern in patterns:
            if "*" in pattern:
                import fnmatch
                if fnmatch.fnmatch(name_lower, pattern.lower()):
                    return True
            elif pattern.lower() in name_lower:
                return True

        # Content keys (JSON only)
        content_keys = self._detect.get("content_keys", [])
        if content_keys and self._format == "json":
            try:
                head = path.read_text(encoding="utf-8", errors="replace")[:4096]
                data = json.loads(head)
                if isinstance(data, dict):
                    if all(k in data for k in content_keys):
                        return True
                elif isinstance(data, list) and data and isinstance(data[0], dict):
                    if all(k in data[0] for k in content_keys):
                        return True
            except (json.JSONDecodeError, OSError):
                pass

        # Content signatures (regex)
        signatures = self._detect.get("content_signatures", [])
        if signatures:
            try:
                head = path.read_text(encoding="utf-8", errors="replace")[:4096]
                for sig in signatures:
                    if re.search(sig, head):
                        return True
            except (OSError, re.error):
                pass

        return False

    def parse(self, path: Path) -> Iterator[Artifact]:
        """Parse a file according to the declarative spec."""
        if self._format == "json":
            yield from self._parse_json(path)
        elif self._format == "csv":
            yield from self._parse_csv(path)
        elif self._format == "jsonl":
            yield from self._parse_jsonl(path)

    def _resolve_records(self, data: Any) -> list[dict[str, Any]]:
        """Navigate to the records array using records_path."""
        if not self._records_path:
            if isinstance(data, list):
                return [r for r in data if isinstance(r, dict)]
            elif isinstance(data, dict):
                return [data]
            return []

        current = data
        for key in self._records_path.split("."):
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return []

        if isinstance(current, list):
            return [r for r in current if isinstance(r, dict)]
        elif isinstance(current, dict):
            return [current]
        return []

    def _map_field(self, record: dict[str, Any], artifact_field: str, source_field: str) -> Any:
        """Extract a value from the record using dotted path notation."""
        current: Any = record
        for key in source_field.split("."):
            if isinstance(current, dict):
                current = current.get(key)
            elif isinstance(current, list):
                try:
                    current = current[int(key)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
        return current

    def _parse_json(self, path: Path) -> Iterator[Artifact]:
        """Parse a JSON file."""
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError) as e:
            log.warning("Failed to parse JSON %s: %s", path, e)
            return

        for record in self._resolve_records(data):
            artifact = self._record_to_artifact(record)
            if artifact is not None:
                yield artifact

    def _parse_jsonl(self, path: Path) -> Iterator[Artifact]:
        """Parse a JSONL file (one JSON object per line)."""
        try:
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if isinstance(record, dict):
                            artifact = self._record_to_artifact(record)
                            if artifact is not None:
                                yield artifact
                    except json.JSONDecodeError:
                        continue
        except OSError as e:
            log.warning("Failed to read JSONL %s: %s", path, e)

    def _parse_csv(self, path: Path) -> Iterator[Artifact]:
        """Parse a CSV file."""
        import csv
        try:
            with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    artifact = self._record_to_artifact(dict(row))
                    if artifact is not None:
                        yield artifact
        except OSError as e:
            log.warning("Failed to read CSV %s: %s", path, e)

    def _record_to_artifact(self, record: dict[str, Any]) -> Artifact | None:
        """Convert a single record to an Artifact using the field map."""
        ts = None
        ts_field = self._field_map.get("timestamp", "")
        if ts_field:
            ts_val = self._map_field(record, "timestamp", ts_field)
            if ts_val:
                ts = self.normalize_timestamp(ts_val)
        if ts is None:
            ts = datetime.now(UTC)

        severity = Severity.INFORMATIONAL
        sev_field = self._field_map.get("severity", "")
        if sev_field:
            raw_sev = self._map_field(record, "severity", sev_field)
            if raw_sev:
                mapped = self._severity_map.get(str(raw_sev).lower())
                if mapped:
                    severity = Severity.normalize(mapped)
                else:
                    severity = Severity.normalize(raw_sev)

        description = ""
        desc_field = self._field_map.get("description", "")
        if desc_field:
            description = str(self._map_field(record, "description", desc_field) or "")[:500]

        technique_ids: list[str] = []
        if self._technique_field:
            tech_val = self._map_field(record, "technique", self._technique_field)
            if tech_val:
                if isinstance(tech_val, list):
                    technique_ids = [str(t) for t in tech_val]
                else:
                    technique_ids = [str(tech_val)]

        iocs: list[str] = []
        for ioc_field in self._ioc_fields:
            val = self._map_field(record, f"ioc_{ioc_field}", ioc_field)
            if val and str(val).strip():
                iocs.append(str(val))

        kwargs: dict[str, Any] = {
            "id": Artifact.new_id(),
            "artifact_type": ArtifactType.UNKNOWN,
            "source": ArtifactSource.UNKNOWN,
            "timestamp": ts,
            "severity": severity,
            "description": description,
            "technique_ids": technique_ids,
            "iocs": iocs,
            "raw": record,
            "tags": [f"custom.{self._name}"],
        }

        optional_fields = {
            "host": "host",
            "user": "user",
            "source_ip": "source_ip",
            "dest_ip": "dest_ip",
            "process_name": "process_name",
            "file_path": "file_path",
            "file_hash_sha256": "file_hash_sha256",
            "file_hash_md5": "file_hash_md5",
            "command_line": "command_line",
        }
        for artifact_field, source_field in self._field_map.items():
            if artifact_field in optional_fields and artifact_field != "description":
                val = self._map_field(record, artifact_field, source_field)
                if val is not None:
                    kwargs[artifact_field] = str(val)

        return Artifact(**kwargs)


def load_declarative_specs(directory: Path | None = None) -> list[dict[str, Any]]:
    """Load all declarative importer specs from a directory."""
    spec_dir = directory or _CUSTOM_IMPORTERS_DIR
    if not spec_dir.is_dir():
        return []

    specs = []
    for json_file in sorted(spec_dir.glob("*.json")):
        try:
            spec = json.loads(json_file.read_text(encoding="utf-8"))
            if isinstance(spec, dict) and "name" in spec and "fields" in spec:
                spec["_spec_path"] = str(json_file)
                specs.append(spec)
            else:
                log.warning("Invalid spec in %s: missing 'name' or 'fields'", json_file)
        except (json.JSONDecodeError, OSError) as e:
            log.warning("Failed to load spec %s: %s", json_file, e)
    return specs


def register_declarative(spec: dict[str, Any]) -> DeclarativeImporter:
    """Register a declarative importer from a spec dict."""
    return DeclarativeImporter(spec)


def register_all_declarative(directory: Path | None = None) -> list[DeclarativeImporter]:
    """Load and register all declarative importers from a directory."""
    specs = load_declarative_specs(directory)
    importers = []
    for spec in specs:
        importer = register_declarative(spec)
        importers.append(importer)
        log.info("Registered declarative importer: %s", spec.get("name"))
    return importers
