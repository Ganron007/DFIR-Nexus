"""Base classes for the Ingest Layer.

All concrete importers extend the Importer abstract base class. The base
class enforces a common interface (parse, ingest) and provides shared
helpers (timestamp parsing, MITRE extraction, severity normalization).
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.ingest.schemas import (
    Artifact,
    ArtifactSource,
)

log = logging.getLogger(__name__)


class ImporterError(Exception):
    """Raised when an importer fails to read or parse input data."""


@dataclass
class ImportResult:
    """Result of an import operation."""

    source: ArtifactSource
    artifacts: list[Artifact] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    total_lines: int = 0
    parsed_lines: int = 0
    skipped_lines: int = 0
    source_files: list[str] = field(default_factory=list)
    #: The importer class that read the path (its registry name, `ScheduledTasksImporter`): a source can have several
    #: (`generic_jsonl` is JSONL, Email and Archive), and the gate records which one read the file (TA-5.3).
    importer: str = ""

    @property
    def success(self) -> bool:
        """True only when artifacts parsed AND nothing failed — a partial
        parse is reported as failure with errors, never as clean success."""
        # Rows streamed to a sink are counted, not kept (D263).
        return (self.parsed_lines > 0 or len(self.artifacts) > 0) and not self.errors

    def to_dict(self) -> dict[str, Any]:
        """Convert to a JSON-serializable dict."""
        return {
            "source": self.source.value,
            "total_artifacts": max(len(self.artifacts), self.parsed_lines),
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "skipped_lines": self.skipped_lines,
            "source_files": self.source_files,
            "errors": self.errors,
            "warnings": self.warnings,
            "success": self.success,
            "importer": self.importer,
        }


class Importer(ABC):
    """Abstract base for all forensic importers.

    Subclasses must implement:
        source_class()  -> the ArtifactSource enum value
        can_handle()    -> heuristic to pick the right importer for a file
        parse()         -> parse input and yield Artifact objects

    They may override:
        normalize_timestamp()  -> convert raw timestamp to datetime
        extract_techniques()   -> MITRE technique extraction
    """

    @classmethod
    def source_class(cls) -> ArtifactSource:
        """The ArtifactSource enum value for this importer."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def can_handle(cls, path: Path) -> bool:
        """Return True if this importer can read the given file/dir."""
        raise NotImplementedError

    @abstractmethod
    def parse(self, path: Path) -> Iterator[Artifact]:
        """Parse the input and yield Artifact objects."""
        raise NotImplementedError
        yield  # pragma: no cover  (makes this a generator for type-checkers)

    def parse_with_context(self, path: Path, context: dict[str, Any]) -> Iterator[Artifact]:
        """Parse with optional case context; existing importers remain context-free."""
        return self.parse(path)

    def with_provenance(self, artifacts: Iterator[Artifact]) -> Iterator[Artifact]:
        """Attach the actual parser, preserving more specific nested delegates."""
        cls = type(self)
        name = f"{cls.__module__}.{cls.__qualname__}"
        for artifact in artifacts:
            # A parser may populate fields from untrusted input. Only chains
            # established by an inner wrapper in this process are provenance.
            if not getattr(artifact, "_provenance_recorded", False):
                artifact.importer_chain = []
                artifact._provenance_recorded = True
            artifact.importer_chain.insert(0, name)
            yield artifact

    def ingest(
        self,
        path: Path,
        on_batch=None,
        batch_size: int = 5000,
        context: dict[str, Any] | None = None,
    ) -> ImportResult:
        """Top-level import: parse all input, return ImportResult.

        ``on_batch`` (D263): artifacts are handed to it ``batch_size`` at a time as they are parsed and are
        not kept on the result, so a file of any size is read whole without being held in memory;
        ``result.parsed_lines`` counts them. ``batch_size`` controls transfer granularity only; every
        parsed artifact is delivered.
        """
        result = ImportResult(source=self.source_class())
        path = Path(path)
        if not path.exists():
            result.errors.append(f"Path does not exist: {path}")
            return result

        self.skipped_lines = 0
        files = self._discover_files(path)
        result.source_files = [str(f) for f in files]
        pending: list[Artifact] = []

        for file in files:
            try:
                stream = self.with_provenance(self.parse_with_context(file, context or {}))
                for artifact in stream:
                    result.parsed_lines += 1
                    if on_batch is None:
                        result.artifacts.append(artifact)
                        continue
                    pending.append(artifact)
                    if len(pending) >= batch_size:
                        on_batch(pending)
                        pending = []
            except Exception as e:  # noqa: BLE001
                log.warning("Failed to parse %s: %s", file, e)
                result.errors.append(f"{file}: {e}")
        if pending:
            on_batch(pending)

        result.skipped_lines = self.skipped_lines
        result.total_lines = result.parsed_lines + result.skipped_lines
        return result

    def _discover_files(self, path: Path) -> list[Path]:
        """Return a list of files this importer can handle."""
        if path.is_file():
            return [path]
        if path.is_dir():
            return sorted(
                f for f in path.rglob("*") if f.is_file() and self.can_handle(f)
            )
        return []

    @staticmethod
    def resolve_timestamp(value: Any) -> tuple[datetime, bool]:
        """Return ``(timestamp, synthesized)`` — see ``resolve_timestamp_ex``."""
        ts, synthesized, _year_assumed = Importer.resolve_timestamp_ex(value)
        return ts, synthesized

    @staticmethod
    def resolve_timestamp_ex(value: Any) -> tuple[datetime, bool, bool]:
        """Return ``(timestamp, synthesized, year_assumed)``.

        ``synthesized`` is True when the input could not be parsed and the
        ingest time was substituted (EH-7). ``year_assumed`` is True for the
        RFC 3164 syslog form, which has no year (the current year is used).
        """
        import datetime as _dt

        ts, flags = Importer.normalize_timestamp_ex(value)
        if ts is None:
            return _dt.datetime.now(_dt.UTC), True, False
        return ts, False, bool(flags.get("year_assumed"))

    @staticmethod
    def normalize_timestamp(value: Any) -> datetime | None:
        """Convert arbitrary timestamp formats to a UTC datetime."""
        ts, _flags = Importer.normalize_timestamp_ex(value)
        return ts

    @staticmethod
    def normalize_timestamp_ex(value: Any) -> tuple[datetime | None, dict[str, bool]]:
        """Convert arbitrary timestamps to ``(UTC datetime | None, flags)``.

        Handles:
        - ISO 8601 strings
        - forensic exports with a SPACE before the offset
          (``2024-11-23 04:06:23.634 +05:30`` — Hayabusa/FOR508 CSVs)
        - Unix epoch seconds or milliseconds
        - RFC 3164 syslog (no year → ``year_assumed`` flag)
        - datetime objects (returned as-is)
        - None
        """
        if value is None:
            return None, {}
        if isinstance(value, datetime):
            return (value if value.tzinfo else value.replace(tzinfo=UTC)), {}
        if isinstance(value, (int, float)):
            ts = float(value)
            if ts > 1e12:  # milliseconds
                ts = ts / 1000.0
            try:
                return datetime.fromtimestamp(ts, tz=UTC), {}
            except (OverflowError, OSError, ValueError):
                return None, {}
        if isinstance(value, str):
            s = value.strip()
            if not s:
                return None, {}
            _RFC3164_MONTHS = {
                "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
                "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
            }
            import re as _re
            _rfc3164 = _re.match(
                r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$", s
            )
            if _rfc3164:
                mon = _RFC3164_MONTHS.get(_rfc3164.group(1).lower())
                if mon:
                    year = datetime.now(UTC).year
                    try:
                        return datetime(
                            year, mon, int(_rfc3164.group(2)),
                            int(_rfc3164.group(3)), int(_rfc3164.group(4)),
                            int(_rfc3164.group(5)), tzinfo=UTC,
                        ), {"year_assumed": True}
                    except ValueError:
                        pass
            # Space before the offset is not ISO-8601 but is ubiquitous in
            # forensic exports (Hayabusa, FOR508 CSVs): normalize then parse.
            _spaced = _re.match(
                r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*"
                r"([+-]\d{2}:?\d{2}|Z)?$",
                s,
            )
            if _spaced:
                iso = f"{_spaced.group(1)}T{_spaced.group(2)}"
                offset = _spaced.group(3) or ""
                if offset == "Z":
                    iso += "+00:00"
                elif offset:
                    if ":" not in offset:
                        offset = f"{offset[:3]}:{offset[3:]}"
                    iso += offset
                try:
                    dt = datetime.fromisoformat(iso)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=UTC)
                    return dt, {}
                except ValueError:
                    pass
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return dt, {}
            except ValueError:
                pass
            try:
                ts = float(s)
                if ts > 1e12:
                    ts = ts / 1000.0
                return datetime.fromtimestamp(ts, tz=UTC), {}
            except (ValueError, OverflowError, OSError):
                pass
        return None, {}

    @staticmethod
    def extract_techniques(tags: list[str] | dict[str, Any]) -> list[str]:
        """Extract MITRE ATT&CK technique IDs from Sigma-style tags or dicts.

        Recognizes:
        - 'attack.t1003'         -> T1003
        - 'attack.t1003.001'     -> T1003.001
        - 'attack.initial_access' -> tactic (filtered out, only techniques)
        """
        out: list[str] = []
        if isinstance(tags, dict):
            items = []
            for _key, value in tags.items():
                if isinstance(value, list):
                    items.extend(value)
                else:
                    items.append(value)
            tags = items
        if not isinstance(tags, list):
            return out
        for tag in tags:
            if not isinstance(tag, str):
                continue
            t = tag.strip().lower()
            if not t.startswith("attack."):
                continue
            rest = t[len("attack."):]
            if rest.startswith("t") and any(c.isdigit() for c in rest):
                out.append(rest.upper())
        return sorted(set(out))

    @staticmethod
    def extract_tactics(tags: list[str] | dict[str, Any]) -> list[str]:
        """Extract MITRE ATT&CK tactic names from Sigma-style tags."""
        out: list[str] = []
        if isinstance(tags, dict):
            items = []
            for _key, value in tags.items():
                if isinstance(value, list):
                    items.extend(value)
                else:
                    items.append(value)
            tags = items
        if not isinstance(tags, list):
            return out
        for tag in tags:
            if not isinstance(tag, str):
                continue
            t = tag.strip().lower()
            if not t.startswith("attack."):
                continue
            rest = t[len("attack."):]
            if rest.startswith("t") and any(c.isdigit() for c in rest):
                continue  # technique, not tactic
            out.append(rest)
        return sorted(set(out))

    @staticmethod
    def read_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
        """Yield (line_number, parsed_json) for each non-empty line."""
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield n, json.loads(line)
                except json.JSONDecodeError:
                    log.debug("Skipping invalid JSON at %s:%d", path, n)
                    continue

    @staticmethod
    def read_lines(path: Path) -> Iterator[tuple[int, str]]:
        """Yield (line_number, stripped_line) for each non-empty line."""
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f, start=1):
                line = line.rstrip("\n\r")
                if line.strip():
                    yield n, line
