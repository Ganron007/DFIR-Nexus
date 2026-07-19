"""Detection rule search across multiple sources.

Searches the local index for rules matching:
- MITRE technique ID
- Tactic ID
- Severity
- Format (Sigma, Splunk, etc.)
- Free-text query (title, description, tags)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from nexus.detection.schemas import (
    DetectionRule,
    DetectionSource,
    RuleFormat,
    RuleSeverity,
)


class DetectionSearcher:
    """Search the local detection rule index."""

    def __init__(self, index_path: Path) -> None:
        self.index_path = index_path
        self._index: list[DetectionRule] = []
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self._load_index()

    def _load_index(self) -> None:
        """Load all detection rules from the index directory."""
        if not self.index_path.exists():
            self._index = []
            self._loaded = True
            return

        # Index is a directory of JSON files (one per rule) + a manifest
        for json_file in self.index_path.rglob("*.json"):
            if json_file.name == "manifest.json":
                continue
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                rule = self._rule_from_dict(data, source_path=str(json_file))
                if rule:
                    self._index.append(rule)
            except Exception:
                # Skip malformed rules
                continue
        self._loaded = True

    @staticmethod
    def _rule_from_dict(data: dict[str, Any], source_path: str = "") -> DetectionRule | None:
        """Convert a dict to a DetectionRule."""
        try:
            return DetectionRule(
                id=data.get("id", ""),
                title=data.get("title", ""),
                description=data.get("description", ""),
                format=RuleFormat(data.get("format", "unknown")),
                source=DetectionSource(data.get("source", "unknown")),
                severity=RuleSeverity(data.get("severity", "unknown")),
                technique_ids=data.get("technique_ids", []),
                tactic_ids=data.get("tactic_ids", []),
                tags=data.get("tags", []),
                source_path=data.get("source_path", source_path),
                metadata=data.get("metadata", {}),
            )
        except (ValueError, KeyError):
            return None

    def search(
        self,
        technique_id: str | None = None,
        tactic_id: str | None = None,
        severity: RuleSeverity | str | None = None,
        rule_format: RuleFormat | str | None = None,
        source: DetectionSource | str | None = None,
        query: str | None = None,
        limit: int = 50,
    ) -> list[DetectionRule]:
        """Search the index.

        Args:
            technique_id: MITRE technique ID (e.g., "T1003.001")
            tactic_id: MITRE tactic ID (e.g., "TA0006")
            severity: Minimum severity (e.g., RuleSeverity.HIGH)
            format: Rule format filter (e.g., RuleFormat.SIGMA)
            source: Rule source filter (e.g., DetectionSource.SIGMAHQ)
            query: Free-text query (matches title, description, tags)
            limit: Max results to return
        """
        self._ensure_loaded()

        # Normalize filter args
        severity_val = severity.value if isinstance(severity, RuleSeverity) else severity
        format_val = rule_format.value if isinstance(rule_format, RuleFormat) else rule_format
        source_val = source.value if isinstance(source, DetectionSource) else source

        results: list[DetectionRule] = []
        for rule in self._index:
            if technique_id and technique_id not in rule.technique_ids:
                continue
            if tactic_id and tactic_id not in rule.tactic_ids:
                continue
            if severity_val and rule.severity.value != severity_val:
                continue
            if format_val and rule.format.value != format_val:
                continue
            if source_val and rule.source.value != source_val:
                continue
            if query:
                q = query.lower()
                haystack = (
                    rule.title.lower()
                    + " "
                    + rule.description.lower()
                    + " "
                    + " ".join(t.lower() for t in rule.tags)
                )
                if q not in haystack:
                    continue
            results.append(rule)
            if len(results) >= limit:
                break
        return results

    def count(self) -> int:
        """Total number of rules in the index."""
        self._ensure_loaded()
        return len(self._index)

    def stats(self) -> dict[str, Any]:
        """Statistics about the index."""
        self._ensure_loaded()
        stats: dict[str, Any] = {
            "total": len(self._index),
            "by_format": {},
            "by_severity": {},
            "by_source": {},
        }
        for rule in self._index:
            fmt = rule.format.value
            sev = rule.severity.value
            src = rule.source.value
            stats["by_format"][fmt] = stats["by_format"].get(fmt, 0) + 1
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
            stats["by_source"][src] = stats["by_source"].get(src, 0) + 1
        return stats
