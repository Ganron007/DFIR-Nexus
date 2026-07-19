"""Pattern extraction from indexed Sigma rules.

Walks the JSON index produced by ``DetectionIndexer`` and extracts
common detection patterns per technique:
- Log source categories (e.g. ``process_creation``, ``file_event``)
- Detection condition keywords (e.g. ``Selection``, ``filter``)
- Field names referenced in detection logic

Pure function — reads only from the local index directory.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class TechniquePatterns:
    """Aggregated patterns for a single MITRE technique."""
    technique_id: str
    rule_count: int = 0
    log_sources: dict[str, int] = field(default_factory=dict)
    condition_keywords: dict[str, int] = field(default_factory=dict)
    field_names: dict[str, int] = field(default_factory=dict)
    severity_distribution: dict[str, int] = field(default_factory=dict)
    sample_titles: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "rule_count": self.rule_count,
            "log_sources": dict(
                sorted(self.log_sources.items(), key=lambda x: -x[1])
            ),
            "condition_keywords": dict(
                sorted(self.condition_keywords.items(), key=lambda x: -x[1])
            ),
            "field_names": dict(
                sorted(self.field_names.items(), key=lambda x: -x[1])
            ),
            "severity_distribution": self.severity_distribution,
            "sample_titles": self.sample_titles[:5],
        }


@dataclass
class PatternReport:
    """Full pattern extraction report across all techniques."""
    total_rules: int = 0
    techniques: dict[str, TechniquePatterns] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_rules": self.total_rules,
            "technique_count": len(self.techniques),
            "techniques": {
                tid: tp.to_dict()
                for tid, tp in sorted(self.techniques.items())
            },
        }


def _extract_log_source_info(rule: dict[str, Any]) -> dict[str, str]:
    """Extract log source category/product/service from a rule dict."""
    meta = rule.get("metadata", {})
    # Some indexed rules store logsource in metadata
    log_source = meta.get("logsource", {})
    if not log_source:
        # Try top-level (raw Sigma format)
        log_source = rule.get("logsource", {})
    return {
        "category": log_source.get("category", ""),
        "product": log_source.get("product", ""),
        "service": log_source.get("service", ""),
    }


def _extract_condition_keywords(raw_content: str) -> list[str]:
    """Parse detection condition keywords from raw Sigma YAML content.

    Looks for named selections (e.g. ``Selection:``, ``Filter:``) and
    logical operators (``and``, ``or``, ``not``).
    """
    if not raw_content:
        return []

    keywords: list[str] = []

    # Find detection block
    det_match = re.search(
        r"^detection:\s*\n([\s\S]+?)(?=\n\S|\Z)", raw_content, re.MULTILINE
    )
    if not det_match:
        return []

    detection_block = det_match.group(1)

    # Named selections: word at start of line followed by colon
    selections = re.findall(r"^(\w+)\s*:", detection_block, re.MULTILINE)
    keywords.extend(selections)

    # Logical operators used in condition
    cond_match = re.search(
        r"condition:\s*(.+)", detection_block, re.MULTILINE
    )
    if cond_match:
        cond_line = cond_match.group(1)
        for op in ("and", "or", "not"):
            if re.search(rf"\b{op}\b", cond_line, re.IGNORECASE):
                keywords.append(op)

    return keywords


def _extract_field_names(raw_content: str) -> list[str]:
    """Extract field names referenced in Sigma detection logic.

    Field names appear as keys under named selections, e.g.:
    ``Selection:\n    EventID: 4624``
    """
    if not raw_content:
        return []

    fields: list[str] = []

    det_match = re.search(
        r"^detection:\s*\n([\s\S]+?)(?=\n\S|\Z)", raw_content, re.MULTILINE
    )
    if not det_match:
        return []

    detection_block = det_match.group(1)

    # Indented keys under named selections (2+ spaces, key followed by colon)
    field_matches = re.findall(r"^\s{2,}(\w+)\s*:", detection_block, re.MULTILINE)
    # Filter out known non-field keys
    non_fields = {"condition", "timeframe"}
    for f in field_matches:
        if f.lower() not in non_fields:
            fields.append(f)

    return fields


def extract_patterns(index_path: Path) -> PatternReport:
    """Extract common patterns from indexed Sigma rules.

    Walks all JSON rule files in *index_path*, groups them by technique
    ID, and aggregates log source types, detection condition keywords,
    field names, and severity distribution per technique.

    Args:
        index_path: Root directory of the Sigma rule index produced by
            ``DetectionIndexer``.

    Returns:
        A ``PatternReport`` keyed by technique ID.
    """
    report = PatternReport()

    if not index_path.exists():
        return report

    # technique_id -> list of rule dicts
    tech_rules: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for json_file in index_path.rglob("*.json"):
        if json_file.name == "manifest.json":
            continue
        try:
            rule = json.loads(json_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        report.total_rules += 1

        for tech_id in rule.get("technique_ids", []):
            tech_rules[tech_id].append(rule)

    for tech_id, rules in tech_rules.items():
        tp = TechniquePatterns(technique_id=tech_id)
        tp.rule_count = len(rules)

        log_source_counter: Counter[str] = Counter()
        condition_counter: Counter[str] = Counter()
        field_counter: Counter[str] = Counter()
        severity_counter: Counter[str] = Counter()
        titles: list[str] = []

        for rule in rules:
            # Log sources
            ls = _extract_log_source_info(rule)
            for key in ("category", "product", "service"):
                val = ls.get(key, "")
                if val:
                    log_source_counter[val] += 1

            # Severity
            sev = rule.get("severity", "unknown")
            severity_counter[sev] += 1

            # Raw content analysis
            raw = rule.get("raw_content", rule.get("metadata", {}).get("raw_content", ""))
            for kw in _extract_condition_keywords(raw):
                condition_counter[kw] += 1
            for fn in _extract_field_names(raw):
                field_counter[fn] += 1

            # Sample titles
            title = rule.get("title", "")
            if title and len(titles) < 5:
                titles.append(title)

        tp.log_sources = dict(log_source_counter)
        tp.condition_keywords = dict(condition_counter)
        tp.field_names = dict(field_counter)
        tp.severity_distribution = dict(severity_counter)
        tp.sample_titles = titles

        report.techniques[tech_id] = tp

    return report


def get_top_patterns(
    report: PatternReport, top_n: int = 10
) -> list[dict[str, Any]]:
    """Return the techniques with the most indexed rules.

    Useful for identifying the most well-covered techniques and their
    common detection patterns.
    """
    sorted_techs = sorted(
        report.techniques.values(), key=lambda t: -t.rule_count
    )
    results: list[dict[str, Any]] = []
    for tp in sorted_techs[:top_n]:
        d = tp.to_dict()
        d["top_log_source"] = (
            max(tp.log_sources, key=lambda k: tp.log_sources[k])
            if tp.log_sources
            else None
        )
        d["top_field"] = (
            max(tp.field_names, key=lambda k: tp.field_names[k])
            if tp.field_names
            else None
        )
        results.append(d)
    return results
