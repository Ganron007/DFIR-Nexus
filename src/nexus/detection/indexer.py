"""Detection rule indexer.

Builds a local index of detection rules from multiple sources:
- SigmaHQ (community Sigma rules)
- Splunk Enterprise Security Content Update (ESCU)
- Elastic detection-rules
- Sublime Security rules
- CrowdStrike Falcon CQL

Phase 1 supports parsing Sigma rules from the local filesystem.
Other formats are parsed in later phases.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import yaml

from nexus.detection.schemas import (
    DetectionRule,
    DetectionSource,
    RuleFormat,
    RuleSeverity,
)

# MITRE ATT&CK technique ID pattern: T1003.001 or T1003
_TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# Tactic ID pattern: TA0006
_TACTIC_ID_RE = re.compile(r"\bTA\d{4}\b")


class DetectionIndexer:
    """Index detection rules from local directories."""

    def __init__(self, output_path: Path) -> None:
        self.output_path = output_path
        self._stats: dict[str, int] = {}

    def index_sigma_directory(self, sigma_root: Path) -> int:
        """Index all Sigma rules from a directory tree.

        Walks the directory recursively, finds all `.yml` files,
        parses each as a Sigma rule, and writes normalized JSON.

        Returns:
            Number of rules indexed.
        """
        count = 0
        if not sigma_root.exists():
            return 0

        for yml_file in sigma_root.rglob("*.yml"):
            try:
                rule = self._parse_sigma_file(yml_file, sigma_root)
                if rule:
                    self._write_rule(rule)
                    count += 1
            except Exception:
                # Skip malformed rules
                continue

        self._stats["sigma_indexed"] = count
        self._write_manifest()
        return count

    def _parse_sigma_file(
        self, yml_file: Path, root: Path
    ) -> DetectionRule | None:
        """Parse a single Sigma rule file."""
        try:
            data = yaml.safe_load(yml_file.read_text(encoding="utf-8"))
        except Exception:
            return None
        if not isinstance(data, dict):
            return None

        # Sigma format: top-level keys include `title`, `id`, `description`, `detection`, `level`, `tags`, etc.
        title = data.get("title", "")
        rule_id = data.get("id", "")
        if not title or not rule_id:
            return None

        description = data.get("description", "")
        level = self._normalize_severity(data.get("level", ""))
        tags = data.get("tags", []) or []

        # Extract MITRE technique/tactic IDs from tags
        technique_ids, tactic_ids = self._extract_mitre_from_tags(tags)

        # Compute file hash for dedup
        content_hash = hashlib.sha256(
            yml_file.read_bytes()
        ).hexdigest()[:12]

        return DetectionRule(
            id=rule_id,
            title=title,
            description=description,
            format=RuleFormat.SIGMA,
            source=DetectionSource.SIGMAHQ,
            severity=level,
            technique_ids=technique_ids,
            tactic_ids=tactic_ids,
            tags=tags,
            source_path=str(yml_file.relative_to(root)),
            metadata={
                "sigma_id": rule_id,
                "content_hash": content_hash,
            },
        )

    @staticmethod
    def _normalize_severity(level: str) -> RuleSeverity:
        """Map Sigma level (critical/high/medium/low/informational) to RuleSeverity."""
        level_lower = (level or "").lower().strip()
        mapping = {
            "critical": RuleSeverity.CRITICAL,
            "high": RuleSeverity.HIGH,
            "medium": RuleSeverity.MEDIUM,
            "low": RuleSeverity.LOW,
            "informational": RuleSeverity.INFORMATIONAL,
        }
        return mapping.get(level_lower, RuleSeverity.UNKNOWN)

    @staticmethod
    def _extract_mitre_from_tags(tags: list[str]) -> tuple[list[str], list[str]]:
        """Extract MITRE technique and tactic IDs from Sigma tags.

        Sigma tags for MITRE ATT&CK use the format:
        - `attack.t1003.001` → technique T1003.001
        - `attack.credential_access` → tactic TA0006 (mapped via name)
        """
        techniques: list[str] = []
        tactics: list[str] = []
        for tag in tags:
            tag_lower = tag.lower()
            # Match attack.tNNNN or attack.tNNNN.NNN
            m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)$", tag_lower)
            if m:
                tid = m.group(1).upper()
                techniques.append(tid)
            # Match attack.<tactic_name>
            tactic_name = re.match(r"attack\.([a-z_]+)$", tag_lower)
            if tactic_name:
                _TACTIC_NAME_TO_ID = {
                    "initial_access": "TA0001", "execution": "TA0002",
                    "persistence": "TA0003", "privilege_escalation": "TA0004",
                    "defense_evasion": "TA0005", "credential_access": "TA0006",
                    "discovery": "TA0007", "lateral_movement": "TA0008",
                    "collection": "TA0009", "command_and_control": "TA0011",
                    "exfiltration": "TA0010", "impact": "TA0040",
                    "reconnaissance": "TA0043", "resource_development": "TA0042",
                }
                name = tactic_name.group(1)
                tactic_id = _TACTIC_NAME_TO_ID.get(name)
                if tactic_id:
                    tactics.append(tactic_id)
        return sorted(set(techniques)), sorted(set(tactics))

    def _write_rule(self, rule: DetectionRule) -> None:
        """Write a normalized rule to the index directory."""
        # Organize by source/format/severity
        out_dir = (
            self.output_path
            / rule.source.value
            / rule.format.value
            / rule.severity.value
        )
        out_dir.mkdir(parents=True, exist_ok=True)
        # Filename: <id>.json (sanitize)
        safe_id = re.sub(r"[^A-Za-z0-9._-]", "_", rule.id)
        out_file = out_dir / f"{safe_id}.json"
        out_file.write_text(
            json.dumps(rule.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _write_manifest(self) -> None:
        """Write a manifest file with index stats."""
        self.output_path.mkdir(parents=True, exist_ok=True)
        manifest = {
            "version": "1.0",
            "stats": self._stats,
            "indexer": "DFIR-Nexus DetectionIndexer v0.1.0",
        }
        (self.output_path / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )

    def get_stats(self) -> dict[str, int]:
        return dict(self._stats)
