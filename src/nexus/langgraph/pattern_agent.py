"""PatternAgent — WP 3.19.

Matches the entity graph + timeline against attack_patterns.yaml. Reports
pattern hits with evidence citations and confidence scores. Feeds
confirmed patterns to SynthesisAgent.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

_PATTERNS_PATH = Path(__file__).resolve().parent.parent / "data" / "knowledge" / "attack_patterns.yaml"


class PatternAgent:
    """Attack pattern detection from entity graph and timeline.

    Matches evidence against the attack pattern library. Each pattern
    defines required entity types, temporal windows, family combinations,
    and MITRE mapping. Confidence is scored based on entity coverage
    and temporal clustering.
    """

    name = "pattern"

    def __init__(self, patterns_path: Path | None = None) -> None:
        self.patterns_path = patterns_path or _PATTERNS_PATH
        self._patterns: list[dict[str, Any]] = []
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load the attack pattern library."""
        if not self.patterns_path.is_file():
            log.warning("Attack patterns file not found: %s", self.patterns_path)
            return
        try:
            data = yaml.safe_load(self.patterns_path.read_text(encoding="utf-8"))
            self._patterns = data.get("patterns") or []
            log.info("Loaded %d attack patterns", len(self._patterns))
        except Exception as exc:
            log.warning("Failed to load attack patterns: %s", exc)

    def detect_patterns(
        self,
        entities: dict[str, list[dict[str, Any]]],
        chains: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Match entities against the attack pattern library.

        Args:
            entities: entity graph from extract_entities() —
                {entity_type: [{value, hits, families}, ...]}
            chains: temporal chains from CorrelationAgent (optional)

        Returns:
            patterns: list of pattern matches with evidence and confidence
            narrative_fragments: text fragments for the SynthesisAgent
        """
        matches: list[dict[str, Any]] = []
        fragments: list[str] = []

        # Build entity lookup: entity_type -> set of values
        entity_values: dict[str, set[str]] = {}
        entity_families: dict[str, set[str]] = {}
        for entity_type, entity_list in entities.items():
            for ent in entity_list:
                key = ent["value"].lower()
                entity_values.setdefault(entity_type, set()).add(key)
                entity_families.setdefault(entity_type, set()).update(
                    ent.get("families", [])
                )

        for pattern in self._patterns:
            match = self._match_pattern(pattern, entity_values, entity_families, chains)
            if match:
                matches.append(match)
                fragments.append(match.get("narrative", ""))

        return {
            "patterns": matches,
            "narrative_fragments": [f for f in fragments if f],
            "total_patterns_checked": len(self._patterns),
            "total_matches": len(matches),
        }

    def _match_pattern(
        self,
        pattern: dict[str, Any],
        entity_values: dict[str, set[str]],
        entity_families: dict[str, set[str]],
        chains: list[dict[str, Any]] | None,
    ) -> dict[str, Any] | None:
        """Check if a pattern matches the current entity graph."""
        required = pattern.get("required_entities") or []
        optional = pattern.get("optional_entities") or []
        families = pattern.get("families") or []
        min_entities = pattern.get("min_entities") or 1

        # Check required entity types are present
        found_required: list[str] = []
        found_optional: list[str] = []
        matched_entities: list[str] = []

        for rtype in required:
            if rtype in entity_values and entity_values[rtype]:
                found_required.append(rtype)
                matched_entities.extend(entity_values[rtype])
            else:
                return None  # Missing required entity type

        for otype in optional:
            if otype in entity_values and entity_values[otype]:
                found_optional.append(otype)
                matched_entities.extend(entity_values[otype])

        # Check minimum entity count
        if len(matched_entities) < min_entities:
            return None

        # Check family coverage (if specified)
        if families:
            covered_families = set()
            for fam in families:
                for etype in required + optional:
                    if fam in entity_families.get(etype, set()):
                        covered_families.add(fam)
            # Require at least 2 families to corroborate
            if len(covered_families) < 2:
                return None

        # Check temporal chains if provided
        chain_match = False
        if chains:
            for chain in chains:
                chain_entities = {e["entity"].lower() for e in chain.get("events", [])}
                if any(e.lower() in chain_entities for e in matched_entities):
                    chain_match = True
                    break

        # Calculate confidence
        base_confidence = pattern.get("confidence_base") or 0.5
        # Boost for optional entities found
        optional_boost = len(found_optional) * 0.05
        # Boost for temporal chain match
        chain_boost = 0.1 if chain_match else 0.0
        confidence = min(base_confidence + optional_boost + chain_boost, 0.95)

        # Build narrative fragment
        narrative = (
            f"{pattern.get('name', 'unknown')}: "
            f"{pattern.get('description', '')} "
            f"(entities: {', '.join(sorted(set(matched_entities))[:5])})"
        )

        return {
            "name": pattern.get("name"),
            "description": pattern.get("description"),
            "mitre": pattern.get("mitre") or [],
            "confidence": round(confidence, 2),
            "required_entities_found": found_required,
            "optional_entities_found": found_optional,
            "matched_entities": sorted(set(matched_entities))[:10],
            "chain_match": chain_match,
            "families_covered": sorted(covered_families) if families else [],
            "narrative": narrative,
        }
