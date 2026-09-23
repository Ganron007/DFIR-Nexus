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
# ITM chains (Insider Threat Matrix) - Preparation/Infringement/Anti-Forensics
# sequences compiled from the Apache-2.0 ITM registry (see itm/itm_registry.yaml).
_ITM_PATTERNS_PATH = Path(__file__).resolve().parent.parent / "data" / "knowledge" / "attack_patterns_itm.yaml"
# External-threat chains (MITRE ATT&CK, value-anchored) - companion library.
_EXTERNAL_PATTERNS_PATH = Path(__file__).resolve().parent.parent / "data" / "knowledge" / "attack_patterns_external.yaml"


def _validated_patterns(patterns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop ITM/ATT&CK ids that do not exist in our registries.

    A pattern with an invented technique id is a fabricated claim waiting to
    happen - the id is dropped (with a warning) rather than rendered. When a
    registry is unavailable the authored id is kept as-is (KB optional).
    """
    try:
        from nexus.langgraph.itm import itm_index

        itm_lookup = itm_index()
    except Exception:  # noqa: BLE001
        itm_lookup = {}
    try:
        from nexus.knowledge.loader import get_attack_techniques

        mitre_ids = {
            str(t.get("technique") or "").upper()
            for t in (get_attack_techniques() or [])
            if t.get("technique")
        }
    except Exception:  # noqa: BLE001
        mitre_ids = set()

    out: list[dict[str, Any]] = []
    for pattern in patterns:
        item = dict(pattern)
        itm_ids: list[str] = []
        for raw in item.get("itm") or []:
            value = str(raw).strip()
            if not value:
                continue
            if not itm_lookup:
                itm_ids.append(value)
                continue
            candidate = value.split("/", 1)[1] if "/" in value else value
            info = itm_lookup.get(candidate.upper())
            if info:
                itm_ids.append(f"{info['article']}/{info['id']}")
            else:
                log.warning("pattern %r: unknown ITM id %r dropped", item.get("name"), value)
        item["itm"] = itm_ids
        if mitre_ids:
            kept = []
            for raw in item.get("mitre") or []:
                ref = str(raw).strip().upper()
                if ref in mitre_ids:
                    kept.append(str(raw).strip())
                else:
                    log.warning("pattern %r: unknown ATT&CK id %r dropped", item.get("name"), raw)
            item["mitre"] = kept
        out.append(item)
    return out


class PatternAgent:
    """Attack pattern detection from entity graph and timeline.

    Matches evidence against the attack pattern library (MITRE library +
    Insider Threat Matrix chains). Each pattern defines required entity types,
    optional value anchors (``required_values``), temporal windows, family
    combinations, and MITRE/ITM mapping. Confidence is scored based on entity
    coverage and temporal clustering.
    """

    name = "pattern"

    def __init__(self, patterns_path: Path | None = None,
                 itm_patterns_path: Path | None = None) -> None:
        self.patterns_path = patterns_path or _PATTERNS_PATH
        # The ITM library rides along only for the default (shipped) library;
        # a custom path stays exactly what the caller handed in.
        if patterns_path is None:
            self._extra_paths = [
                itm_patterns_path or _ITM_PATTERNS_PATH,
                _EXTERNAL_PATTERNS_PATH,
            ]
        else:
            self._extra_paths = [itm_patterns_path] if itm_patterns_path else []
        self._patterns: list[dict[str, Any]] = []
        self._load_patterns()

    def _load_patterns(self) -> None:
        """Load the attack pattern library (+ ITM chains) and validate ids."""
        loaded: list[dict[str, Any]] = []
        for path in [self.patterns_path, *self._extra_paths]:
            if not path.is_file():
                log.warning("Attack patterns file not found: %s", path)
                continue
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                loaded.extend((data or {}).get("patterns") or [])
                log.info("Loaded %d attack patterns from %s",
                         len((data or {}).get("patterns") or []), path.name)
            except Exception as exc:  # noqa: BLE001 - KB must never kill the agent
                log.warning("Failed to load attack patterns (%s): %s", path, exc)
        self._patterns = _validated_patterns(loaded)

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

        # Value anchors: each listed type must have an entity value containing
        # one of the tokens (case-insensitive). This turns a generic
        # "process_name + families" match into "vssadmin.exe ran" (ITM chains).
        for vtype, tokens in (pattern.get("required_values") or {}).items():
            wanted = [str(t).lower() for t in (tokens or []) if str(t).strip()]
            values = entity_values.get(str(vtype), set())
            if not wanted or not any(w in v for w in wanted for v in values):
                return None

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
        itm_ids = [str(x) for x in (pattern.get("itm") or [])]
        narrative = (
            f"{pattern.get('name', 'unknown')}: "
            f"{pattern.get('description', '')} "
            f"(entities: {', '.join(sorted(set(matched_entities))[:5])})"
        )
        if itm_ids:
            narrative = f"{narrative} [ITM: {', '.join(itm_ids)}]"

        return {
            "name": pattern.get("name"),
            "description": pattern.get("description"),
            "mitre": pattern.get("mitre") or [],
            "itm": itm_ids,
            "evidence": pattern.get("evidence") or [],
            "temporal_window_seconds": pattern.get("temporal_window_seconds"),
            "confidence": round(confidence, 2),
            "required_entities_found": found_required,
            "optional_entities_found": found_optional,
            "matched_entities": sorted(set(matched_entities))[:10],
            "chain_match": chain_match,
            "families_covered": sorted(covered_families) if families else [],
            "narrative": narrative,
        }
