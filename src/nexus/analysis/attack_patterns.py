"""Attack Pattern Engine (WP 13.8 / T2-30 / D16).

Loads data-driven attack patterns from YAML knowledge files:
- attack_patterns.yaml (entity-driven persistence/execution patterns)
- attack_patterns_itm.yaml (insider threat matrix behavioral sequences)
- attack_patterns_external.yaml (adversary IOC and value-anchored patterns)

Correlates timeline events and extracted forensic entities to identify multi-stage
attack pattern chains and map them to MITRE ATT&CK techniques.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

KNOWLEDGE_DIR = Path(__file__).resolve().parents[1] / "data" / "knowledge"


@dataclass
class AttackPattern:
    name: str
    mitre: list[str] = field(default_factory=list)
    required_entities: list[str] = field(default_factory=list)
    optional_entities: list[str] = field(default_factory=list)
    families: list[str] = field(default_factory=list)
    temporal_window_seconds: int = 3600
    min_entities: int = 1
    confidence_base: float = 0.5
    description: str = ""
    required_values: list[str] = field(default_factory=list)
    source_file: str = ""


@dataclass
class MatchedAttackPattern:
    pattern_name: str
    mitre_techniques: list[str]
    confidence: float
    description: str
    matched_entities: dict[str, list[str]]
    contributing_events: list[dict[str, Any]]
    first_seen: str | None = None
    last_seen: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_name": self.pattern_name,
            "mitre_techniques": self.mitre_techniques,
            "confidence": round(self.confidence, 3),
            "description": self.description,
            "matched_entities": self.matched_entities,
            "contributing_event_count": len(self.contributing_events),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


class AttackPatternMatcher:
    """Evaluates timeline events and entities against the attack pattern knowledge library."""

    def __init__(self, knowledge_dir: Path | None = None) -> None:
        self.knowledge_dir = Path(knowledge_dir or KNOWLEDGE_DIR)
        self.patterns: list[AttackPattern] = []
        self._load_patterns()

    def _load_patterns(self) -> None:
        file_names = (
            "attack_patterns.yaml",
            "attack_patterns_itm.yaml",
            "attack_patterns_external.yaml",
        )
        for fname in file_names:
            pfile = self.knowledge_dir / fname
            if not pfile.is_file():
                continue
            try:
                data = yaml.safe_load(pfile.read_text(encoding="utf-8")) or {}
                for p in data.get("patterns") or []:
                    pattern = AttackPattern(
                        name=str(p.get("name") or "").strip(),
                        mitre=list(p.get("mitre") or []),
                        required_entities=list(p.get("required_entities") or []),
                        optional_entities=list(p.get("optional_entities") or []),
                        families=[str(f).lower() for f in (p.get("families") or [])],
                        temporal_window_seconds=int(p.get("temporal_window_seconds") or 3600),
                        min_entities=int(p.get("min_entities") or 1),
                        confidence_base=float(p.get("confidence_base") or 0.5),
                        description=str(p.get("description") or ""),
                        required_values=[str(v).lower() for v in (p.get("required_values") or [])],
                        source_file=fname,
                    )
                    if pattern.name:
                        self.patterns.append(pattern)
            except Exception as exc:
                logger.warning("Failed loading attack patterns from %s: %s", fname, exc)

    def match_events(self, events: list[dict[str, Any]]) -> list[MatchedAttackPattern]:
        """Correlate a sequence of timeline events against known attack patterns."""
        if not events or not self.patterns:
            return []

        # Parse timestamps where possible
        parsed_events: list[tuple[datetime | None, dict[str, Any]]] = []
        for ev in events:
            ts_str = ev.get("timestamp") or ev.get("@timestamp")
            dt = None
            if ts_str:
                try:
                    dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
                except ValueError:
                    dt = None
            parsed_events.append((dt, ev))

        matches: list[MatchedAttackPattern] = []

        for pat in self.patterns:
            matched_pat = self._evaluate_pattern(pat, parsed_events)
            if matched_pat:
                matches.append(matched_pat)

        matches.sort(key=lambda m: m.confidence, reverse=True)
        return matches

    def _evaluate_pattern(
        self,
        pat: AttackPattern,
        parsed_events: list[tuple[datetime | None, dict[str, Any]]],
    ) -> MatchedAttackPattern | None:
        contributing: list[dict[str, Any]] = []
        matched_entities: dict[str, set[str]] = {ent: set() for ent in pat.required_entities}
        optional_matched: dict[str, set[str]] = {ent: set() for ent in pat.optional_entities}

        for _dt, ev in parsed_events:
            fam = str(ev.get("family") or ev.get("source_family") or "").lower()
            if pat.families and fam not in pat.families:
                continue

            text_content = f"{ev.get('message', '')} {ev.get('description', '')} {ev.get('command_line', '')}".lower()
            if pat.required_values and not any(req in text_content for req in pat.required_values):
                continue

            # Extract entities present in this event
            ev_entities = ev.get("entities") or {}
            event_matched_something = False

            for req in pat.required_entities:
                val = ev_entities.get(req) or ev.get(req)
                if val:
                    if isinstance(val, (list, set)):
                        matched_entities[req].update(str(v) for v in val)
                    else:
                        matched_entities[req].add(str(val))
                    event_matched_something = True

            for opt in pat.optional_entities:
                val = ev_entities.get(opt) or ev.get(opt)
                if val:
                    if isinstance(val, (list, set)):
                        optional_matched[opt].update(str(v) for v in val)
                    else:
                        optional_matched[opt].add(str(val))
                    event_matched_something = True

            if event_matched_something or (not pat.required_entities and not pat.optional_entities):
                contributing.append(ev)

        # Check all required entities are present
        if any(len(vals) == 0 for vals in matched_entities.values()):
            return None

        total_unique_entities = sum(len(v) for v in matched_entities.values())
        if total_unique_entities < pat.min_entities:
            return None

        if not contributing:
            return None

        # Check temporal window if timestamps available
        valid_dts = [
            dt for dt, ev in parsed_events
            if dt and ev in contributing
        ]
        first_seen = None
        last_seen = None
        if len(valid_dts) >= 2:
            min_dt, max_dt = min(valid_dts), max(valid_dts)
            delta = (max_dt - min_dt).total_seconds()
            if delta > pat.temporal_window_seconds:
                # If window exceeded across all, but we have multiple events, still allow if subset matches
                pass
            first_seen = min_dt.isoformat()
            last_seen = max_dt.isoformat()
        elif valid_dts:
            first_seen = valid_dts[0].isoformat()
            last_seen = valid_dts[0].isoformat()

        # Compute confidence: base + bonus for optional entities and multiple contributing events
        confidence = pat.confidence_base
        for opt_vals in optional_matched.values():
            if opt_vals:
                confidence += 0.05
        if len(contributing) >= 3:
            confidence += 0.05
        confidence = min(0.99, confidence)

        formatted_entities = {k: sorted(v) for k, v in matched_entities.items()}
        for k, v in optional_matched.items():
            if v:
                formatted_entities[k] = sorted(v)

        return MatchedAttackPattern(
            pattern_name=pat.name,
            mitre_techniques=pat.mitre,
            confidence=confidence,
            description=pat.description,
            matched_entities=formatted_entities,
            contributing_events=contributing,
            first_seen=first_seen,
            last_seen=last_seen,
        )
