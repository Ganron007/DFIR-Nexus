"""MITRE D.0.3 schemas — Navigator, actors, RBA."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ThreatActorProfile:
    """Static threat actor profile for investigation context."""

    id: str
    name: str
    aliases: list[str] = field(default_factory=list)
    description: str = ""
    motivation: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    campaigns: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "aliases": self.aliases,
            "description": self.description,
            "motivation": self.motivation,
            "technique_ids": self.technique_ids,
            "campaigns": self.campaigns,
        }


@dataclass
class RBAScore:
    """Risk-based alerting score for an investigation context."""

    score: int
    tier: str
    factors: list[dict[str, Any]] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    matched_actors: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "tier": self.tier,
            "factors": self.factors,
            "technique_ids": self.technique_ids,
            "matched_actors": self.matched_actors,
        }
