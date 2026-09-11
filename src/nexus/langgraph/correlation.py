"""Entity correlation engine — WP 3.15.

Maintains a shared entity graph across all agents. When an agent reports
an entity, the engine checks if that entity appears in other families'
hits. Cross-family matches = corroborated findings. Temporal correlation:
entities within N seconds of each other are linked into chains.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

log = logging.getLogger(__name__)

# Default temporal window for chain detection (seconds)
_DEFAULT_CHAIN_WINDOW_SECONDS = 300  # 5 minutes

# Entity types that are meaningful for cross-family correlation
_CORRELATABLE_TYPES = {
    "process_name", "ipv4", "domain", "domain_user",
    "sha256", "sha1", "md5", "windows_path", "url",
}


class EntityGraph:
    """Shared entity graph across all evidence families.

    Tracks which entities appear in which families, when they were seen,
    and which hits produced them. Used for cross-family correlation and
    temporal chain detection.
    """

    def __init__(self) -> None:
        # entity_type -> value -> {"families": set, "hits": [], "timestamps": []}
        self._entities: dict[str, dict[str, dict[str, Any]]] = {}
        # entity_type -> value -> list of (family, timestamp)
        self._temporal: dict[str, dict[str, list[tuple[str, datetime]]]] = {}

    def add_entity(
        self,
        entity_type: str,
        value: str,
        family: str,
        hit_ref: dict[str, Any],
        timestamp: datetime | None = None,
    ) -> None:
        """Add an entity observation to the graph."""
        key = value.lower()
        if entity_type not in self._entities:
            self._entities[entity_type] = {}
        if key not in self._entities[entity_type]:
            self._entities[entity_type][key] = {
                "value": value,
                "families": set(),
                "hits": [],
                "timestamps": [],
            }
        ent = self._entities[entity_type][key]
        ent["families"].add(family)
        ent["hits"].append(hit_ref)
        if timestamp:
            ent["timestamps"].append(timestamp)
            self._temporal.setdefault(entity_type, {}).setdefault(key, []).append(
                (family, timestamp)
            )

    def add_from_hits(self, entities: dict[str, list[dict[str, Any]]]) -> None:
        """Bulk-add entities from extract_entities() output."""
        for entity_type, entity_list in entities.items():
            for ent in entity_list:
                for hit_ref in ent.get("hits", []):
                    ts = hit_ref.get("ts")
                    dt = _parse_timestamp(ts) if ts else None
                    self.add_entity(
                        entity_type,
                        ent["value"],
                        hit_ref.get("family", ""),
                        hit_ref,
                        dt,
                    )

    def get_cross_family_entities(
        self, entity_type: str | None = None
    ) -> list[dict[str, Any]]:
        """Return entities that appear in more than one family."""
        results: list[dict[str, Any]] = []
        types_to_check = [entity_type] if entity_type else list(self._entities.keys())
        for etype in types_to_check:
            if etype not in _CORRELATABLE_TYPES:
                continue
            for _key, ent in self._entities.get(etype, {}).items():
                families = sorted(ent["families"])
                if len(families) >= 2:
                    results.append({
                        "type": etype,
                        "value": ent["value"],
                        "families": families,
                        "hit_count": len(ent["hits"]),
                        "hits": ent["hits"],
                    })
        return results

    def get_entity(self, entity_type: str, value: str) -> dict[str, Any] | None:
        """Get a specific entity by type and value."""
        key = value.lower()
        ent = self._entities.get(entity_type, {}).get(key)
        if ent:
            return {
                "type": entity_type,
                "value": ent["value"],
                "families": sorted(ent["families"]),
                "hits": ent["hits"],
            }
        return None

    def get_chains(
        self, window_seconds: int = _DEFAULT_CHAIN_WINDOW_SECONDS
    ) -> list[dict[str, Any]]:
        """Find temporal chains: entities that appear across families within
        a time window. Returns chains of correlated events."""
        chains: list[dict[str, Any]] = []
        for entity_type, entity_map in self._temporal.items():
            if entity_type not in _CORRELATABLE_TYPES:
                continue
            for key, observations in entity_map.items():
                if len(observations) < 2:
                    continue
                # Sort by timestamp
                sorted_obs = sorted(observations, key=lambda x: x[1])
                # Find chains: consecutive observations within window
                chain: list[dict[str, Any]] = []
                for i, (family, ts) in enumerate(sorted_obs):
                    if i == 0:
                        chain = [{"family": family, "ts": ts.isoformat(), "entity": key}]
                    else:
                        prev_ts = sorted_obs[i - 1][1]
                        if (ts - prev_ts) <= timedelta(seconds=window_seconds):
                            chain.append({
                                "family": family,
                                "ts": ts.isoformat(),
                                "entity": key,
                            })
                        else:
                            if len(chain) >= 2:
                                chains.append({
                                    "entity_type": entity_type,
                                    "entity": self._entities[entity_type][key]["value"],
                                    "events": chain,
                                    "duration_seconds": (
                                        sorted_obs[0][1] - sorted_obs[len(chain) - 1][1]
                                    ).total_seconds(),
                                    "families": sorted(set(o["family"] for o in chain)),
                                })
                            chain = [{"family": family, "ts": ts.isoformat(), "entity": key}]
                if len(chain) >= 2:
                    chains.append({
                        "entity_type": entity_type,
                        "entity": self._entities[entity_type][key]["value"],
                        "events": chain,
                        "duration_seconds": (
                            sorted_obs[0][1] - sorted_obs[len(chain) - 1][1]
                        ).total_seconds(),
                        "families": sorted(set(o["family"] for o in chain)),
                    })
        return chains

    def summary(self) -> dict[str, Any]:
        """Return a summary of the entity graph."""
        return {
            "total_entities": sum(len(v) for v in self._entities.values()),
            "by_type": {
                etype: len(entity_map)
                for etype, entity_map in self._entities.items()
            },
            "cross_family_count": len(self.get_cross_family_entities()),
        }


def _parse_timestamp(ts: str) -> datetime | None:
    """Best-effort timestamp parsing."""
    if not ts:
        return None
    ts = str(ts).strip()
    # Try ISO format first
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
    ):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def correlate_entities(
    entity_graph: EntityGraph,
) -> dict[str, Any]:
    """Run the correlation engine on the entity graph.

    Returns:
        corroborated_entities: entities appearing in 2+ families
        chains: temporal chains of correlated events
        summary: entity graph statistics
    """
    return {
        "corroborated_entities": entity_graph.get_cross_family_entities(),
        "chains": entity_graph.get_chains(),
        "summary": entity_graph.summary(),
    }
