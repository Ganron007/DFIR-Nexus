"""Velociraptor framework schemas (D.0.2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class VRCatalogEntry:
    """A Velociraptor hunt or custom artifact catalog row."""

    id: str
    artifact_name: str
    title: str
    description: str
    platforms: list[str]
    technique_ids: list[str] = field(default_factory=list)
    kind: str = "hunt"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "artifact_name": self.artifact_name,
            "title": self.title,
            "description": self.description,
            "platforms": self.platforms,
            "technique_ids": self.technique_ids,
            "kind": self.kind,
        }


@dataclass
class VRClientInfo:
    """Enrolled Velociraptor client."""

    client_id: str
    hostname: str
    platform: str
    ip: str = ""
    online: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "hostname": self.hostname,
            "platform": self.platform,
            "ip": self.ip,
            "online": self.online,
        }


@dataclass
class VRHuntRunResult:
    """Result of orchestrated hunt / artifact collection."""

    hunt_id: str
    artifact_name: str
    client_id: str
    row_count: int
    rows: list[dict[str, Any]] = field(default_factory=list)
    duration_ms: int = 0
    error: str | None = None
    vql: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hunt_id": self.hunt_id,
            "artifact_name": self.artifact_name,
            "client_id": self.client_id,
            "row_count": self.row_count,
            "rows": self.rows,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "vql": self.vql,
        }
