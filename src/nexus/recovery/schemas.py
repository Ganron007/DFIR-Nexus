"""WP 10.9 — Recovery schemas for in-app artifact recovery surfaces."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

RecoveryCategory = Literal["rdp_bitmap", "thumbcache", "recycle_bin", "deleted_file"]


@dataclass
class RecoveryItem:
    """An artifact recovered through forensic extraction tooling."""

    id: str
    category: RecoveryCategory
    name: str
    source_path: str
    size_bytes: int
    extraction_path: str | None = None
    timestamp: str | None = None
    preview_url: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RecoverySummary:
    """Aggregated census of recovered items across forensic categories."""

    case_id: str
    rdp_tile_count: int = 0
    thumbcache_count: int = 0
    recycle_bin_count: int = 0
    deleted_file_count: int = 0
    generated_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
