"""WP 10.9 — RDP Bitmap Cache Gallery.

Parses extracted RDP bitmap cache tiles (from bmc-tools) into an in-app gallery
with dimensions, source cache file, user context, and preview tokens.
"""

from __future__ import annotations

import re
from pathlib import Path

from nexus.recovery.schemas import RecoveryItem

_TILE_PATTERN = re.compile(r"(\d+)_([0-9a-fA-F]+)")


def scan_rdp_tiles(case_dir: Path) -> list[RecoveryItem]:
    """Scan case extractions for recovered RDP bitmap tiles."""
    items: list[RecoveryItem] = []
    extractions = case_dir / "extractions"
    if not extractions.is_dir():
        return items

    # Search for bmc-tools directories or bmc extraction subfolders
    for p in extractions.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in (".bmp", ".png"):
            continue

        parent_names = [part.lower() for part in p.parts]
        if not any("bmc" in part or "rdp" in part for part in parent_names):
            continue

        rel_path = p.relative_to(case_dir).as_posix()
        file_size = p.stat().st_size

        # Extract tile index or user from path relative to extractions
        rel_to_ext = p.relative_to(extractions)
        user = "unknown"
        for part in rel_to_ext.parts:
            if part.lower() not in ("extractions", "bmc", "bmc-tools", "tiles") and part != p.name:
                user = part
                break

        tile_id = f"rdp_{len(items)+1:05d}"
        items.append(
            RecoveryItem(
                id=tile_id,
                category="rdp_bitmap",
                name=p.name,
                source_path=rel_path,
                size_bytes=file_size,
                extraction_path=rel_path,
                metadata={
                    "user": user,
                    "format": p.suffix.lstrip(".").upper(),
                    "file_name": p.name,
                },
                provenance={
                    "tool": "bmc-tools",
                    "source": "RDP Bitmap Cache (bcache/bin)",
                },
            )
        )

    return items
