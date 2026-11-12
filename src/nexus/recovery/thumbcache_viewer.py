"""WP 10.9 — Thumbcache / Iconcache Viewer.

Parses extracted thumbnail and icon cache entries into an in-app viewer.
"""

from __future__ import annotations

import re
from pathlib import Path

from nexus.recovery.schemas import RecoveryItem

_THUMB_FILE_RE = re.compile(r"thumbcache_(\d+)", re.IGNORECASE)


def scan_thumbcache(case_dir: Path) -> list[RecoveryItem]:
    """Scan case extractions for recovered thumbcache entries."""
    items: list[RecoveryItem] = []
    extractions = case_dir / "extractions"
    if not extractions.is_dir():
        return items

    for p in extractions.rglob("*"):
        if not p.is_file():
            continue

        parent_names = [part.lower() for part in p.parts]
        is_thumb = any("thumb" in part or "icon" in part for part in parent_names)
        if not is_thumb and not _THUMB_FILE_RE.search(p.name):
            continue

        if p.suffix.lower() not in (".jpg", ".jpeg", ".png", ".bmp", ".db"):
            continue

        rel_path = p.relative_to(case_dir).as_posix()
        file_size = p.stat().st_size

        m = _THUMB_FILE_RE.search(p.name) or _THUMB_FILE_RE.search(str(p.parent))
        resolution = m.group(1) if m else "unknown"

        item_id = f"thumb_{len(items)+1:05d}"
        items.append(
            RecoveryItem(
                id=item_id,
                category="thumbcache",
                name=p.name,
                source_path=rel_path,
                size_bytes=file_size,
                extraction_path=rel_path,
                metadata={
                    "resolution": resolution,
                    "format": p.suffix.lstrip(".").upper(),
                    "file_name": p.name,
                },
                provenance={
                    "tool": "thumbcache_viewer",
                    "source": "Windows Thumbnail/Icon Cache",
                },
            )
        )

    return items
