"""WP 10.9 — Recovery Service: Unified interface for all case recovery surfaces."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from nexus.recovery.deleted_files_browser import scan_deleted_files
from nexus.recovery.rdp_gallery import scan_rdp_tiles
from nexus.recovery.recycle_bin_browser import scan_recycle_bin
from nexus.recovery.schemas import RecoverySummary
from nexus.recovery.thumbcache_viewer import scan_thumbcache


class RecoveryService:
    """Provides structured, paginated, searchable recovery artifacts for a case."""

    def __init__(self, case_dir: Path | str) -> None:
        self.case_dir = Path(case_dir).resolve()

    def get_summary(self) -> RecoverySummary:
        """Return census counts across all artifact recovery categories."""
        rdp_count = len(scan_rdp_tiles(self.case_dir))
        thumb_count = len(scan_thumbcache(self.case_dir))
        rb_count = len(scan_recycle_bin(self.case_dir))
        del_count = len(scan_deleted_files(self.case_dir))

        return RecoverySummary(
            case_id=self.case_dir.name,
            rdp_tile_count=rdp_count,
            thumbcache_count=thumb_count,
            recycle_bin_count=rb_count,
            deleted_file_count=del_count,
        )

    def list_rdp_tiles(self, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        """List recovered RDP bitmap tiles with pagination."""
        all_items = scan_rdp_tiles(self.case_dir)
        total = len(all_items)
        sliced = all_items[offset : offset + limit]
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [it.to_dict() for it in sliced],
        }

    def list_thumbcache(self, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        """List recovered thumbcache entries with pagination."""
        all_items = scan_thumbcache(self.case_dir)
        total = len(all_items)
        sliced = all_items[offset : offset + limit]
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [it.to_dict() for it in sliced],
        }

    def list_recycle_bin(
        self, limit: int = 50, offset: int = 0, query: str | None = None
    ) -> dict[str, Any]:
        """List Recycle Bin records with search and pagination."""
        items = scan_recycle_bin(self.case_dir)
        if query:
            q = query.lower()
            items = [
                it
                for it in items
                if q in it.name.lower() or q in it.source_path.lower()
            ]
        total = len(items)
        sliced = items[offset : offset + limit]
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [it.to_dict() for it in sliced],
        }

    def list_deleted_files(
        self, limit: int = 50, offset: int = 0, query: str | None = None
    ) -> dict[str, Any]:
        """List deleted / unallocated files with search and pagination."""
        items = scan_deleted_files(self.case_dir)
        if query:
            q = query.lower()
            items = [
                it
                for it in items
                if q in it.name.lower() or q in it.source_path.lower()
            ]
        total = len(items)
        sliced = items[offset : offset + limit]
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [it.to_dict() for it in sliced],
        }

    def export_manifest(self) -> dict[str, Any]:
        """Export comprehensive JSON manifest of all recovered artifacts."""
        summary = self.get_summary()
        rdp = [it.to_dict() for it in scan_rdp_tiles(self.case_dir)]
        thumb = [it.to_dict() for it in scan_thumbcache(self.case_dir)]
        rb = [it.to_dict() for it in scan_recycle_bin(self.case_dir)]
        deleted = [it.to_dict() for it in scan_deleted_files(self.case_dir)]

        return {
            "summary": summary.to_dict(),
            "artifacts": {
                "rdp_bitmap": rdp,
                "thumbcache": thumb,
                "recycle_bin": rb,
                "deleted_file": deleted,
            },
        }
