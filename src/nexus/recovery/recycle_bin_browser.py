"""WP 10.9 — Recycle Bin Browser.

Parses RBCmd CSV outputs and raw $I/$R Recycle Bin records into a searchable,
sortable recovery surface with original paths, file sizes, and deletion timestamps.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from nexus.recovery.schemas import RecoveryItem


def parse_rbcmd_csv(csv_path: Path, case_dir: Path) -> list[RecoveryItem]:
    """Parse an RBCmd CSV output file into structured RecoveryItems."""
    items: list[RecoveryItem] = []
    if not csv_path.is_file():
        return items

    try:
        content = csv_path.read_text(encoding="utf-8-sig", errors="replace")
        reader = csv.DictReader(io.StringIO(content))
        for idx, row in enumerate(reader, start=1):
            # Normalize headers case-insensitively
            lower_row = {k.lower().strip(): v.strip() for k, v in row.items() if k}

            orig_path = lower_row.get("originalpath") or lower_row.get("original filename") or lower_row.get("filename") or "Unknown"
            source_file = lower_row.get("sourcefile") or lower_row.get("source name") or csv_path.name
            deleted_on = lower_row.get("deletedon") or lower_row.get("deleted on") or lower_row.get("timestamp") or None
            file_size_str = lower_row.get("filesize") or lower_row.get("file size") or "0"
            try:
                file_size = int(file_size_str)
            except ValueError:
                file_size = 0

            filename = Path(orig_path).name or source_file
            item_id = f"rb_{idx:05d}"

            items.append(
                RecoveryItem(
                    id=item_id,
                    category="recycle_bin",
                    name=filename,
                    source_path=source_file,
                    size_bytes=file_size,
                    extraction_path=csv_path.relative_to(case_dir).as_posix() if csv_path.is_relative_to(case_dir) else str(csv_path),
                    timestamp=deleted_on,
                    metadata={
                        "original_path": orig_path,
                        "file_extension": Path(orig_path).suffix.lower(),
                        "deleted_on": deleted_on,
                        "source_i_file": source_file,
                    },
                    provenance={
                        "tool": "RBCmd",
                        "source": "Windows Recycle Bin ($I/$R)",
                    },
                )
            )
    except Exception:
        pass

    return items


def scan_recycle_bin(case_dir: Path) -> list[RecoveryItem]:
    """Scan case directory for RBCmd CSV outputs or Recycle Bin evidence."""
    items: list[RecoveryItem] = []
    extractions = case_dir / "extractions"
    if not extractions.is_dir():
        return items

    for p in extractions.rglob("*.csv"):
        if not p.is_file():
            continue
        p_name = p.name.lower()
        if "rbcmd" in p_name or "recycle" in p_name or "$recycle" in p_name:
            items.extend(parse_rbcmd_csv(p, case_dir))

    # Fallback: scan for any $I files in extractions
    if not items:
        for p in extractions.rglob("$I*"):
            if not p.is_file():
                continue
            item_id = f"rb_{len(items)+1:05d}"
            rel = p.relative_to(case_dir).as_posix()
            items.append(
                RecoveryItem(
                    id=item_id,
                    category="recycle_bin",
                    name=p.name,
                    source_path=rel,
                    size_bytes=p.stat().st_size,
                    extraction_path=rel,
                    metadata={
                        "source_i_file": p.name,
                        "raw_i_record": True,
                    },
                    provenance={
                        "tool": "filesystem",
                        "source": "Recycle Bin $I file",
                    },
                )
            )

    return items
