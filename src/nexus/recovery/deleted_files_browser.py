"""WP 10.9 — Deleted File Recovery Browser.

Parses The Sleuth Kit (fls / icat) deleted file extractions and bodyfiles
into a searchable surface showing unallocated/deleted paths, inodes, timestamps, and sizes.
"""

from __future__ import annotations

import re
from pathlib import Path

from nexus.recovery.schemas import RecoveryItem

# Match fls deleted entry: e.g. "d/d * 1422-144-1:  Folder/File.ext" or "r/r * 2841: file.txt"
_FLS_DELETED_RE = re.compile(
    r"^([a-z\-]+/[a-z\-]+)\s+\*\s+(\d+(?:-\d+-\d+)?):\s+(.+)$",
    re.IGNORECASE,
)


def parse_fls_output(fls_path: Path, case_dir: Path) -> list[RecoveryItem]:
    """Parse TSK fls output text for deleted file records."""
    items: list[RecoveryItem] = []
    if not fls_path.is_file():
        return items

    try:
        lines = fls_path.read_text(encoding="utf-8", errors="replace").splitlines()
        for idx, line in enumerate(lines, start=1):
            m = _FLS_DELETED_RE.match(line.strip())
            if not m:
                continue

            entry_type, inode, path_str = m.group(1), m.group(2), m.group(3).strip()
            name = Path(path_str).name or path_str
            item_id = f"del_{idx:05d}"

            items.append(
                RecoveryItem(
                    id=item_id,
                    category="deleted_file",
                    name=name,
                    source_path=path_str,
                    size_bytes=0,
                    extraction_path=fls_path.relative_to(case_dir).as_posix() if fls_path.is_relative_to(case_dir) else str(fls_path),
                    metadata={
                        "inode": inode,
                        "type": entry_type,
                        "status": "deleted / unallocated",
                        "full_path": path_str,
                    },
                    provenance={
                        "tool": "fls",
                        "source": "TSK File System Walk",
                    },
                )
            )
    except Exception:
        pass

    return items


def scan_deleted_files(case_dir: Path) -> list[RecoveryItem]:
    """Scan case directory for fls outputs or icat extracted deleted files."""
    items: list[RecoveryItem] = []
    extractions = case_dir / "extractions"
    if not extractions.is_dir():
        return items

    for p in extractions.rglob("*"):
        if not p.is_file():
            continue
        p_name = p.name.lower()
        if "fls" in p_name and p.suffix.lower() in (".txt", ".log", ".body"):
            items.extend(parse_fls_output(p, case_dir))
        elif "icat" in p_name or "carved" in p_name:
            rel = p.relative_to(case_dir).as_posix()
            item_id = f"del_{len(items)+1:05d}"
            items.append(
                RecoveryItem(
                    id=item_id,
                    category="deleted_file",
                    name=p.name,
                    source_path=rel,
                    size_bytes=p.stat().st_size,
                    extraction_path=rel,
                    metadata={
                        "status": "carved / extracted",
                        "file_size": p.stat().st_size,
                    },
                    provenance={
                        "tool": "icat",
                        "source": "TSK Inode Extraction",
                    },
                )
            )

    return items
