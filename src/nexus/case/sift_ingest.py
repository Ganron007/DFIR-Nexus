"""Stage SIFT-produced outputs into a case (Option B - ingest-only).

The examiner runs SIFT tools themselves (plaso, vol3, TSK, bulk_extractor)
and hands us the outputs; this stages them under
``<case>/sift/extractions/<family>/`` - an index root - where the existing
field mappings (``es_mappings/<family>.yaml``) type the rows. Name the family
after the tool (``plaso``, ``vol``, ``fls``, ``bulk_extractor``) so the right
mapping applies.
"""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path


def stage_sift_outputs(
    case_dir: Path,
    paths: list[Path],
    *,
    family: str = "",
) -> list[Path]:
    """Copy directories / extract zips / copy files into ``sift/extractions``.

    Returns the staged destination directories, newest last. Existing content
    is merged, never deleted - staging is additive.
    """
    dest_root = Path(case_dir) / "sift" / "extractions"
    staged: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            raise FileNotFoundError(f"SIFT output not found: {p}")
        name = (family or p.stem or "sift").strip()
        dest = dest_root / name
        dest.mkdir(parents=True, exist_ok=True)
        if p.is_dir():
            shutil.copytree(p, dest, dirs_exist_ok=True)
        elif p.suffix.lower() == ".zip":
            with zipfile.ZipFile(p) as zf:
                zf.extractall(dest)
        else:
            shutil.copy2(p, dest / p.name)
        staged.append(dest)
    return staged
