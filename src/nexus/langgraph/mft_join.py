"""D116 (2026-10-13): the parent directory of a USN journal row, from the MFT of the same run.

MFTECmd writes the USN journal with the file's name (``Name``) and its parent's entry number, and leaves
``ParentPath`` empty: in the case of 2026-10-13, all 365,943 rows. The parent directory is the path of the MFT
entry that the row's ``ParentEntryNumber`` and ``ParentSequenceNumber`` name. The join is exact where that entry is
in the MFT of the same run. Where it is not (the directory was deleted or never recorded), the row keeps no path:
the path is not guessed from the name.
"""
from __future__ import annotations

import csv
from functools import lru_cache
from pathlib import Path
from typing import Any

_USN_NAME = "usn.csv"
_USN_FOLDER = "mftecmd-usn"
_MFT_FOLDER = "mftecmd"
PARENT_SOURCE = "MFT join (same run): ParentEntryNumber and ParentSequenceNumber"


def usn_mft_csv(path: Path) -> Path | None:
    """The MFT of the run a USN journal belongs to: ``mftecmd/mft.csv`` beside ``mftecmd-usn/``; None for any other file."""
    if path.name.lower() != _USN_NAME or path.parent.name.lower() != _USN_FOLDER:
        return None
    mft = path.parent.parent / _MFT_FOLDER / "mft.csv"
    return mft if mft.is_file() else None


@lru_cache(maxsize=2)
def mft_parent_paths(mft_csv: str) -> dict[tuple[str, str], str]:
    """``(EntryNumber, SequenceNumber)`` -> the entry's own path, ``ParentPath\\FileName``, for every named MFT entry."""
    paths: dict[tuple[str, str], str] = {}
    with Path(mft_csv).open(encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            entry = str(row.get("EntryNumber") or "").strip()
            name = str(row.get("FileName") or "").strip()
            if not entry or not name:
                continue
            parent = str(row.get("ParentPath") or "").strip()
            key = (entry, str(row.get("SequenceNumber") or "").strip())
            paths.setdefault(key, f"{parent}\\{name}" if parent else name)
    return paths


def resolve_usn_row(path: Path, fields: dict[str, Any]) -> dict[str, Any]:
    """The row's fields with ``ParentPath`` and ``FileName`` set when the MFT names the parent entry; unchanged otherwise.

    ``FileName`` takes the row's ``Name``, so the family's own join makes the full path. A row whose parent does not
    resolve keeps no path. The resolved fields are marked by ``ParentPathSource``, so a stored document says where its
    path came from.
    """
    if not fields:
        return fields
    mft = usn_mft_csv(path)
    if mft is None:
        return fields
    key = (
        str(fields.get("ParentEntryNumber") or "").strip(),
        str(fields.get("ParentSequenceNumber") or "").strip(),
    )
    if not key[0]:
        return fields
    parent = mft_parent_paths(str(mft)).get(key)
    name = str(fields.get("Name") or "").strip()
    if not parent or not name:
        return fields
    # The file name takes the MFT's FileName column, so the family's own join makes the full path.
    return {**fields, "ParentPath": parent, "FileName": name, "ParentPathSource": PARENT_SOURCE}
