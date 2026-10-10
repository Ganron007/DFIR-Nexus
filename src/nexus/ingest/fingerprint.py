"""Recognize a pre-processed forensic CSV from its header.

The tool lane normally parses raw evidence. When the examiner already has
EvtxECmd, MFTECmd, or LogFileParser output, the header is enough to name the
family. A generic spreadsheet stays unrecognized.
"""
from __future__ import annotations

import csv
import hashlib
from pathlib import Path


def _columns(header: str) -> set[str]:
    # The header is read as a CSV record, so a quoted column that contains a
    # comma stays one column, and a UTF-8 byte-order mark that a Windows tool
    # writes before the first column name is removed (R12: EvtxECmd output
    # starts with BOM and was not recognised by raw comma splitting).
    text = header.lstrip("﻿")
    if not text.strip():
        return set()
    row = next(csv.reader([text]), [])
    return {part.strip().lower() for part in row if part.strip()}


def family_for_csv_header(header: str) -> str | None:
    """Return a family name, or None when the header is not a known tool."""
    cols = _columns(header.splitlines()[0] if header else "")
    if {"recordnumber", "eventrecordid", "mapdescription", "payloaddata1"} <= cols:
        return "evtxecmd"
    if {"entrynumber", "inuse", "parententrynumber", "filename"} <= cols:
        return "mftecmd"
    if {"lsn", "redoop", "undoop"} <= cols or (
        "logfile" in cols and "currentlsn" in cols
    ):
        return "logfileparser"
    if {"executablename", "runcount", "lastrun"} <= cols:
        return "pecmd"
    if {"hivepath", "keypath", "valuename"} <= cols:
        return "recmd"
    if {"date", "time", "timezone", "macb", "source", "sourcetype"} <= cols:
        return "plaso"
    return None


def place_recognized_csv(source: Path, extraction_root: Path) -> Path | None:
    """Copy a recognized CSV under ``<extraction_root>/<family>/``.

    The examiner's original stays where it was registered. The copy is what
    the tool lane's folder-name family rule reads.
    """
    source = Path(source)
    if not source.is_file() or source.suffix.lower() != ".csv":
        return None
    try:
        # utf-8-sig: a BOM-prefixed header is still the same header (R12).
        lines = source.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        header = lines[0] if lines else ""
    except OSError:
        return None
    family = family_for_csv_header(header)
    if not family:
        return None
    dest_dir = Path(extraction_root) / family
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        source.resolve().relative_to(dest_dir.resolve())
        return source
    except ValueError:
        pass
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    dest = dest_dir / source.name
    if dest.exists():
        # Two different files that share a name (two hosts' parsed.csv) must
        # not overwrite each other (R11). Equal bytes are one copy, deduplicated;
        # different bytes get a content-named sibling, and the original stays
        # registered under its own evidence id.
        if hashlib.sha256(dest.read_bytes()).hexdigest() == digest:
            return dest
        dest = dest_dir / f"{source.stem}-{digest[:12]}{source.suffix}"
        if dest.exists():
            return dest
    dest.write_bytes(data)
    return dest


_RAW_HINTS: dict[str, tuple[str, ...]] = {
    "logfileparser": ("$logfile",),
    "mftecmd": ("$mft",),
    "evtxecmd": (".evtx",),
    "pecmd": (".pf",),
    "recmd": (".hiv", "ntuser.dat"),
}


def propose_pairs(items: list[dict]) -> list[dict]:
    """A pre-processed CSV and the raw artifact it can stand in for.

    Both must already be registered. The examiner still confirms the pair.
    """
    proposals: list[dict] = []
    for output in items:
        family = str(output.get("recognized_family") or "")
        digest = str(output.get("sha256") or "")
        hints = _RAW_HINTS.get(family, ())
        if not family or not digest or not hints:
            continue
        for raw in items:
            if raw is output:
                continue
            name = str(raw.get("name") or "").lower()
            if not any(hint in name for hint in hints):
                continue
            proposals.append({
                "raw_name": raw.get("name") or "",
                "output_name": output.get("name") or "",
                "output_sha256": digest,
                "family": family,
            })
    return proposals


def place_loose_csvs(root: Path) -> list[Path]:
    """Copy recognized CSVs that sit in ``root`` itself into ``root/<family>/``.

    Tool output that is already inside a subfolder is left where the lane
    wrote it. Only a file dropped at the root of ingest or extractions needs
    a family folder so the indexer can name it.
    """
    root = Path(root)
    if not root.is_dir():
        return []
    placed: list[Path] = []
    for source in list(root.glob("*.csv")):
        dest = place_recognized_csv(source, root)
        if dest is None or dest.resolve() == source.resolve():
            continue
        source.unlink()
        placed.append(dest)
    return placed
