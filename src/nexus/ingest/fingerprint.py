"""Recognize a pre-processed forensic CSV from its header.

The tool lane normally parses raw evidence. When the examiner already has
EvtxECmd, MFTECmd, or LogFileParser output, the header is enough to name the
family. A generic spreadsheet stays unrecognized.
"""
from __future__ import annotations

from pathlib import Path


def _columns(header: str) -> set[str]:
    return {part.strip().lower().strip('"') for part in header.split(",") if part.strip()}


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
        lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
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
    dest = dest_dir / source.name
    if source.resolve() != dest.resolve():
        dest.write_bytes(source.read_bytes())
    return dest


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
