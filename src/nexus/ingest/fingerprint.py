"""Recognize a pre-processed forensic CSV from its header.

The tool lane normally parses raw evidence. When the examiner already has
EvtxECmd, MFTECmd, or LogFileParser output, the header is enough to name the
family. A generic spreadsheet stays unrecognized.
"""
from __future__ import annotations


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
    if {"date", "time", "timezone", "macb", "source", "sourcetype"} <= cols:
        return "plaso"
    return None
