"""Shared file ownership rules for tool-generated run logs.

These files describe the tool's invocation and progress, not the evidence. Keep
the names in one place so the indexer and lane's output-completeness checks
apply the same rule.
"""

from __future__ import annotations

from pathlib import Path

TOOL_OWN_LOGS: dict[str, frozenset[str]] = {
    "memprocfs": frozenset({"forensic.json"}),
    "logfileparser": frozenset({"debug.log"}),
    "sbecmd": frozenset({"!sbecmd_messages.txt"}),
    "suricata": frozenset({"suricata.log", "stats.log"}),
    "zeek": frozenset({"packet_filter.log", "loaded_scripts.log"}),
}


# TA-Z (2026-10-24): given `-m`, MFTECmd 2026.10 also exports that $MFT under its default name ("The $MFT is exported
# too, as before, with its default file names", pinned README at 2919ded). The lane's $J and $LogFile jobs write into
# their own folders and every lane MFTECmd job names its output with --csvf, so a default-named $MFT table in those
# folders is that by-product: byte-identical to the run's own $MFT table (T06: three copies of one 303 MB table were
# indexed). An examiner's own default-named MFTECmd output is placed under mftecmd/, which this rule leaves alone.
_MFTECMD_M_FOLDERS = frozenset({"mftecmd-usn", "mftecmd-logfile"})
_MFTECMD_DEFAULT_MFT_SUFFIX = "_mftecmd_$mft_output.csv"


def is_tool_own_log_name(tool: str, filename: str | Path) -> bool:
    """Return whether ``filename`` is a file ``tool`` writes about its own run, not about the evidence.

    That is a known invocation log, or MFTECmd's `-m` by-product: a copy of the $MFT table the run already has.
    """
    path = Path(filename)
    name = path.name.lower()
    if str(tool).lower() == "mftecmd" and name.endswith(_MFTECMD_DEFAULT_MFT_SUFFIX):
        return path.parent.name.lower() in _MFTECMD_M_FOLDERS
    return name in TOOL_OWN_LOGS.get(str(tool).lower(), frozenset())
