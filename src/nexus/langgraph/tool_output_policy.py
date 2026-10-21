"""Shared file ownership rules for tool-generated run logs.

These files describe the tool's invocation and progress, not the evidence. Keep
the names in one place so the indexer and lane's output-completeness checks
apply the same rule.
"""

from __future__ import annotations

from pathlib import Path

TOOL_OWN_LOGS: dict[str, frozenset[str]] = {
    "logfileparser": frozenset({"debug.log"}),
    "suricata": frozenset({"suricata.log", "stats.log"}),
    "zeek": frozenset({"packet_filter.log", "loaded_scripts.log"}),
}


def is_tool_own_log_name(tool: str, filename: str | Path) -> bool:
    """Return whether ``filename`` is a known invocation log for ``tool``."""
    return Path(filename).name.lower() in TOOL_OWN_LOGS.get(str(tool).lower(), frozenset())
