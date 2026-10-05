"""WO-KR2c 0c: map an EvtxECmd concept to its generic column per event ID.

The reviewer's point: EvtxECmd 4624 puts the user in `PayloadData1` as
`Target: NT AUTHORITY\SYSTEM`, the logon type in `PayloadData2` as `LogonType 5`,
and the binary in `ExecutableInfo`. A stored query searching `process_name` or
`command_line` on an EVTX family is searching a column that is not there.

`src/nexus/data/schema/evtxecmd_maps.yaml` (imported from the pinned EZTools
snapshot by `import_evtx_maps.py`) says what each generic column holds per
(Channel, EventId). This module reads it and answers the two questions a converter
needs:

- which columns an EvtxECmd event fills for a given concept;
- what template that column's value has, so a query can target the RIGHT part
  (`Target: `), not just the column.

Design time only: `src/nexus` never imports this at runtime. The runtime answer is
the live catalog (`es_mappings`) plus the population index.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
MAPS = REPO / "src" / "nexus" / "data" / "schema" / "evtxecmd_maps.yaml"

#: A concept -> the map templates that carry it. These are matched against the
#: imported `PropertyValue` template (e.g. `Target: %TargetDomainName%\...`), so
#: they describe how a concept APPEARS in the value rather than the value itself.
#: The wording follows the EZTools maps' own templates, which are the whole point:
#: EvtxECmd 4624 carries the user in `PayloadData1` as `Target: <domain>\<user>`,
#: and that literal prefix is what a parsed row contains.
CONCEPT_PATTERNS = {
    "user": ["target user", "subject user", "account", "user name",
             "logon account", "%targetusername%", "%subjectusername%", "%user%",
             "target domain", "subject domain"],
    "process": ["process", "image", "executable", "binary", "exe", "logon processname"],
    "parent": ["parent process", "parent image", "parent"],
    "command": ["command line", "process command", "cmdline"],
    "file": ["file", "target filename", "object name"],
    "registry": ["key", "registry", "target object"],
    "logontype": ["logon type", "logontype"],
    "ip": ["source address", "ip address", "dest address", "destination address",
           "%ipaddress%", "workstation"],
    "port": ["port"],
    "hash": ["hash", "sha", "md5"],
    "service": ["service", "driver"],
    "task": ["task"],
    "parentcommand": ["parent command"],
    "logonid": ["logon id", "targetlogonid", "logonid"],
    "workstation": ["workstation", "%workstation%"],
    "scriptblock": ["scriptblocktext", "script block"],
    "authenticationpackage": ["authenticationpackagename"],
}


def _load() -> list[dict[str, Any]]:
    import yaml

    if not MAPS.is_file():
        return []
    data = yaml.safe_load(MAPS.read_text(encoding="utf-8")) or {}
    return [e for e in (data.get("packs") or []) if isinstance(e, dict)]


def _norm(text: Any) -> str:
    return str(text or "").strip().lower()


def columns_for_concept(concept: str, *, event_id: str = "",
                        channel: str = "") -> list[dict[str, str]]:
    """What EvtxECmd columns carry `concept`, and each column's value template.

    An empty result is honest: the maps do not name that column for this event.
    """
    keys = CONCEPT_PATTERNS.get(_norm(concept), [_norm(concept)])
    out: list[dict[str, str]] = []
    for entry in _load():
        if event_id and str(entry.get("event_id") or "") != str(event_id):
            continue
        if channel and _norm(entry.get("channel")) != _norm(channel):
            continue
        for column, meta in (entry.get("columns") or {}).items():
            template = str((meta or {}).get("template") or "")
            if not template:
                continue
            if any(k in template.lower() for k in keys):
                out.append({
                    "column": str(column),
                    "template": template,
                    "channel": str(entry.get("channel") or ""),
                    "event_id": str(entry.get("event_id") or ""),
                    "description": str(entry.get("description") or ""),
                })
    return out


def query_for_concept(concept: str, value: str = "", *, event_id: str = "",
                      channel: str = "") -> list[str]:
    """Wildcard values that would match the column's own template.

    For a 4624 `user` the template is `Target:
    %TargetDomainName%\%TargetUserName%`, so the useful search is the literal
    prefix the parser emits (`Target: `), never the placeholder name.
    """
    wants = CONCEPT_PATTERNS.get(_norm(concept), [_norm(concept)])
    out: list[str] = []
    for entry in _load():
        if event_id and str(entry.get("event_id") or "") != str(event_id):
            continue
        if channel and _norm(entry.get("channel")) != _norm(channel):
            continue
        for column, meta in (entry.get("columns") or {}).items():
            template = str((meta or {}).get("template") or "")
            low = template.lower()
            if not any(k in low for k in wants):
                continue
            # The static prefix before the first placeholder is what a parsed row
            # actually contains; `Target: ` matches, `%TargetUserName%` does not.
            # The prefix may start with a placeholder when the template is the
            # bare value (4624 UserName is `%domain%\%user%`), in which case no
            # literal prefix exists and the value itself must be searched.
            m = re.match(r"^(?:([A-Za-z][A-Za-z ]{0,24}:)\s*|(%[A-Za-z]+%))", template)
            if m:
                out.append(f'{column}:{m.group(1) if m.group(1) else m.group(2)}')
    return sorted(set(out))


def summary() -> dict[str, Any]:
    entries = _load()
    return {
        "entries": len(entries),
        "channels": len({str(e.get("channel")) for e in entries}),
        "generic_columns": sorted({
            c for e in entries for c in (e.get("columns") or {})
        }),
    }
