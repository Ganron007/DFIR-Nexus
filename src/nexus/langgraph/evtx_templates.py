"""The value an EvtxECmd map placed in a generic column, without the map's own words (D214).

EvtxECmd renders a map's template into its generic columns (`UserName`, `PayloadData1`, ...), and
a template may carry literal text: Defender 1116 writes `Detection User: %User%`, Task Scheduler
`Context: %UserContext%`, Security `%domain%\\%user% (%sid%)`. Copied as is, the column made
`Context: NT AUTHORITY\\SYSTEM` (18,087 rows of CASE-C5B04D31) and a bare `Detection User:` the user,
and split one account in two (`shieldbase\\rd01$` and `shieldbase\\rd01$ (s-1-5-18)`).

The templates come from the pinned maps (`data/schema/evtxecmd_maps.yaml`, imported from
EricZimmerman/evtx), never typed here. The value is the template's first run of placeholders
joined only by a domain separator: the user a template names first, `domain\\user`, without a label
or a trailing `(sid)`. A value no template of its (channel, event) fits is returned unchanged.

`event_value` reads the same value from an event's own data, for the tools that do not render the maps (D471:
MemProcFS's event logs from memory had a user only for the events a hand-written table repeated).
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

_MAPS = Path(__file__).resolve().parents[1] / "data" / "schema" / "evtxecmd_maps.yaml"
_PLACEHOLDER = re.compile(r"%([^%\s]+)%")
#: EvtxECmd's empty marker (a 4624 with no workstation reads `-`).
_EMPTY = {"", "-"}


@lru_cache(maxsize=1)
def _packs() -> dict[tuple[str, str], dict[str, list[str]]]:
    """(channel, event id) -> column -> its templates, from the pinned maps."""
    try:
        import yaml

        doc = yaml.safe_load(_MAPS.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 - without the maps every value stays as rendered
        return {}
    out: dict[tuple[str, str], dict[str, list[str]]] = {}
    for pack in doc.get("packs") or []:
        key = (str(pack.get("channel") or "").strip().lower(), str(pack.get("event_id") or "").strip())
        columns = out.setdefault(key, {})
        for column, spec in (pack.get("columns") or {}).items():
            templates = [str(v.get("template") or "") for v in spec.get("variants") or []] or [
                str(spec.get("template") or "")]
            columns.setdefault(str(column), [])
            columns[str(column)] += [t for t in templates if t and t not in columns[str(column)]]
    return out


@lru_cache(maxsize=1)
def rendered_columns() -> frozenset[str]:
    """The columns a map renders a template into (`UserName`, `PayloadData1`, ...), from the maps."""
    return frozenset(column for columns in _packs().values() for column in columns)


@lru_cache(maxsize=512)
def _pattern(template: str) -> tuple[re.Pattern[str], tuple[int, ...]] | None:
    """The template as a pattern, and the groups of its first placeholder run."""
    parts = _PLACEHOLDER.split(template)  # literal, name, literal, name, ..., literal
    names = parts[1::2]
    if not names:
        return None
    # Whitespace in the literal text is matched loosely: a value with nothing after its label is
    # stored trimmed (`Detection User:`, not `Detection User: `).
    literals = [r"\s*".join(re.escape(piece) for piece in re.split(r"\s+", lit)) for lit in parts[0::2]]
    regex = "".join(lit + (f"(?P<g{i}>.*?)" if i < len(names) else "")
                    for i, lit in enumerate(literals))
    run = [0]
    for i in range(1, len(names)):
        if parts[2 * i] != "\\":  # the literal text between placeholder i-1 and i
            break
        run.append(i)
    return re.compile(f"^{regex}$", re.DOTALL), tuple(run)


#: Where a map source reads: one named EventData item, or a UserData element (`/Event/UserData/LogFileCleared/
#: SubjectUserName`), which a producer that flattens an event's data (MemProcFS's eventlog.csv) carries by its leaf name.
_DATA_ITEM = re.compile(r'^/Event/EventData/Data\[@Name="([^"]+)"\]$')
_USER_DATA_LEAF = re.compile(r"^/Event/UserData/[^/\[]+/([^/\[]+)$")


@lru_cache(maxsize=1)
def _readers() -> dict[tuple[str, str], dict[str, tuple[str, dict[str, str]]]]:
    """(channel, event id) -> column -> (template, {placeholder: the data name it reads}), from the pinned maps.

    The column's primary (last) occurrence, the one EvtxECmd renders: a real Sysmon 1 row's `UserName` is its `%User%`,
    not `ParentUser: %ParentUser%`. A placeholder read through a `Refine` pattern, or from anything but one named data
    item, has no entry, so a run holding one is not read from the data.
    """
    try:
        import yaml

        doc = yaml.safe_load(_MAPS.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 - without the maps no event value is read
        return {}
    out: dict[tuple[str, str], dict[str, tuple[str, dict[str, str]]]] = {}
    for pack in doc.get("packs") or []:
        key = (str(pack.get("channel") or "").strip().lower(), str(pack.get("event_id") or "").strip())
        for column, spec in (pack.get("columns") or {}).items():
            names: dict[str, str] = {}
            for source in spec.get("sources") or []:
                found = _DATA_ITEM.match(str(source.get("xpath") or "")) or _USER_DATA_LEAF.match(
                    str(source.get("xpath") or ""))
                if found and source.get("name") and not source.get("refine"):
                    names[str(source["name"])] = found.group(1)
            out.setdefault(key, {})[str(column)] = (str(spec.get("template") or ""), names)
    return out


def event_value(channel: Any, event_id: Any, column: str, data: dict[str, Any]) -> str | None:
    """The value the map places in ``column``, read from an event's own data, whichever tool read the event (D471).

    The same value ``map_value`` reads back from EvtxECmd's rendering of that event: the template's first run of
    placeholders joined only by a domain separator, an empty placeholder left out. ``""`` when the run's names are in
    the data but empty. None when the map gives the event no such column, a placeholder of the run is not a named data
    item, or the data carries none of the run's names.
    """
    reader = _readers().get((str(channel or "").strip().lower(), str(event_id or "").strip()), {}).get(column)
    if reader is None:
        return None
    template, names = reader
    compiled = _pattern(template)
    if compiled is None:
        return None
    placeholders = _PLACEHOLDER.split(template)[1::2]
    values: list[str] = []
    present = False
    for i in compiled[1]:
        name = names.get(placeholders[i])
        if name is None:
            return None
        if name in data:
            present = True
        values.append(str(data.get(name) or "").strip())
    if not present:
        return None
    return "\\".join(v for v in values if v not in _EMPTY)


def map_value(channel: Any, event_id: Any, column: str, rendered: Any) -> str:
    """The value the map placed in ``column``; the rendered text when no template of its event fits."""
    text = str(rendered or "")
    templates = _packs().get((str(channel or "").strip().lower(), str(event_id or "").strip()), {}).get(column)
    for template in templates or ():
        compiled = _pattern(template)
        if compiled is None:
            continue
        pattern, run = compiled
        match = pattern.match(text)
        if not match:
            continue
        values = [match.group(f"g{i}").strip() for i in run]
        if all(v in _EMPTY for v in values):
            return ""
        return "\\".join(v for v in values if v not in _EMPTY)
    return text
