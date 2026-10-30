"""A detection tool's row read back as its event (D474).

Chainsaw and Zircolite write each event a rule matched as a row of their own columns. Their event data was added
after the step that types an event (the per-(channel, event) table and the event's own user, D471), so a Zircolite
4688 row carried no process and no user, its rule columns and the event's System fields were read as event data,
and a Chainsaw row's YAML cell was read line by line. Which column is the event's System field, which its data and
which the tool's own is the tools' own data (``data/schema/tool_event_columns.yaml``, generated from their files at
their release tags by ``devtools/knowledge/import_tool_event_columns.py``).

A reader returns the event's System fields by their EVTX path (``Event.System.EventID``) and its event data by name.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from nexus.langgraph.event_categories import channel_for

_TABLE = Path(__file__).resolve().parents[1] / "data" / "schema" / "tool_event_columns.yaml"
CHANNEL = "Event.System.Channel"
PROVIDER = "Event.System.Provider"
EVENT_ID = "Event.System.EventID"
#: The paths a tool writes one System field under in more than one form: Zircolite's provider is its name
#: attribute, and its event id is the element or its `#text`.
_SAME_FIELD = {"Event.System.Provider.#attributes.Name": PROVIDER, "Event.System.EventID.#text": EVENT_ID}


@lru_cache(maxsize=1)
def _table() -> dict[str, Any]:
    return yaml.safe_load(_TABLE.read_text(encoding="utf-8")) or {}


class _EventDataLoader(yaml.BaseLoader):
    """Every scalar as the string it is written as, except a plain null, which is no value."""


_EventDataLoader.add_implicit_resolver(
    "tag:yaml.org,2002:null", re.compile(r"^(?:~|null|Null|NULL|)$"), ["~", "n", "N", ""])
_EventDataLoader.add_constructor("tag:yaml.org,2002:null", lambda _loader, _node: None)


def _value(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value)


def _yaml_cell(cell: Any) -> dict[str, str]:
    """An object cell Chainsaw wrote as YAML (``serde_yaml``) -> {name: value}, each value as written."""
    try:
        doc = yaml.load(str(cell or ""), Loader=_EventDataLoader)  # noqa: S506 - BaseLoader constructs no objects
    except yaml.YAMLError:
        return {}
    if not isinstance(doc, dict):
        return {}
    return {str(k): _value(v) for k, v in doc.items() if v not in (None, "")}


def _text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def chainsaw_event(fields: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    """One Chainsaw hunt row. Chainsaw writes no channel: it is the one the pinned manifests give the row's
    (provider, event id)."""
    columns = _table()["chainsaw"]["columns"]  # event path -> column
    system = {path: _text(fields.get(column)) for path, column in columns.items() if path.startswith("Event.System.")}
    if not system.get(CHANNEL):
        system[CHANNEL] = channel_for(system.get(PROVIDER), system.get(EVENT_ID))
    data_column = columns.get("Event.EventData")
    return {p: v for p, v in system.items() if v}, _yaml_cell(fields.get(data_column)) if data_column else {}


def zircolite_event(fields: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    """One Zircolite NDJSON line: every column the tool's mappings do not name a System field of, and that is not
    the tool's own (the rule's, the ones it adds, a transform's), is the event's data."""
    z = _table()["zircolite"]
    paths = z["system"]  # event path -> column
    system: dict[str, str] = {}
    for path, column in paths.items():
        value = _text(fields.get(column))
        if value:
            system.setdefault(_SAME_FIELD.get(path, path), value)
    own = set(paths.values()) | set(z["rule"]) | set(z["added"]) | set(z["derived"])
    data = {str(k): _value(v) for k, v in fields.items() if k not in own and v not in (None, "")}
    return system, data


READERS: dict[str, Callable[[dict[str, Any]], tuple[dict[str, str], dict[str, str]]]] = {
    "chainsaw": chainsaw_event,
    "zircolite": zircolite_event,
}
