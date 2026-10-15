"""A Hayabusa timeline row read back as the event it reports (D232).

Hayabusa writes a matched event's channel by its own abbreviation (`Sec`, `Defender`), the fields its
rule shows as `Label: value` pieces under the rule's details template, the other fields under their own
names (ExtraFieldInfo), and some values rewritten into words (`LogonType` 0 as `0 - SYSTEM`). Read as
written, a row carried neither its event's channel nor its data, so no pinned category or event-data
map applied to the rows findings cite most.

Everything here is Hayabusa's own: `data/schema/hayabusa_fields.yaml` is generated from the
hayabusa-rules repository the lane runs (devtools/knowledge/import_hayabusa_fields.py), and the provider
of a channel's event comes from the pinned Windows manifests (`event_categories.provider_for`).
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from nexus.langgraph.event_categories import provider_for

_TABLE = Path(__file__).resolve().parents[1] / "data" / "schema" / "hayabusa_fields.yaml"
#: Hayabusa joins the fields of Details and ExtraFieldInfo with this separator.
_SEPARATOR = "¦"


@lru_cache(maxsize=1)
def _table() -> dict[str, Any]:
    return yaml.safe_load(_TABLE.read_text(encoding="utf-8")) or {}


def _pairs(text: Any) -> list[tuple[str, str]]:
    """`Label: value ¦ Label: value` -> [(label, value), ...]; a value may itself hold `: `."""
    out: list[tuple[str, str]] = []
    for piece in str(text or "").split(_SEPARATOR):
        label, sep, value = piece.strip().partition(": ")
        if sep and label.strip():
            out.append((label.strip(), value.strip()))
    return out


def channel_of(raw: Any) -> str:
    """The channel a Hayabusa row names, unabbreviated."""
    text = str(raw or "").strip()
    return str((_table().get("channels") or {}).get(text, text))


def hayabusa_event(fields: dict[str, Any]) -> tuple[str, str, dict[str, str]]:
    """(channel, provider, event data) of one Hayabusa timeline row.

    The event data is the row's ExtraFieldInfo, under the fields' own names, and its Details read
    through the template that wrote them: the rule's own (by RuleID), else Hayabusa's default for the
    event's (provider, event id). A label no template names is left out: its field cannot be told.
    Values Hayabusa rewrote are given back their original form.
    """
    table = _table()
    channel = channel_of(fields.get("Channel"))
    event_id = str(fields.get("EventID") or "").strip()
    provider = provider_for(channel, event_id)
    data: dict[str, str] = dict(_pairs(fields.get("ExtraFieldInfo")))
    template = (table.get("rule_details") or {}).get(str(fields.get("RuleID") or "").strip())
    if template is None and provider:
        template = (table.get("default_details") or {}).get(f"{provider}|{event_id}")
    by_label = {str(label): str(field) for label, field in (template or [])}
    for label, value in _pairs(fields.get("Details")):
        if label in by_label:
            data[by_label[label]] = value
    for field, back in ((table.get("rewrites") or {}).get(f"{channel}|{event_id}") or {}).items():
        if data.get(field) in back:
            data[field] = back[data[field]]
    return channel, provider, data
