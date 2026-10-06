"""WO-CS1 — the ECS normalization at index time (pure, additive).

`normalize(family, fields, record)` returns the `ecs` sub-document for one row, or
`{}` when nothing maps. It never invents a value: every field comes from a real
column or the EVTX `Payload` JSON.

The map lives in `src/nexus/data/schema/ecs_map.yaml`. Transforms are limited to
splitting a path into name/directory/extension, parsing `Hashes=` lists, and
lower-casing keyword copies.

ADDITIVE: `text`, the core envelope and every `fields.<tool column>` stay exactly
as they are; `ecs` is added beside them.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

_MAP_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "schema" / "ecs_map.yaml"
)


@lru_cache(maxsize=1)
def load_ecs_map() -> dict[str, Any]:
    """The parsed ECS map (empty when the file is missing/unreadable)."""
    try:
        import yaml

        doc = yaml.safe_load(_MAP_PATH.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 - a missing map must not break indexing
        return {}
    return doc if isinstance(doc, dict) else {}


def _set(doc: dict[str, Any], path: str, value: Any) -> None:
    """Set a dotted path, creating intermediate dicts. Empty/None is skipped.

    The map's destinations are written with the `ecs.` prefix (`ecs.process.name`)
    because that is how a query names them; the stored sub-document IS the part
    under `ecs`, so the leading `ecs.` is stripped here.
    """
    if value in (None, "", [], {}):
        return
    if path.startswith("ecs."):
        path = path[len("ecs."):]
    parts = path.split(".")
    node = doc
    for part in parts[:-1]:
        nxt = node.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            node[part] = nxt
        node = nxt
    node[parts[-1]] = value


def _parse_payload(payload: Any) -> dict[str, Any]:
    """`{EventData: {Data: [{"@Name": n, "#text": v}]}}` -> {name: value}."""
    if isinstance(payload, dict):
        data = payload
    else:
        raw = str(payload or "").strip()
        if not raw or not raw.startswith("{"):
            return {}
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return {}
    if not isinstance(data, dict):
        return {}
    ev = data.get("EventData")
    out: dict[str, Any] = {}
    if isinstance(ev, dict):
        items = ev.get("Data")
        if isinstance(items, dict):
            items = [items]
        for item in items or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("@Name") or "").strip()
            text = item.get("#text")
            if name and text not in (None, ""):
                out[name] = text
        # Some payloads carry a single @Name/#text at EventData level
        name = str(ev.get("@Name") or "").strip()
        if name and ev.get("#text") not in (None, ""):
            out[name] = ev.get("#text")
    return out


_HASH_SPLIT = re.compile(r"[=:]")


def _parse_hashes(value: Any) -> dict[str, str]:
    """`SHA1=..,MD5=..,SHA256=..` -> {sha1:.., md5:.., sha256:..} (lowercased)."""
    out: dict[str, str] = {}
    for chunk in re.split(r"[,\s]+", str(value or "").strip()):
        if "=" not in chunk:
            continue
        algo, _, h = chunk.partition("=")
        algo = algo.strip().lower()
        h = h.strip()
        if algo in {"md5", "sha1", "sha256"} and h:
            out[algo] = h.lower()
    return out


def _split_path(value: Any) -> dict[str, Any]:
    raw = str(value or "").strip()
    if not raw:
        return {}
    norm = raw.replace("/", "\\")
    idx = norm.rfind("\\")
    directory = norm[:idx] if idx >= 0 else ""
    name = norm[idx + 1:] if idx >= 0 else norm
    ext = ""
    if "." in name:
        ext = name.rsplit(".", 1)[1]
    return {"path": raw, "name": name, "directory": directory, "extension": ext}


def _split_pieces(path_doc: dict[str, Any], dst: str) -> dict[str, Any]:
    return {
        f"{dst}.path": path_doc.get("path"),
        f"{dst}.name": path_doc.get("name"),
        f"{dst}.directory": path_doc.get("directory"),
        f"{dst}.extension": path_doc.get("extension"),
    }


def normalize(
    family: str,
    fields: dict[str, Any] | None,
    record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """The `ecs` sub-document for one row (empty dict when nothing maps)."""
    emap = load_ecs_map()
    if not emap:
        return {}
    fam = str(family or "").strip().lower()
    fields = {str(k): v for k, v in (fields or {}).items()}
    record = record or {}
    ecs: dict[str, Any] = {}

    # 1. Every EVTX row: EventData -> ecs.winlog.event_data.<Name>, then the
    #    per-(channel, event) common fields from names the event carries.
    payload = fields.get("Payload")
    ev = _parse_payload(payload)
    if ev:
        for name, value in ev.items():
            # WO-CS1b item 1: an event_data value keeps up to 4,096 chars; a
            # PowerShell script block may keep up to 32 KB.
            limit = 32768 if name == "ScriptBlockText" else 4096
            _set(ecs, f"ecs.winlog.event_data.{name}", str(value)[:limit])
        event_id = str(fields.get("EventId") or fields.get("EventID") or "").strip()
        channel = str(
            fields.get("Channel") or fields.get("Provider")
            or fields.get("SourceName") or ""
        ).strip()
        # WO-CS1b item 2: the table is keyed by (channel or provider, event ID), so
        # Sysmon's "1"/"3"/"11" apply only to the Sysmon channel, Security's 4624
        # only to Security. The legacy event-id-only bucket is a fallback.
        winlog_table = emap.get("winlog_event_data") or {}
        per_event = (
            (winlog_table.get(channel) or {}).get(event_id)
            or winlog_table.get(event_id)
            or {}
        )
        for name, dst in per_event.items():
            if name in ev:
                _apply_mapped(ecs, dst, ev[name])

    # 2. Column -> ECS for this family, plus the importer slot table. The slots
    #    (process_name, command_line, file_path, ...) are uniquely named, so they
    #    are applied against `fields` whether the row came from an importer or a
    #    tool - the index projects them into `fields.*` either way.
    tables = emap.get("family_columns") or {}
    file_path_parts: list[str] = []
    for table_name in (fam, "ingest"):
        table = tables.get(table_name)
        if not isinstance(table, dict):
            continue
        for column, dst in table.items():
            if column not in fields:
                continue
            if dst == "ecs.file.path":
                # A path column is a PART here (ParentPath + FileName); collect and
                # join below so a single wildcard matches the full path.
                file_path_parts.append(str(fields[column]))
                continue
            _apply_mapped(ecs, dst, fields[column])
    if file_path_parts:
        joined = "\\".join(p.rstrip("\\/") for p in file_path_parts if p)
        if joined:
            _apply_mapped(ecs, "ecs.file.path", joined)

    # 2b. WO-CS1b item 3: Chainsaw's `Event Data` is `key: value` lines; Zircolite's
    #     detection rows carry EventData columns. Both become
    #     ecs.winlog.event_data.<Name>.
    if fam == "chainsaw":
        for name, value in _parse_chainsaw_event_data(fields.get("Event Data")).items():
            _set(ecs, f"ecs.winlog.event_data.{name}", str(value)[:4096])
    if fam == "zircolite":
        _zircolite_event_data(ecs, fields, record)

    # 3. Core envelope always present.
    for key, dst in (("family", "ecs.event.dataset"), ("host", "ecs.host.name"),
                     ("user", "ecs.user.name"), ("event_id", "ecs.event.code")):
        if fields.get(key):
            _set(ecs, dst, str(fields[key])[:512])
    for key, dst in (("host", "ecs.host.name"), ("user", "ecs.user.name")):
        if record.get(key):
            _set(ecs, dst, str(record[key])[:512])
    if record.get("artifact_type"):
        _set(ecs, "ecs.event.action", str(record["artifact_type"])[:512])

    return _flatten_hashes(ecs)


#: Targets whose value is a filesystem path and should be split into the
#: structured `ecs.file.*` fields. `ecs.process.executable` stays the full path
#: (the WO lists it as a scalar), and `ecs.registry.path` is not a filesystem path.
_PATH_TARGETS = frozenset({"ecs.file.path"})


def _apply_mapped(ecs: dict[str, Any], dst: str, value: Any) -> None:
    """One mapped value, with the limited transforms the WO allows.

    A path target is split into the structured ECS path fields (name/directory/
    extension); a hash target parses `Hashes=` lists; everything else is copied.
    `ecs.registry.path` is NOT path-split - a registry key is not a filesystem path.
    """
    if dst == "ecs.process.hash" or dst.endswith(".hash"):
        hashes = _parse_hashes(value)
        for algo, h in hashes.items():
            _set(ecs, f"{dst}.{algo}", h)
        return
    if dst in _PATH_TARGETS:
        pieces = _split_path(value)
        base = dst[: -len(".path")] if dst.endswith(".path") else dst
        for k, v in _split_pieces(pieces, base).items():
            _set(ecs, k, v)
        return
    _set(ecs, dst, str(value)[:4096])


def _parse_chainsaw_event_data(value: Any) -> dict[str, str]:
    """Chainsaw `Event Data` is `key: value` lines (one per line)."""
    out: dict[str, str] = {}
    for line in str(value or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip().strip("'\"")
        if key:
            out[key] = val
    return out


def _zircolite_event_data(ecs: dict[str, Any], fields: dict[str, Any],
                          record: dict[str, Any]) -> None:
    """Zircolite detection rows: EventData columns -> ecs.winlog.event_data.*.

    A Zircolite row is a rule match with a `matches` list; each match carries the
    event's own fields. Any field the row already holds that is not a rule column
    is treated as event data (the same rule Chainsaw's parser follows).
    """
    rule_cols = {"title", "id", "description", "sigmafile", "sigma", "rule_level",
                 "tags", "count", "matches"}
    matches = record.get("matches") if isinstance(record, dict) else None
    if isinstance(matches, list):
        for m in matches[:1]:
            if isinstance(m, dict):
                for k, v in m.items():
                    if v not in (None, "", [], {}):
                        _set(ecs, f"ecs.winlog.event_data.{k}", str(v)[:4096])
    for k, v in fields.items():
        if str(k).lower() in rule_cols or k in ("Event Data",):
            continue
        _set(ecs, f"ecs.winlog.event_data.{k}", str(v)[:4096])


def _flatten_hashes(ecs: dict[str, Any]) -> dict[str, Any]:
    """Convert `{...: {"hash": {...}}}` nothing - hashes are already flat dicts."""
    return ecs
