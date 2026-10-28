"""What an evidence value is, by the field that holds it: the one owner (D455, Part 12 FM-2/FM-7).

Evidence values are typed by field meaning: the index envelope's ``host`` and ``user`` (set at index time from each
family's declared columns, D287) and the ECS fields ``data/schema/ecs_map.yaml`` writes (WO-CS1). A value is never
typed by the shape of a string. On T22 (one memory image, 1,737,335 rows, 2026-10-28) pattern sweeps of every row
took WinSxS catalog names, installer component IDs, PDB GUIDs, version numbers and browsing history for 8,337 IOCs,
and 1,416 "processes", 5,197 "paths" and 2,603 "users" (``0``, ``0x0``, ``Author``, hex addresses) for the entity
inventory; the typed fields hold 4 hosts, 30 users, 73 process names and one public address. Examiner-written text,
which has no fields, is typed by ``ti_context.extract_iocs``.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from typing import Any

#: Entities by the field that holds them. ``host`` and ``user`` are the envelope every indexed row carries; the
#: process fields are ECS. Paths and command lines are queried, not listed: a disk image holds millions of them.
ENTITY_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("host", ("host",)),
    ("user", ("user",)),
    ("process", ("ecs.process.name",)),
    ("executable", ("ecs.process.executable",)),
    ("parent_process", ("ecs.process.parent.name", "ecs.process.parent.executable")),
)

#: Observables (threat-intel lookups, the inventory's network and hashes). A path matches by its tail
#: (``process.hash.sha256``, ``file.hash.md5``); ``winlog.event_data.*`` is the event's own raw data, typed only
#: through the map's per-event copies. The TI router types an address as IPv4 only.
OBSERVABLE_FIELDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sha256", ("hash.sha256",)),
    ("sha1", ("hash.sha1",)),
    ("md5", ("hash.md5",)),
    ("ipv4", ("destination.ip", "source.ip")),
    ("domain", ("dns.question.name", "destination.domain", "url.domain")),
    ("url", ("url.full",)),
)
OBSERVABLE_KINDS = tuple(kind for kind, _ in OBSERVABLE_FIELDS)
NETWORK_KINDS = ("ipv4", "domain", "url")
HASH_KINDS = ("sha256", "sha1", "md5")
_HASH_LENGTHS = {"sha256": 64, "sha1": 40, "md5": 32}
_HEX_RE = re.compile(r"[0-9a-f]+")
_PAGE = 1000


def is_private_ip(value: str) -> bool:
    """True for an address that is not a public one (or not an address)."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved


def observable_kind(path: str) -> str | None:
    """The observable kind an ECS field path means, or None."""
    path = path[len("ecs."):] if path.startswith("ecs.") else path
    if path.startswith("winlog."):
        return None
    for kind, tails in OBSERVABLE_FIELDS:
        if any(path == tail or path.endswith("." + tail) for tail in tails):
            return kind
    return None


def typed_value(kind: str, value: Any) -> str:
    """The value as the observable its field names, or "" when it is not one (a placeholder, a private address,
    a hash of the wrong length)."""
    text = str(value or "").strip()
    if kind in _HASH_LENGTHS:
        text = text.lower()
        return text if len(text) == _HASH_LENGTHS[kind] and _HEX_RE.fullmatch(text) else ""
    if kind == "ipv4":
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return ""
        return text if address.version == 4 and not is_private_ip(text) else ""
    if kind == "domain":
        text = text.lower().strip(".")
        return text if "." in text and " " not in text else ""
    if kind == "url":
        return text if re.match(r"https?://", text, re.IGNORECASE) else ""
    return ""


def observables_from_ecs(ecs: Any, prefix: str = "") -> dict[str, set[str]]:
    """Every observable one stored ``ecs`` sub-document holds, by field meaning."""
    found: dict[str, set[str]] = {kind: set() for kind in OBSERVABLE_KINDS}
    if not isinstance(ecs, dict):
        return found
    for key, value in ecs.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            for kind, values in observables_from_ecs(value, path).items():
                found[kind] |= values
            continue
        kind = observable_kind(path)
        if kind is None:
            continue
        for item in value if isinstance(value, list) else [value]:
            typed = typed_value(kind, item)
            if typed:
                found[kind].add(typed)
    return found


def _post(case_id: str, body: dict[str, Any]) -> dict[str, Any]:
    from nexus.langgraph.case_index import _client, index_name

    with _client() as client:
        response = client.post(f"/{index_name(case_id)}/_search", json=body)
    if response.status_code >= 400:
        raise RuntimeError(f"typed-field search failed: {response.status_code} {response.text[:300]}")
    return response.json()


def iter_sources(case_id: str, query: dict[str, Any], source: list[str]) -> Iterable[dict[str, Any]]:
    """Every matching stored document of the case's index, with its ``_id``; a failed request raises."""
    search_after: list[Any] | None = None
    while True:
        body: dict[str, Any] = {"size": _PAGE, "query": query, "_source": source,
                                "sort": ["_doc"], "track_total_hits": False}
        if search_after:
            body["search_after"] = search_after
        page = _post(case_id, body).get("hits", {}).get("hits", [])
        for hit in page:
            yield {**(hit.get("_source") or {}), "_id": str(hit.get("_id") or "")}
        if len(page) < _PAGE:
            return
        search_after = page[-1].get("sort")
        if not search_after:
            raise RuntimeError("typed-field search page omitted its search_after cursor")


def _field_value_counts(case_id: str, field: str, query: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Every distinct value of one keyword field with its row count, families and a source file (exact, paged)."""
    after: dict[str, Any] | None = None
    while True:
        composite: dict[str, Any] = {"size": _PAGE, "sources": [{"value": {"terms": {"field": field}}}]}
        if after:
            composite["after"] = after
        body = {"size": 0, "query": query, "aggs": {"values": {
            "composite": composite,
            "aggs": {"families": {"terms": {"field": "family", "size": 20}},
                     "files": {"terms": {"field": "file", "size": 1}}},
        }}}
        agg = _post(case_id, body).get("aggregations", {}).get("values", {})
        for bucket in agg.get("buckets") or []:
            yield {"value": str(bucket["key"]["value"]), "count": int(bucket.get("doc_count") or 0),
                   "families": [str(b["key"]) for b in bucket.get("families", {}).get("buckets") or []],
                   "source_file": next((str(b["key"]) for b in bucket.get("files", {}).get("buckets") or []), "")}
        after = agg.get("after_key")
        if not after or not agg.get("buckets"):
            return


def _merged(case_id: str, fields: list[str], query: dict[str, Any], kind: str = "") -> list[dict[str, Any]]:
    """The values of one kind across its fields, merged by value, by row count then value."""
    merged: dict[str, dict[str, Any]] = {}
    for field in fields:
        for item in _field_value_counts(case_id, field, query):
            value = typed_value(kind, item["value"]) if kind else item["value"].strip()
            if not value:
                continue
            entry = merged.setdefault(value, {"value": value, "count": 0, "families": [], "source_file": ""})
            entry["count"] += item["count"]
            entry["families"] += [f for f in item["families"] if f not in entry["families"]]
            entry["source_file"] = entry["source_file"] or item["source_file"]
    return sorted(merged.values(), key=lambda e: (-e["count"], e["value"].lower()))


def typed_fields(case_id: str) -> dict[str, list[str]]:
    """Each entity and observable kind -> the typed fields of this case's index that hold it."""
    from nexus.langgraph import es_native as es

    keyword = {field for field, kind in es._field_types(case_id).items() if kind in ("keyword", "ip", "wildcard")}
    out = {kind: [f for f in fields if f in keyword] for kind, fields in ENTITY_FIELDS}
    for kind in OBSERVABLE_KINDS:
        out[kind] = [f for f in sorted(keyword) if observable_kind(f) == kind]
    return out


def case_entities(case_id: str, query: dict[str, Any] | None = None) -> dict[str, Any]:
    """Every typed entity and observable of the case (or of the rows ``query`` matches), with row counts."""
    query = query or {"match_all": {}}
    fields = typed_fields(case_id)
    out: dict[str, Any] = {"source": "typed index fields: the envelope host and user, ECS process, address, "
                                     "DNS, URL and hash fields", "fields": fields}
    for kind, present in fields.items():
        out[kind] = _merged(case_id, present, query, kind if kind in OBSERVABLE_KINDS else "")
    return out
