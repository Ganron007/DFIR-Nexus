"""Entity extraction service — WP 3.14.

Extracts structured entities (process names, IPs, users, hashes, paths,
domains, URLs, emails) from N4 hits. Unlike the examiner-question extractor
in mode1.py, this operates on hit records with parsed fields and produces
an entity graph with hit references — the foundation for cross-family
correlation and attack pattern detection.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Entity patterns — same base set as mode1.py plus forensic-specific types
# ---------------------------------------------------------------------------

_ENTITY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("sha256", re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("sha1", re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("md5", re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("url", re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("domain", re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b")),
    ("windows_path", re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|]+")),
    ("posix_path", re.compile(r"/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){2,}")),
    ("domain_user", re.compile(r"\b[A-Za-z][A-Za-z0-9._-]{1,31}\\[A-Za-z0-9._$-]{1,64}\b")),
    ("process_name", re.compile(r"\b[A-Za-z0-9_-]{3,64}\.exe\b", re.IGNORECASE)),
    ("service_name", re.compile(r"\b[A-Za-z][A-Za-z0-9_-]{2,63}\b(?=\s+(?:service|svc|daemon))", re.IGNORECASE)),
]

_ENTITY_TRAILING = ").,;:!?]}>'\""

# Fields that are likely to contain entity values, keyed by entity type.
# Maps field names (lowercase) to entity types they typically contain.
_FIELD_ENTITY_MAP: dict[str, str] = {
    "image": "process_name",
    "process_name": "process_name",
    "processname": "process_name",
    "executable": "process_name",
    "commandline": "windows_path",
    "command_line": "windows_path",
    "command": "windows_path",
    "file_path": "windows_path",
    "filepath": "windows_path",
    "path": "windows_path",
    "targetfilename": "windows_path",
    "target_filename": "windows_path",
    "sourceip": "ipv4",
    "source_ip": "ipv4",
    "destinationip": "ipv4",
    "destination_ip": "ipv4",
    "dest_ip": "ipv4",
    "src_ip": "ipv4",
    "ip": "ipv4",
    "username": "domain_user",
    "user": "domain_user",
    "account": "domain_user",
    "targetusername": "domain_user",
    "target_username": "domain_user",
    "subjectusername": "domain_user",
    "subject_username": "domain_user",
    "hash": "sha256",
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "imphash": "sha256",
    "url": "url",
    "uri": "url",
    "domain": "domain",
    "hostname": "domain",
    "computername": "domain",
    "computer": "domain",
    "workstation": "domain",
}


def _extract_from_text(text: str) -> dict[str, list[str]]:
    """Extract entities from raw text using regex patterns."""
    text = text or ""
    out: dict[str, list[str]] = {}
    seen: set[str] = set()
    for kind, rx in _ENTITY_PATTERNS:
        for raw in rx.findall(text):
            value = str(raw).rstrip(_ENTITY_TRAILING)
            key = value.lower()
            if not value or key in seen:
                continue
            seen.add(key)
            out.setdefault(kind, []).append(value)
    return out


def _extract_from_fields(fields: dict[str, str]) -> dict[str, list[str]]:
    """Extract entities from parsed CSV fields using the field map."""
    out: dict[str, list[str]] = {}
    for field_name, value in fields.items():
        if not value or not isinstance(value, str):
            continue
        entity_type = _FIELD_ENTITY_MAP.get(field_name.lower())
        if entity_type:
            value = value.strip().rstrip(_ENTITY_TRAILING)
            if value:
                out.setdefault(entity_type, []).append(value)
    return out


def extract_entities(hits: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Extract a structured entity graph from N4 hits.

    Args:
        hits: list of N4 hit dicts, each with:
            - family: evidence family name
            - text: raw hit text
            - fields: parsed CSV fields (optional, from attach_hit_fields)
            - file: relative path to source file
            - line: line number
            - ts: timestamp (optional)
            - host: hostname (optional)
            - audit_id: parser run audit ID (optional)

    Returns:
        dict mapping entity_type -> list of entity records:
        {
            "process_name": [
                {"value": "powershell.exe", "hits": [hit_ref, ...], "families": ["hayabusa", "evtxecmd"]},
                ...
            ],
            "ipv4": [
                {"value": "10.0.0.5", "hits": [hit_ref, ...], "families": ["evtx", "netstat"]},
                ...
            ],
            ...
        }

        Each hit_ref is: {"family": str, "file": str, "line": str, "audit_id": str}
    """
    entities: dict[str, dict[str, dict[str, Any]]] = {}

    for hit in hits:
        family = str(hit.get("family") or "")
        hit_ref = {
            "family": family,
            "file": str(hit.get("file") or ""),
            "line": str(hit.get("line") or ""),
            "audit_id": str(hit.get("audit_id") or ""),
            "ts": str(hit.get("ts") or ""),
            "host": str(hit.get("host") or ""),
        }

        # Extract from parsed fields first (higher confidence)
        fields = hit.get("fields")
        if isinstance(fields, dict):
            for entity_type, values in _extract_from_fields(fields).items():
                for value in values:
                    key = value.lower()
                    if key not in entities.get(entity_type, {}):
                        entities.setdefault(entity_type, {})[key] = {
                            "value": value,
                            "hits": [],
                            "families": set(),
                        }
                    ent = entities[entity_type][key]
                    ent["hits"].append(hit_ref)
                    ent["families"].add(family)

        # Extract from raw text (fallback + additional entities)
        text = str(hit.get("text") or "")
        for entity_type, values in _extract_from_text(text).items():
            for value in values:
                key = value.lower()
                if key not in entities.get(entity_type, {}):
                    entities.setdefault(entity_type, {})[key] = {
                        "value": value,
                        "hits": [],
                        "families": set(),
                    }
                ent = entities[entity_type][key]
                # Don't duplicate the same hit for the same entity
                if not any(h["line"] == hit_ref["line"] and h["file"] == hit_ref["file"] for h in ent["hits"]):
                    ent["hits"].append(hit_ref)
                    ent["families"].add(family)

    # Convert sets to sorted lists and dicts to lists
    result: dict[str, list[dict[str, Any]]] = {}
    for entity_type, entity_map in entities.items():
        result[entity_type] = [
            {
                "value": ent["value"],
                "hits": ent["hits"],
                "families": sorted(ent["families"]),
            }
            for ent in entity_map.values()
        ]
    return result


def entities_to_dict(entities: dict[str, list[dict[str, Any]]]) -> dict[str, list[str]]:
    """Flatten entity graph to a simple dict of entity_type -> [values]."""
    return {
        entity_type: [e["value"] for e in entity_list]
        for entity_type, entity_list in entities.items()
    }
