"""WO-KR2 — stored knowledge query validator.

Every stored knowledge query (analytics in `behavioral_analytics.yaml` and skill
steps in `skills/*.yaml`) lives in an `es:` field as ES query JSON.

This module validates that every stored query:
(a) passes `langgraph.es_native.validate_query` — allowlisted clauses only;
(b) references only fields that exist in `src/nexus/data/schema/field_registry.yaml`
    for the item's declared `requires.families` — paths `fields.<Name>` /
    `fields.<Name>.kw`, plus envelope fields `family`, `ts`, `text`, `host`, `file`;
(c) has a citation.

An item that fails is NOT loaded, and the failure is reported. A failing item is
never silently skipped.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from nexus.langgraph.es_native import ESQueryError, validate_query

log = logging.getLogger(__name__)


class StoredQueryValidationError(ValueError):
    """Raised when a stored knowledge query fails validation."""


FIELD_REGISTRY_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "schema"
    / "field_registry.yaml"
)

# Core envelope fields always available on every case document.
CORE_ENVELOPE_FIELDS = frozenset({
    "family",
    "ts",
    "text",
    "text.wc",
    "host",
    "file",
    "line",
    "user",
    "event_id",
    "case_id",
})

# Family aliases / expansions mapping generic family names to tool & ingest families.
FAMILY_EXPANSIONS: dict[str, set[str]] = {
    "evtx": {
        "evtx", "evtxecmd", "hayabusa", "ingest-hayabusa", "chainsaw",
        "zircolite", "deepbluecli", "ingest-kape", "security", "system",
        "sysmon", "powershell",
    },
    "evtxecmd": {
        "evtx", "evtxecmd", "hayabusa", "ingest-hayabusa", "chainsaw",
        "zircolite", "deepbluecli", "ingest-kape", "security", "system",
        "sysmon", "powershell",
    },
    "hayabusa": {
        "evtx", "evtxecmd", "hayabusa", "ingest-hayabusa", "chainsaw",
        "zircolite", "deepbluecli", "ingest-kape", "security", "system",
        "sysmon",
    },
    "security": {
        "security", "evtx", "evtxecmd", "hayabusa", "ingest-hayabusa",
        "chainsaw", "zircolite", "deepbluecli", "ingest-kape",
    },
    "system": {
        "system", "evtx", "evtxecmd", "hayabusa", "ingest-hayabusa", "ingest-kape",
    },
    "sysmon": {
        "sysmon", "evtx", "evtxecmd", "hayabusa", "ingest-hayabusa", "ingest-kape",
    },
    "prefetch": {"prefetch", "pecmd", "ingest-kape"},
    "pecmd": {"prefetch", "pecmd", "ingest-kape"},
    "amcache": {"amcache", "ingest-amcache", "ingest-kape"},
    "mft": {"mft", "mftecmd", "mftecmd-i30", "mftecmd-usn", "fls", "ingest-kape", "ntfs"},
    "mftecmd": {"mft", "mftecmd", "mftecmd-i30", "mftecmd-usn", "fls", "ingest-kape", "ntfs"},
    "ntfs": {"ntfs", "mft", "mftecmd", "mftecmd-i30", "mftecmd-usn", "fls", "ingest-kape"},
    "registry": {"registry", "recmd", "ingest-windows_registry", "ingest-kape", "ntuser"},
    "recmd": {"registry", "recmd", "ingest-windows_registry", "ingest-kape", "ntuser"},
    "ntuser": {"ntuser", "registry", "recmd", "ingest-windows_registry"},
    "lnk": {"lnk", "lecmd", "ingest-kape"},
    "lecmd": {"lnk", "lecmd", "ingest-kape"},
    "jumplist": {"jumplist", "jlecmd", "ingest-kape"},
    "jlecmd": {"jumplist", "jlecmd", "ingest-kape"},
    "shellbags": {"shellbags", "sbecmd", "ingest-kape"},
    "sbecmd": {"shellbags", "sbecmd", "ingest-kape"},
    "srum": {"srum", "srumecmd", "ingest-kape"},
    "srumecmd": {"srum", "srumecmd", "ingest-kape"},
    "tasks": {"tasks", "ingest-scheduled_tasks", "ingest-kape"},
    "services": {"services", "ingest-windows_services", "ingest-kape"},
    "wmi": {"wmi", "ingest-scheduled_tasks", "ingest-windows_services"},
    "memory": {"memory", "vol", "ingest-volatility"},
    "vol": {"memory", "vol", "ingest-volatility"},
    "volatility": {"memory", "vol", "ingest-volatility"},
    "pcap": {"pcap", "tshark-flows", "nfdump", "ingest-zeek", "ingest-suricata", "ingest-wireshark"},
    "network": {"network", "tshark-flows", "nfdump", "ingest-zeek", "ingest-suricata", "ingest-wireshark"},
    "powershell": {"powershell", "evtx", "evtxecmd", "hayabusa", "ingest-hayabusa"},
    "browser": {"browser", "hindsight", "ingest-kape"},
    "usb": {"usb", "usbdeview", "ingest-kape"},
}

_CACHED_REGISTRY: dict[str, Any] | None = None


def load_field_registry(path: Path | str | None = None) -> dict[str, Any]:
    """Load the field registry column mapping."""
    global _CACHED_REGISTRY
    target = Path(path) if path else FIELD_REGISTRY_PATH
    if _CACHED_REGISTRY is not None and not path:
        return _CACHED_REGISTRY
    if not target.is_file():
        return {}
    try:
        import yaml

        data = yaml.safe_load(target.read_text(encoding="utf-8")) or {}
        cols = data.get("columns") or {}
        if not path:
            _CACHED_REGISTRY = cols if isinstance(cols, dict) else {}
        return cols if isinstance(cols, dict) else {}
    except Exception as exc:  # noqa: BLE001
        log.warning("field registry unreadable: %s", exc)
        return {}


def expand_families(families: Iterable[str]) -> set[str]:
    """Expand family names with known tool aliases and ingest prefixes."""
    expanded: set[str] = set()
    for f in families:
        low = str(f).strip().lower()
        if not low:
            continue
        expanded.add(low)
        expanded.add(f"ingest-{low}")
        if low.startswith("ingest-"):
            expanded.add(low[7:])
        if low in FAMILY_EXPANSIONS:
            expanded |= FAMILY_EXPANSIONS[low]
    return expanded


def extract_es_fields(query: Any) -> set[str]:
    """Extract all field paths referenced in an ES query object."""
    fields: set[str] = set()
    if not isinstance(query, dict):
        return fields
    for k, v in query.items():
        if k in ("term", "match", "match_phrase", "prefix", "wildcard", "terms", "range"):
            if isinstance(v, dict):
                for f in v:
                    fields.add(str(f))
        elif k == "exists":
            if isinstance(v, dict) and "field" in v:
                fields.add(str(v["field"]))
        elif k == "multi_match":
            if isinstance(v, dict) and "fields" in v:
                for f in v["fields"]:
                    fields.add(str(f))
        elif k == "bool" and isinstance(v, dict):
            for bkey in ("must", "should", "must_not", "filter"):
                sub = v.get(bkey)
                if isinstance(sub, list):
                    for item in sub:
                        fields |= extract_es_fields(item)
                elif isinstance(sub, dict):
                    fields |= extract_es_fields(sub)
    return fields


def validate_stored_query(
    es: Any,
    declared_families: Iterable[str] | None = None,
    citation: Any = None,
    registry_columns: dict[str, Any] | None = None,
) -> list[str]:
    """Validate a stored knowledge query against criteria (a), (b), (c).

    Returns a list of error strings. Empty list indicates full validity.
    """
    problems: list[str] = []

    # Format check: must be a dictionary (ES query JSON object)
    if not isinstance(es, dict) or not es:
        problems.append(
            f"query must be an ES query JSON object (dict), got {type(es).__name__}"
        )
        return problems

    # (a) Pass es_native.validate_query (allowlisted clauses only)
    try:
        validate_query(es)
    except ESQueryError as exc:
        problems.append(f"clause validation failed: {exc}")

    # (b) References only fields in field_registry.yaml for declared families
    cols = registry_columns if registry_columns is not None else load_field_registry()
    cols_norm: dict[str, dict[str, Any]] = {
        name.lower().replace("_", "").replace("-", "").replace(" ", ""): info
        for name, info in cols.items()
        if isinstance(info, dict)
    }

    fams_expanded = (
        expand_families(declared_families)
        if declared_families is not None
        else set()
    )

    referenced = extract_es_fields(es)
    for field_path in referenced:
        if field_path in CORE_ENVELOPE_FIELDS:
            continue
        if not field_path.startswith("fields."):
            problems.append(
                f"unsupported non-envelope field {field_path!r} — must be envelope "
                "(family, ts, text, host, file) or start with 'fields.'"
            )
            continue

        raw_col = field_path[7:]  # strip 'fields.'
        if raw_col.endswith(".kw"):
            raw_col = raw_col[:-3]

        norm_col = raw_col.lower().replace("_", "").replace("-", "").replace(" ", "")
        if raw_col in cols:
            col_info = cols[raw_col]
        elif norm_col in cols_norm:
            col_info = cols_norm[norm_col]
        else:
            problems.append(
                f"field {field_path!r} refers to column {raw_col!r} not in field registry"
            )
            continue

        # If families were declared, check intersection
        if fams_expanded:
            col_fams = {
                str(f).lower() for f in (col_info.get("families") or [])
            }
            if not (col_fams & fams_expanded):
                problems.append(
                    f"field {field_path!r} (column {raw_col!r}) does not exist for declared "
                    f"families {sorted(fams_expanded)} (column exists for {sorted(col_fams)})"
                )

    # (c) Has a citation
    if citation is None:
        problems.append("missing citation")
    elif isinstance(citation, dict):
        cid = (
            citation.get("id")
            or citation.get("source")
            or citation.get("chunk_id")
            or citation.get("type")
        )
        if not cid:
            problems.append("citation mapping has no identifier (id/source/chunk_id)")
    elif isinstance(citation, list):
        if not citation:
            problems.append("citation list is empty")
    elif isinstance(citation, str):
        if not citation.strip():
            problems.append("citation string is empty")
    else:
        problems.append(f"invalid citation type: {type(citation).__name__}")

    return problems
