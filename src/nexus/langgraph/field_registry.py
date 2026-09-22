"""Schema v5 — shipped field registry (generated from the validated tool-run catalog).

``src/nexus/data/schema/field_registry.yaml`` is produced by
``scripts/build_field_registry.py`` from ``Evidence-files/ES-Mapping/es_mappings``
(every validated tool-run mapping). The case index uses it to emit **explicit
typed** ``fields.<Column>`` properties instead of relying on dynamic mapping,
so numeric/date push-down works and malformed values degrade safely.

Override the registry path with ``NEXUS_FIELD_REGISTRY`` (tests / custom packs).
"""
from __future__ import annotations

import logging
import os
from functools import lru_cache
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

_DEFAULT_PATH = Path(__file__).resolve().parents[1] / "data" / "schema" / "field_registry.yaml"

# Every typed date column shares one format list: lane outputs are ISO, but the
# tool CSVs also carry "yyyy-MM-dd HH:mm:ss" (SRUM/mactime), US-format dates
# (plaso l2tcsv) and epoch millis (vol).
DATE_FORMATS = (
    "strict_date_optional_time||epoch_millis||yyyy-MM-dd HH:mm:ss"
    "||MM/dd/yyyy HH:mm:ss||yyyy/MM/dd HH:mm:ss"
)

_EMPTY: dict = {"version": 0, "columns": {}, "families": {}, "conflicts": []}


def registry_path() -> Path:
    override = (os.environ.get("NEXUS_FIELD_REGISTRY") or "").strip()
    return Path(override) if override else _DEFAULT_PATH


@lru_cache(maxsize=4)
def _load(path: str) -> dict:
    p = Path(path)
    if not p.is_file():
        log.warning("field registry missing: %s (schema v5 falls back to dynamic mapping)", p)
        return dict(_EMPTY)
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        log.warning("field registry unreadable (%s): %s", p, exc)
        return dict(_EMPTY)
    if not isinstance(doc, dict):
        return dict(_EMPTY)
    return doc


def load_field_registry() -> dict:
    """Whole registry document (cached per path)."""
    return _load(str(registry_path()))


def merged_columns() -> dict[str, dict]:
    """Column name (exact case as indexed) -> ``{"type", "families"}``."""
    cols = load_field_registry().get("columns") or {}
    return {str(k): dict(v or {}) for k, v in cols.items()}


def es_property(spec: dict) -> dict:
    """One registry column -> ES property definition."""
    t = str((spec or {}).get("type") or "text").lower()
    if t == "long":
        return {"type": "long"}
    if t == "double":
        return {"type": "double"}
    if t == "boolean":
        return {"type": "boolean"}
    if t == "date":
        return {"type": "date", "format": DATE_FORMATS}
    if t == "keyword":
        return {"type": "keyword", "ignore_above": 1024}
    # text (also keyword+text conflicts): searchable with a keyword subfield so
    # exact DSL operators (in/eq) keep working.
    return {"type": "text", "fields": {"kw": {"type": "keyword", "ignore_above": 1024}}}


def field_properties() -> dict[str, dict]:
    """The explicit ``fields.*`` property map for the case index mapping."""
    return {name: es_property(spec) for name, spec in merged_columns().items()}


def registry_summary() -> dict:
    """Small honest summary for doctor/Briefing surfaces."""
    doc = load_field_registry()
    counts = doc.get("counts") or {}
    return {
        "version": int(doc.get("version") or 0),
        "families": int(counts.get("families") or len(doc.get("families") or {})),
        "columns": int(counts.get("columns") or len(doc.get("columns") or {})),
        "conflicts": int(counts.get("conflicts") or len(doc.get("conflicts") or [])),
        "generated": str(doc.get("generated") or ""),
    }
