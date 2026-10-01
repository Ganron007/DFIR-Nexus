"""Timeline events on Elasticsearch (WO-A10 / T1-4, WPs 8.5 / 10.5 / 10.6).

A timeline today is a viewer over buckets. This module makes it queryable: one
event per timestamp column per row, in a per-case ``-events`` index, built from
the document index that already holds every row.

Three decisions this file exists to enforce:

* **MACB expansion.** A row with four timestamps (MFT created / modified /
  record-changed / accessed) is *four* events. Collapsing them loses the
  "written then changed within a second" pattern that is most of the value.
* **Content-derived ids.** ``event_id`` is a hash of file + record + column, so
  the same evidence indexed twice produces the same ids: a re-index is a no-op
  for anything downstream that stored them, and a duplicated bulk is detectable
  instead of invisible.
* **Never re-parse evidence.** The source is the index; the reader is the
  shared one (WO-17/22). An unknown family produces *no* events and is reported
  as skipped - silence would read as "no activity".
"""
from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

TIMELINE_SCHEMA_VERSION = 1
EVENTS_SUFFIX = "-events"

#: Families this slice writes events for. Explicit, so "why is prefetch missing
#: from my timeline" has an answer instead of a shrug. Extended in Tier 2.
SUPPORTED_FAMILIES = ("evtx", "mftecmd", "mftecmd-i30", "tasks", "wxtcmd")

_STATE_FILENAME = "timeline_events.json"


def events_index_name(case_id: str) -> str:
    """The per-case events index. Never shared across cases (isolation is the
    property R17-R19 proved)."""
    from nexus.langgraph.case_index import index_name

    return f"{index_name(case_id)}{EVENTS_SUFFIX}"


def _state_path(case_dir: Path) -> Path:
    return Path(case_dir) / "analysis" / _STATE_FILENAME


def read_events_state(case_dir: Path | str) -> dict[str, Any]:
    path = _state_path(case_dir)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def write_events_state(case_dir: Path | str, state: dict[str, Any]) -> Path:
    path = _state_path(case_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# expansion
# --------------------------------------------------------------------------

def date_columns_for(family: str) -> set[str]:
    """The date-typed columns a family can carry, from the field registry."""
    from nexus.langgraph.field_registry import merged_columns

    registry = merged_columns()
    families = (family or "").lower()
    out: set[str] = set()
    for name, spec in registry.items():
        if str(spec.get("type") or "").lower() != "date":
            continue
        fams = {str(f).lower() for f in (spec.get("families") or [])}
        if families in fams or not fams:
            out.add(name)
    return out


def event_id_for(source_file: str, record_key: str, ts_desc: str) -> str:
    """Content-derived and stable - the property that makes re-indexing safe."""
    raw = "\x1f".join((str(source_file), str(record_key), str(ts_desc)))
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:32]


def _record_key(doc: dict[str, Any]) -> str:
    """Identity of the source row: family + file + line (WO-17 record lines)."""
    return ":".join(
        str(doc.get(part) or "")
        for part in ("family", "file", "line")
    )


def _parse_ts(value: Any) -> datetime | None:
    if value in (None, "", "N/A"):
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    from nexus.langgraph.timestamps import parse_time_value  # the one authority

    parsed = parse_time_value(str(value))
    if not parsed:
        return None
    dt = parsed.get("dt")
    if not isinstance(dt, datetime):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def expand_doc(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """One event per timestamp column in this row (MACB).

    The row's own ingest timestamp (``ts``) is the primary event when it is a
    real event time; a synthesized one is included with its flag carried, never
    silently promoted.
    """
    family = str(doc.get("family") or "").lower()
    if family not in SUPPORTED_FAMILIES:
        return []
    source_file = str(doc.get("file") or "")
    record_key = _record_key(doc)
    fields = doc.get("fields") or {}
    if not isinstance(fields, dict):
        fields = {}

    date_columns = date_columns_for(family)
    events: list[dict[str, Any]] = []

    def emit(ts_desc: str, raw: Any, ts_src: str, precision: str) -> None:
        parsed = _parse_ts(raw)
        if parsed is None:
            return
        events.append({
            "event_id": event_id_for(source_file, record_key, ts_desc),
            "ts": parsed.isoformat(),
            "ts_raw": str(raw)[:64],
            "ts_src": ts_src,
            "ts_precision": precision,
            "ts_desc": ts_desc,
            "host": str(doc.get("host") or "")[:120],
            "user": str(doc.get("user") or "")[:120],
            "family": family,
            "artifact": Path(source_file).name,
            "event_type": "",
            "fields": {
                k: v for k, v in fields.items()
                if k != ts_desc and v not in (None, "")
            },
            "source_file": source_file,
            "source_line": doc.get("line"),
            "audit_id": str(doc.get("audit_id") or "")[:64],
            "finding_ids": [],
            # design review §5 #6: reserved, never populated by a guess
            "host_clock_skew": None,
        })

    for column, value in fields.items():
        if column in date_columns:
            emit(column, value, "column", "millisecond")
        elif _looks_like_date_column(column):
            # Not registry-typed. Kept - a timestamp the registry forgot is
            # still evidence - but marked, so a column that merely looks like
            # a date is distinguishable from one the registry vouches for.
            emit(column, value, "column-heuristic", "millisecond")

    # the row's own timestamp, when the index resolved a real one
    if str(doc.get("ts_src") or "") != "synthesized":
        emit("ingest", doc.get("ts_raw") or doc.get("ts"), str(doc.get("ts_src") or "event"),
             str(doc.get("ts_precision") or "second"))
    return events


def _looks_like_date_column(name: str) -> bool:
    lowered = str(name).lower()
    return (
        lowered.endswith("date")
        or lowered.startswith("timecreated")
        or lowered.endswith("time")
        or "modified" in lowered
        or lowered.startswith("created")
    )


def iter_events(case_dir: Path | str) -> Iterator[dict[str, Any]]:
    """Stream every event for a case from the existing document index."""
    from nexus.langgraph.case_index import iter_index_docs

    for doc in iter_index_docs(Path(case_dir)):
        yield from expand_doc(doc)


# --------------------------------------------------------------------------
# the index
# --------------------------------------------------------------------------

EVENTS_MAPPING: dict[str, Any] = {
    "properties": {
        "event_id": {"type": "keyword"},
        "ts": {"type": "date"},
        "ts_raw": {"type": "keyword"},
        "ts_src": {"type": "keyword"},
        "ts_precision": {"type": "keyword"},
        "ts_desc": {"type": "keyword"},
        "host": {"type": "keyword"},
        "user": {"type": "keyword"},
        "family": {"type": "keyword"},
        "artifact": {"type": "keyword"},
        "event_type": {"type": "keyword"},
        "source_file": {"type": "keyword"},
        "source_line": {"type": "long"},
        "audit_id": {"type": "keyword"},
        "finding_ids": {"type": "keyword"},
        "host_clock_skew": {"type": "long"},
        "fields": {"type": "object", "dynamic": True},
    }
}


def ensure_events_index(case_id: str) -> str:
    """Create the events index if needed; returns its name."""
    from nexus.langgraph.case_index import _client

    name = events_index_name(case_id)
    body = {
        "settings": {"index": {"mapping": {"total_fields": {"limit": 2000}}}},
        "mappings": EVENTS_MAPPING,
    }
    with _client() as client:
        if client.head(f"/{name}").status_code == 200:
            return name
        response = client.put(f"/{name}", json=body)
        response.raise_for_status()
    return name


def needs_rebuild(case_dir: Path | str) -> bool:
    """True when the index is absent, older than the schema, or never built."""
    state = read_events_state(case_dir)
    return int(state.get("schema_version") or 0) != TIMELINE_SCHEMA_VERSION


def build_events(
    case_dir: Path | str,
    *,
    chunk: int = 2000,
    force: bool = False,
) -> dict[str, Any]:
    """Build (or rebuild) the events index for one case.

    Read-only on evidence: the only writes are the events index and the case's
    ``analysis/timeline_events.json`` state.
    """
    case_dir = Path(case_dir)
    case_id = case_dir.name

    if not force and not needs_rebuild(case_dir):
        state = read_events_state(case_dir)
        return {
            "case_id": case_id,
            "built": False,
            "reason": f"schema v{state.get('schema_version')} already built",
            **state,
        }

    skipped: dict[str, int] = {}
    total = 0
    try:
        index = ensure_events_index(case_id)
    except Exception as exc:  # noqa: BLE001 - ES down is a state, not a crash
        # Deliberately NOT stamped with the current schema version: a failed
        # build must stay rebuildable, or a case whose Elasticsearch was down
        # at build time would report "already built" forever and never get
        # its timeline once the backend came back.
        state = {
            "schema_version": 0,
            "case_id": case_id,
            "error": f"elasticsearch unavailable: {str(exc)[:200]}",
            "events": total,
        }
        write_events_state(case_dir, state)
        return {"case_id": case_id, "built": False, "reason": state["error"], **state}

    from nexus.langgraph.case_index import _bulk_insert, _client

    pending: list[dict[str, Any]] = []
    errors = 0

    def flush() -> None:
        nonlocal pending, errors, total
        if not pending:
            return
        with _client() as client:
            errors += _bulk_insert(client, index, pending, chunk=chunk)
        total += len(pending)
        pending = []

    for doc in _index_doc_stream(case_dir, skipped):
        pending.extend(expand_doc(doc))
        if len(pending) >= chunk:
            flush()
    flush()

    state = {
        "schema_version": TIMELINE_SCHEMA_VERSION,
        "case_id": case_id,
        "index": index,
        "built_at": datetime.now(UTC).isoformat(),
        "events": total,
        "errors": errors,
        "events_skipped": skipped,
        "supported_families": list(SUPPORTED_FAMILIES),
    }
    write_events_state(case_dir, state)
    log.info("timeline events built for %s: %d event(s)", case_id, total)
    return {"case_id": case_id, "built": True, **state}


def _index_doc_stream(
    case_dir: Path,
    skipped: dict[str, int],
) -> Iterable[dict[str, Any]]:
    """Every indexed row, counting the families this slice does not write."""
    from nexus.langgraph.case_index import iter_index_docs

    for doc in iter_index_docs(case_dir):
        family = str(doc.get("family") or "").lower()
        if family not in SUPPORTED_FAMILIES:
            skipped[family or "unknown"] = skipped.get(family or "unknown", 0) + 1
            continue
        yield doc