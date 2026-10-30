"""Magnet AXIOM case importer (``Case.mfdb``).

An AXIOM case folder holds the case database ``Case.mfdb`` (SQLite) and AXIOM's own working files: its search index
(``index/``), its timeline database (``Case.timeline``), the attachment store (``<id>.attachments``), its logs and
``Case Information.txt``/``.xml``. The database keeps every result as a hit: ``scan_artifact_hit`` names the hit's
artifact (``artifact_version``: Outlook Emails, Email Attachments, Pictures, ...), and its fields are typed fragments
(``hit_fragment_string``, ``_date``, ``_int``, ``_float``) named by ``fragment_definition``, with where AXIOM found it in
``hit_location``. Sample S09 registers an AXIOM case and no importer read it (2026-10-18).

One artifact per hit, with AXIOM's field names as written. Its time is the hit's first date field in AXIOM's own field
order (``sort_order``); AXIOM stores dates as Unix seconds in UTC. Fragments of type Attachment (the attachment,
thumbnail and raw-data blobs) and AXIOM's internal fields (named with a leading underscore) are not read: the lane
reads records, not specimens. The database is read from a copy with its write-ahead log (``sqlite_snapshot``).
"""

from __future__ import annotations

import heapq
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.ingest.base import Importer
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity
from nexus.ingest.sqlite_snapshot import is_sqlite, snapshot, tables
from nexus.langgraph.lane_gate import IMPORT_TOOL

_REQUIRED_TABLES = {"scan_artifact_hit", "artifact_version", "fragment_definition", "hit_fragment_string"}
_FRAGMENT_TABLES = ("hit_fragment_string", "hit_fragment_int", "hit_fragment_float")
_DESCRIPTION_CHARS = 300

# The files of an AXIOM case folder that are AXIOM's own, beside Case.mfdb: what each is, for the gate.
_CASE_PARTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^case\.mfdb-(wal|shm)$"), "the case database's write-ahead log, read with Case.mfdb"),
    (re.compile(r"^case\.timeline(-wal|-shm)?$"), "AXIOM's timeline database, built from the same hits"),
    (re.compile(r"^[0-9a-f]{32}\.attachments(-wal|-shm)?$"), "AXIOM's attachment store (specimens, not records)"),
    (re.compile(r"^case information\.(txt|xml)$"), "AXIOM's case summary"),
    (re.compile(r"^(axiomexamine.*|artifacts|custom_artifacts|ipc|tagslog)\.log$"), "AXIOM's own log"),
    (re.compile(r"^logging-.*\.zip$"), "AXIOM's own log archive"),
)


def is_axiom_case_db(path: Path) -> bool:
    path = Path(path)
    return path.name.lower().endswith(".mfdb") and is_sqlite(path) and tables(path) >= _REQUIRED_TABLES


def find_axiom_cases(paths: list[str]) -> list[Path]:
    """The AXIOM case databases in the registered evidence."""
    found: list[Path] = []
    for raw in paths:
        p = Path(str(raw))
        candidates = [p] if p.is_file() else (sorted(p.rglob("*.mfdb")) if p.is_dir() else [])
        found.extend(c for c in candidates if c.is_file() and is_axiom_case_db(c))
    return found


def case_parts(db: Path) -> dict[Path, str]:
    """AXIOM's own files in the case folder of ``db``, each with what it is; Case.mfdb itself is not one."""
    folder = Path(db).parent
    parts: dict[Path, str] = {}
    for f in folder.rglob("*"):
        if not f.is_file() or f == db:
            continue
        rel = f.relative_to(folder)
        if rel.parts[0].lower() == "index":
            parts[f] = "AXIOM's search index, built from the same hits"
            continue
        if len(rel.parts) == 1:
            what = next((label for rx, label in _CASE_PARTS if rx.match(f.name.lower())), "")
            if what:
                parts[f] = what
    return parts


def part_gate_rows(db: Path, parts: dict[Path, str]) -> list[dict[str, str]]:
    """The gate's row for each of AXIOM's own files: not read, and why."""
    return [{"tool": f"{IMPORT_TOOL}:axiom", "purpose": f"import {f}", "family": "axiom", "status": "SKIP",
             "reason": f"part of the Magnet AXIOM case read from {db.name}: {what}"} for f, what in sorted(parts.items())]


class AxiomCaseImporter(Importer):
    """Parser for a Magnet AXIOM case database (Case.mfdb)."""

    @classmethod
    def source_class(cls) -> ArtifactSource:
        return ArtifactSource.AXIOM

    @classmethod
    def can_handle(cls, path: Path) -> bool:
        return Path(path).is_file() and is_axiom_case_db(path)

    def parse(self, path: Path) -> Iterator[Artifact]:
        with snapshot(path) as con:
            definitions = {
                fid: (name, dtype or "", order if order is not None else 1 << 30)
                for fid, name, dtype, order in con.execute(
                    "select fragment_definition_id, name, data_type, sort_order from fragment_definition")
            }
            present = {r[0] for r in con.execute("select name from sqlite_master where type = 'table'")}
            streams = [
                con.execute(f"select hit_id, fragment_definition_id, value from {t} order by hit_id")
                for t in _FRAGMENT_TABLES if t in present
            ]
            if "hit_fragment_date" in present:
                streams.append(con.execute(
                    "select hit_id, fragment_definition_id, unix_timestamp from hit_fragment_date order by hit_id"))
            fragments = heapq.merge(*streams, key=lambda r: r[0])
            locations = (con.execute("select hit_id, location_value from hit_location order by hit_id, sort_order")
                         if "hit_location" in present else iter(()))
            hits = con.execute(
                "select h.hit_id, v.artifact_name from scan_artifact_hit h "
                "left join artifact_version v on v.artifact_version_id = h.artifact_version_id order by h.hit_id")
            pending_fragment = next(fragments, None)
            pending_location = next(locations, None)
            for hit_id, artifact in hits:
                values: list[tuple[int, str, Any, str]] = []
                while pending_fragment is not None and pending_fragment[0] <= hit_id:
                    if pending_fragment[0] == hit_id:
                        name, dtype, order = definitions.get(pending_fragment[1], ("", "", 1 << 30))
                        if name and not name.startswith("_") and dtype != "Attachment":
                            values.append((order, name, pending_fragment[2], dtype))
                    pending_fragment = next(fragments, None)
                where: list[str] = []
                while pending_location is not None and pending_location[0] <= hit_id:
                    if pending_location[0] == hit_id and pending_location[1] not in (None, "", "n/a"):
                        where.append(str(pending_location[1]))
                    pending_location = next(locations, None)
                yield self._artifact(hit_id, artifact or "", sorted(values, key=lambda v: v[0]), where)

    @staticmethod
    def _artifact(hit_id: Any, artifact: str, values: list[tuple[int, str, Any, str]], where: list[str]) -> Artifact:
        fields: dict[str, Any] = {}
        ts: datetime | None = None
        for _order, name, value, dtype in values:
            if dtype == "DateTime" and isinstance(value, int | float):
                when = datetime.fromtimestamp(value, UTC)
                fields[name] = when.isoformat()
                ts = ts or when
            else:
                fields[name] = value
        summary = "; ".join(f"{k}: {str(v)[:120]}" for k, v in fields.items() if v not in (None, ""))
        return Artifact(
            id=Artifact.new_id(),
            artifact_type=ArtifactType.UNKNOWN,
            source=ArtifactSource.AXIOM,
            timestamp=ts or datetime.now(UTC),
            ts_synthesized=ts is None,
            severity=Severity.INFORMATIONAL,
            file_path=where[0] if where else None,
            description=f"AXIOM {artifact}: {summary}"[:_DESCRIPTION_CHARS],
            raw={"artifact": artifact, "hit_id": hit_id, **fields, **({"location": where} if where else {})},
            tags=["axiom", f"axiom.{re.sub(r'[^a-z0-9]+', '_', artifact.lower()).strip('_')}"],
        )
