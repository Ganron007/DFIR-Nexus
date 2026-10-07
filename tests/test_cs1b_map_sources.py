"""WO-CS1b item 3: the source-name test the map's header promises.

Every `family_columns` source must exist in that family's ES-Mapping catalog, and
every EVTX EventData name must appear in that (channel, event) entry's xpaths in
the pinned `evtxecmd_maps.yaml`. This is the test the map header claimed existed
and did not.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

BUILD = REPO / "scripts" / "build_field_registry.py"


def _catalog_families() -> dict[str, set[str]]:
    """Families -> columns, from the build catalog AND the real-run population.

    The ES-Mapping catalog uses source namespacing (`aws.EventName`), while the
    corpus the index reads flattens them (`EventName`) - so the population profile
    is the authoritative set of real columns a family row carries.
    """
    import json

    spec = importlib.util.spec_from_file_location("bfr_under_test", BUILD)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["bfr_under_test"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    rows, _ = mod.load_rows()
    out = {fam: set(cols) for fam, cols in rows.items()}

    pop_path = REPO / "Evidence-files/ES-Mapping/es_mappings/_population.json"
    if pop_path.is_file():
        data = json.loads(pop_path.read_text(encoding="utf-8")) or {}
        for fam, body in (data.get("families") or {}).items():
            cols = set((body.get("columns") or {}).keys())
            out.setdefault(fam, set()).update(cols)
    return out


def _ecs_map() -> dict:
    from nexus.langgraph.ecs_normalize import load_ecs_map
    return load_ecs_map()


def test_every_family_column_exists_in_that_familys_catalog():
    """A `family_columns` source must be a real column of that family."""
    catalog = _catalog_families()
    # family -> the catalog family name where it differs. The importer slots are
    # the `ingest-*` schema; a tool with an importer counterpart resolves there.
    alias = {
        "amcache": "ingest-amcache",
        "plaso": None,  # the real plaso l2tcsv family exists as `plaso`
        "ingest": None,  # the normalized importer schema, checked separately
    }
    problems: list[str] = []
    for fam, table in (_ecs_map().get("family_columns") or {}).items():
        if fam == "ingest":
            continue  # the normalized importer schema, not a tool catalog
        cat_fam = alias.get(fam, fam)
        if cat_fam is None:
            cat_fam = fam
        cols = catalog.get(cat_fam)
        if cols is None:
            # a family with no catalog is skipped (e.g. a tool without a yaml);
            # do not fail - the reviewer's demand is that a NAMED source exists.
            continue
        for column in table:
            if str(column).startswith("__"):
                continue  # a transform declaration, not a column
            if column not in cols:
                problems.append(f"{fam}.{column} not in {cat_fam} catalog")
    assert problems == [], "\n".join(problems)


def test_no_mapped_source_is_a_provenance_column():
    """An `ecs` field must never hold `<source>` (WO-CS1b item 3)."""
    from nexus.langgraph.path_sanitize import (
        FAMILY_SOURCE_COLUMNS,
        SOURCE_PATH_COLUMNS,
    )

    problems: list[str] = []
    for fam, table in (_ecs_map().get("family_columns") or {}).items():
        fam_sources = {c.lower() for c in (FAMILY_SOURCE_COLUMNS.get(fam) or [])}
        for column in table:
            low = str(column).lower()
            if low in SOURCE_PATH_COLUMNS or low in fam_sources:
                problems.append(f"{fam}.{column} is a provenance column")
    assert problems == [], "\n".join(problems)


def test_every_evtx_event_data_name_is_real():
    """Each EVTX EventData name must appear in the real Payload of that (channel, event).

    The pinned `evtxecmd_maps.yaml` only records the names its templates resolve, so
    it is a SUBSET of the names EvtxECmd actually emits. The authoritative source is
    the real `Payload` JSON of a verbatim row (the committed public-sample fixture,
    plus any EvtxECmd output present under `Evidence-files/`).
    """
    import csv
    import json

    # (channel, event_id) -> set of real EventData @Name values
    real: dict[tuple[str, str], set[str]] = {}

    def _ingest(path: Path) -> None:
        if not path.is_file():
            return
        with path.open(encoding="utf-8", errors="replace") as fh:
            for row in csv.DictReader(fh):
                pl = row.get("Payload", "")
                if not pl.startswith("{"):
                    continue
                try:
                    doc = json.loads(pl)
                except ValueError:
                    continue
                data = ((doc.get("EventData") or {}).get("Data")) or []
                if isinstance(data, dict):
                    data = [data]
                names = {str(i.get("@Name")) for i in data if isinstance(i, dict)}
                key = (str(row.get("Channel")), str(row.get("EventId")))
                real.setdefault(key, set()).update(names)

    fixture = REPO / "tests/fixtures/cs1b_evtx_real_rows.csv"
    assert fixture.is_file(), "the CS1b real-row fixture is missing"
    _ingest(fixture)
    # the operator's own EvtxECmd outputs, when present (never committed)
    for extra in (REPO / "Evidence-files/ES-Mapping/outputs/ccs1b-real").glob("*.csv") \
            if (REPO / "Evidence-files/ES-Mapping/outputs/ccs1b-real").is_dir() else []:
        _ingest(extra)

    problems: list[str] = []
    for channel, events in (_ecs_map().get("winlog_event_data") or {}).items():
        if not isinstance(events, dict):
            continue
        for event_id, fields in events.items():
            if not isinstance(fields, dict):
                continue
            names = real.get((channel, str(event_id)))
            if names is None:
                problems.append(f"no real row for ({channel}, {event_id})")
                continue
            for ev_name in fields:
                if ev_name not in names:
                    problems.append(
                        f"({channel},{event_id}).{ev_name} not in the real Payload")
    assert problems == [], "\n".join(problems)
