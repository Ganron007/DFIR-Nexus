"""WO-KM1 item 4: the EvtxECmd maps are imported from a pinned snapshot.

The defect: the mapping recorded `PayloadData1-6` as names with one (often empty)
example, but their content **depends on the event ID** - a query against
`fields.PayloadData1` on a Security 4624 row and a PowerShell 4100 row means two
different things, and neither is discoverable from a per-column example.

The WO: pin EvtxECmd's maps at a commit SHA, import per (Channel, EventId) what each
generic column holds (the map's value template), and check 10 random entries against
the snapshot.
"""
from __future__ import annotations

import importlib.util
import os
import random
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
IMPORTED = REPO / "src" / "nexus" / "data" / "schema" / "evtxecmd_maps.yaml"
IMPORTER = REPO / "devtools" / "knowledge" / "import_evtx_maps.py"


def _snapshots() -> Path | None:
    spec = importlib.util.spec_from_file_location("iem", IMPORTER)
    if not spec or not spec.loader:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules["iem"] = module
    spec.loader.exec_module(module)
    for candidate in (
        os.environ.get("NEXUS_KL2B_SNAPSHOTS"),
        os.path.join(os.environ.get("TEMP", "/tmp"), "kl2b-snapshots"),
    ):
        if candidate and (Path(candidate) / "evtx" / "evtx" / "Maps").is_dir():
            return Path(candidate)
    return None


@pytest.fixture(scope="module")
def imported_pack() -> dict:
    assert IMPORTED.is_file(), "run devtools/knowledge/import_evtx_maps.py"
    return yaml.safe_load(IMPORTED.read_text(encoding="utf-8")) or {}


def test_the_import_is_pinned_to_a_commit(imported_pack):
    """Rule 9: an external attribution is a pinned snapshot, not a claim."""
    assert len(str(imported_pack.get("source_version") or "")) == 40
    assert "EricZimmerman" in str(imported_pack.get("source"))
    assert imported_pack.get("source_key") == "Maps/*.map"


def test_the_generic_columns_carry_a_template_per_channel_and_event(imported_pack):
    """Each entry says what its generic columns hold, from the map's own value.

    The old per-column example could not show this: the same `PayloadData1` is
    different data on different events.
    """
    packs = imported_pack.get("packs") or []
    assert packs
    with_cols = [p for p in packs if p.get("columns")]
    assert with_cols, "no entry has generic columns"
    for entry in packs[:50]:
        for column, meta in (entry.get("columns") or {}).items():
            assert str(column).startswith(("PayloadData", "Executable", "UserName", "RemoteHost")), column
            assert "template" in meta, (entry["source_key"], column)
            assert meta["template"], (entry["source_key"], column)


def test_the_import_is_not_invented(imported_pack):
    """A map entry must not exist without its source file, and no duplicate keys."""
    packs = imported_pack.get("packs") or []
    keys = [(e.get("channel"), e.get("event_id")) for e in packs]
    assert len(keys) == len(set(keys)), "duplicate (Channel, EventId)"
    for entry in packs:
        assert entry.get("source_key", "").endswith(".map"), entry


def test_the_import_is_reproducible():
    """`--check` proves the file is what the snapshot produces."""
    import subprocess

    proc = subprocess.run([sys.executable, str(IMPORTER), "--check"],
                          cwd=str(REPO), capture_output=True, text=True, timeout=300, check=False)
    out = proc.stdout + proc.stderr
    if "snapshot not found" in out:
        pytest.skip("EvtxECmd maps snapshot absent - set NEXUS_KL2B_SNAPSHOTS")
    assert proc.returncode == 0, out[-600:]


def test_ten_random_entries_match_the_snapshot(imported_pack):
    """The WO's acceptance: 10 random entries checked against the pinned source."""
    snapshots = _snapshots()
    if snapshots is None:
        pytest.skip("EvtxECmd maps snapshot absent - set NEXUS_KL2B_SNAPSHOTS")
    maps_dir = snapshots / "evtx" / "evtx" / "Maps"
    packs = imported_pack.get("packs") or []
    sample = random.Random(0).sample(packs, min(10, len(packs)))
    bad: list[str] = []
    for entry in sample:
        src = maps_dir / entry["source_key"]
        if not src.is_file():
            bad.append(f"{entry['source_key']}: source file missing")
            continue
        doc = yaml.safe_load(src.read_text(encoding="utf-8")) or {}
        channel = str(doc.get("Channel") or "").strip().strip('"')
        event = str(doc.get("EventId") or "").strip()
        if (channel, event) != (entry["channel"], entry["event_id"]):
            bad.append(f"{entry['source_key']}: channel/event mismatch")
        templates = {
            str(i["Property"]): str(i.get("PropertyValue") or "")
            for i in (doc.get("Maps") or [])
            if isinstance(i, dict) and str(i.get("Property") or "") in
            ("PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
             "PayloadData5", "PayloadData6", "ExecutableInfo", "UserName", "RemoteHost")
        }
        if set(entry.get("columns") or {}) != set(templates):
            bad.append(f"{entry['source_key']}: column set differs")
        else:
            for column, template in templates.items():
                if entry["columns"][column].get("template") != template:
                    bad.append(f"{entry['source_key']}.{column}: template differs")
    assert bad == [], "\n".join(bad)
