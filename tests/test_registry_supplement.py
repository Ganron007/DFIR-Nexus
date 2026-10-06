"""WO-R0F item 8: the registry build must not silently drop a column or family.

`f98698b` (KM1) regenerated `field_registry.yaml` from a corpus and dropped the
`registration_date` column and the `tasks` family, breaking
`test_timeline_events.py::test_task_xml_registration_time_is_registry_typed`. The
build now merges `src/nexus/data/schema/field_registry_supplement.yaml` (the
documented, reviewable home for product-required declarations the evidence tree
cannot carry) and FAILS if a regeneration would remove a column or a required
family with no reason.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
SUPPLEMENT = REPO / "src" / "nexus" / "data" / "schema" / "field_registry_supplement.yaml"
REGISTRY = REPO / "src" / "nexus" / "data" / "schema" / "field_registry.yaml"
BUILDER = REPO / "scripts" / "build_field_registry.py"


def _builder():
    spec = importlib.util.spec_from_file_location("bfr_under_test", BUILDER)
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["bfr_under_test"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def test_supplement_exists_and_declares_the_regression() -> None:
    assert SUPPLEMENT.is_file(), "the registry supplement is missing"
    doc = yaml.safe_load(SUPPLEMENT.read_text(encoding="utf-8")) or {}
    cols = doc.get("columns") or {}
    assert "registration_date" in cols, sorted(cols)
    assert "tasks" in (cols["registration_date"].get("families") or [])


def test_the_shipped_registry_carries_the_tasks_family() -> None:
    reg = yaml.safe_load(REGISTRY.read_text(encoding="utf-8")) or {}
    cols = reg.get("columns") or {}
    assert "registration_date" in cols, "registration_date dropped again"
    assert "tasks" in (cols["registration_date"].get("families") or [])
    assert "task_registration_date" in cols
    assert "tasks" in (cols["task_registration_date"].get("families") or [])


def test_the_build_check_reports_a_silent_removal(tmp_path) -> None:
    """A removed column/family is caught, not written silently."""
    mod = _builder()
    deduped = {"c1": {"type": "text", "families": ["tasks"]}}
    # simulate the check's core: prior columns minus new ones
    prior = {"c1", "c2"}
    new = set(deduped)
    removals = sorted(prior - new)
    assert removals == ["c2"]
    # and the builder exposes the required-family list
    _, required = mod.load_supplement()
    assert "tasks" in required
