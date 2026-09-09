"""Pytest configuration — test isolation + legacy-script exclusion.

Two jobs:

1. **Test isolation** (restored — it was accidentally overwritten during the
   discovery fix): redirect ``cases_root`` + the active-case pointer to a
   per-test temp directory so pytest never writes into the examiner's real
   case store.
2. **Legacy-script exclusion**: standalone check-scripts (module-level
   ``sys.exit``/``__main__``, not pytest-collectable) are excluded from
   discovery. Everything else under ``tests/test_*.py`` runs in the full
   suite — the previous explicit ``python_files`` allowlist silently
   excluded 28 real test files (Mode 1/2/3, portal, RAG, FD-006/007,
   Phase 4 APIs) from full runs.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

collect_ignore_glob = [
    "test_detection.py",
    "test_hunt_parser.py",
    "test_integration.py",
    "test_portal.py",
    "test_ti.py",
]


@pytest.fixture(autouse=True)
def _isolated_case_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Redirect cases_root + active-case pointer to tmp for every test."""
    from nexus.config import settings

    original_cases_root = settings.cases_root
    tmp_cases = tmp_path / "cases"
    tmp_cases.mkdir(parents=True, exist_ok=True)
    settings.cases_root = tmp_cases

    active_file = tmp_path / "active_case"
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(active_file))

    # Module-level constants captured the real path at import time.
    for mod_name, attr in (
        ("nexus.cli.case_cmd", "_ACTIVE_CASE_FILE"),
        ("nexus.cli.evidence", "_ACTIVE_CASE_FILE"),
        ("nexus.cli.report", "_ACTIVE_CASE_FILE"),
        ("nexus.case.outputs", "_ACTIVE_CASE_FILE"),
    ):
        try:
            mod = importlib.import_module(mod_name)
        except ImportError:  # pragma: no cover - optional deps
            continue
        if hasattr(mod, attr):
            monkeypatch.setattr(mod, attr, active_file)

    yield

    settings.cases_root = original_cases_root
