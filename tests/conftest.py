"""Test isolation — keep pytest out of the examiner's real case store.

Every test that touches CaseManager / the CLI previously wrote into the
real ``cases_root`` (``cases/`` in-repo via ``~/.nexus/config.yaml``) and
overwrote the real ``~/.nexus/active_case`` pointer — resurrecting
hundreds of dummy ``CASE-*`` dirs on every full run. These fixtures
redirect both to a per-test temp directory.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


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
