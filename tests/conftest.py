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
    "test_detection.py",    # script-style: sys.exit() at module level
    "test_hunt_parser.py",  # script-style: sys.exit() at module level
    "test_integration.py",  # script-style: starts live server, long-running
    "test_ti.py",           # script-style: sys.exit() at module level
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

    # Point ES at nothing for the duration of the test.
    #
    # The case store is redirected but Elasticsearch was not, so a test that
    # created a case also created a real index on the developer's cluster - named
    # after the test case, and never deleted. Those indexes then outlived the test
    # that made them: a zero-doc `nexus-case-inc-test-0001` left by an earlier run
    # made `n4_hits` take the ES path, find nothing, and return a confident zero
    # while the CSV pack beside it was full. Two suites failed because of it.
    #
    # Redirecting rather than deleting: a test must not reach a shared external
    # service, or its result depends on what other runs left behind.
    monkeypatch.setenv("NEXUS_ES_URL", "")
    monkeypatch.setenv("NEXUS_ES_AUTOINDEX", "0")

    # The password store is the one directory a test must never reach: it holds
    # the examiner's real approval credential, and writing to it does not fail -
    # it silently replaces the credential with whatever the test made up. That
    # happened: an early draft of `test_examiner_identity_store.py` wrote its
    # fixture names into `~/.nexus/passwords/` and overwrote `gate-bot.json` with
    # `{"hash": "h", "salt": "s", "iterations": 1}`, leaving the real examiner
    # unable to approve anything.
    #
    # Redirected here rather than in each test so it cannot be forgotten. A test
    # that wants to exercise the store patches its own tmp copy on top of this.
    import nexus.auth as _auth

    _pw_dir = tmp_path / "passwords"
    _pw_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(_auth, "_PASSWORDS_DIR", _pw_dir)
    monkeypatch.setattr(_auth, "_LOCKOUT_FILE", tmp_path / "approval_lockout")

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
