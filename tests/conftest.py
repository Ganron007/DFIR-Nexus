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
    # Child processes (stdio MCP children) read the config loader's names, not
    # the module-level constants the fixture patches in-process.
    monkeypatch.setenv("NEXUS_CASE_DIR", str(active_file))
    monkeypatch.setenv("NEXUS_AUDIT_DIR", str(tmp_path / "audit"))

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

    # WO-5: every module-level constant that captured a real home path at
    # import time (the session tripwire below is the backstop; these are the
    # redirects).
    monkeypatch.setattr(_auth, "VERIFICATION_DIR", tmp_path / "verification")
    import nexus.transparency as _transparency

    monkeypatch.setattr(_transparency, "TRANSPARENCY_DIR", tmp_path / "transparency")
    from nexus.case import secrets as _secrets

    monkeypatch.setattr(_secrets, "_PERSISTED_SECRET_PATH", tmp_path / "audit_secret")
    import nexus.dashboard.app as _dash

    monkeypatch.setattr(_dash, "_LOCKOUT_FILE", tmp_path / ".commit_lockout")
    monkeypatch.setenv("NEXUS_NEEDLE_OVERLAY", str(tmp_path / "needle_overlay.yaml"))
    monkeypatch.delenv("NEXUS_HTTP_AUDIT_GLOBAL", raising=False)
    monkeypatch.setenv("NEXUS_HTTP_LOG_DIR", str(tmp_path / "http_logs"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    settings.data_root = tmp_path / "data"
    settings.audit_dir = tmp_path / "audit"

    # The RAG index resolves through these at call time; redirect them and
    # drop any cached index so no in-process path can reach the real bundle.
    import nexus.tools.rag as _rag

    monkeypatch.setattr(_rag, "_get_index_dir", lambda: tmp_path / "data" / "rag")
    monkeypatch.setattr(_rag, "_global_index", None)

    # No test may download the RAG bundle (a 128 MB GitHub release asset). The
    # index-dir redirect above makes "index missing" the normal test state, and
    # a route or pipeline path that reacts by downloading must not reach the
    # network — a stalled asset hung a full-suite run (2026-09-29).
    def _blocked_asset(url, dest):
        raise RuntimeError("blocked in tests: RAG bundle download disabled")

    def _blocked_release(*_args, **_kwargs):
        raise RuntimeError("blocked in tests: RAG release lookup disabled")

    monkeypatch.setattr(_rag, "_download_asset", _blocked_asset)
    monkeypatch.setattr(_rag, "_fetch_latest_release", _blocked_release)

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


# ---------------------------------------------------------------------------
# WO-5 — credential / path tripwire (the real guard)
# ---------------------------------------------------------------------------

_TRIPWIRE_ROOTS = (Path.home() / ".nexus",)


def _protected_snapshot() -> dict[str, tuple[int, int]]:
    """``(size, mtime_ns)`` for every protected file. Stat only — no reads."""
    out: dict[str, tuple[int, int]] = {}
    targets: list[Path] = []
    for root in _TRIPWIRE_ROOTS:
        if root.is_dir():
            targets.extend(root.rglob("*"))
    targets.append(Path(__file__).resolve().parent.parent / ".env")
    targets.append(Path.home() / ".claude" / "settings.json")
    for path in targets:
        try:
            if path.is_file():
                st = path.stat()
                out[str(path)] = (st.st_size, st.st_mtime_ns)
        except OSError:
            continue
    return out


@pytest.fixture(scope="session", autouse=True)
def _credential_tripwire():
    """Fail the session if the run wrote anything under the protected paths.

    D25/D26/D27: tests overwrote the real password store, the real LLM key in
    ``.env`` and leaked ES indexes. The redirects above are the first layer;
    this snapshot (stat only, a few thousand stats) is the guard that catches
    whatever they miss.

    Two notes: any writer counts — a live ``nexus serve`` sharing this machine
    will trip the wire (stop it before a full run); and
    ``tests/test_credential_tripwire.py`` is the canary that proves it fires.
    """
    before = _protected_snapshot()
    yield
    after = _protected_snapshot()
    lines = (
        [f"+ created  {p}" for p in sorted(set(after) - set(before))]
        + [f"- deleted  {p}" for p in sorted(set(before) - set(after))]
        + [
            f"~ modified {p}"
            for p in sorted(set(before) & set(after))
            if before[p] != after[p]
        ]
    )
    if lines:
        pytest.fail(
            "credential/path tripwire: the test run touched protected paths:\n  "
            + "\n  ".join(lines[:40])
            + (f"\n  ... {len(lines) - 40} more" if len(lines) > 40 else ""),
            pytrace=False,
        )
