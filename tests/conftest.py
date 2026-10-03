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
    # NOTE: do NOT export NEXUS_AUDIT_DIR here. AuditWriter._get_audit_dir()
    # checks that env BEFORE the active case, so it would send a child's lane
    # audit entries to the session-level sink instead of cases/<id>/audit/ and
    # break finding citations (FD-001/WP 10.4).

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

    # Point the LLM at nothing too, for the same reason as ES: `nexus/__init__`
    # loads the developer's `.env`, so without this a test that reaches a model
    # makes a REAL call to the hosted provider. That is not a test, it is a
    # network dependency: the suite's wall time became the provider's latency
    # (2308 s / 2674 s / 2683 s for one tree; a stack dump during a "slow" run
    # showed the main thread waiting on an established connection to the
    # provider on :443), and a provider outage reads as a test failure. It also
    # defeated the point of tests written for the deterministic path — the
    # suggestions test's own docstring says "with no model configured".
    #
    # Empty but PRESENT, because `_load_dotenv` only fills keys that are absent
    # ("existing vars win") and `get_model` re-loads `.env` on every call; a
    # deleted variable would simply be refilled from the file.
    #
    # Opt back in when the live provider path is what is under test:
    # NEXUS_TESTS_LIVE_LLM=1.
    if os.environ.get("NEXUS_TESTS_LIVE_LLM") != "1":
        for _key in ("NEXUS_LLM_MODEL", "NEXUS_MODEL", "NEXUS_LLM_BASE_URL",
                     "NEXUS_LLM_API_KEY", "NEXUS_LLM_PROVIDER"):
            monkeypatch.setenv(_key, "")

    # The egress anonymizer must not fire on a TestClient loopback either.
    monkeypatch.delenv("NEXUS_BEARER_TOKEN", raising=False)

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
    """``(size, mtime_ns)`` for every protected file. Stat only — no reads.

    Scope set by the operator 2026-10-03 (register D21): the protected set is
    the D25–D27 rationale — the case/credential store and the LLM config. An
    IDE-agent file (``~/.claude/settings.json``) was dropped from it: no test
    and no ``src/`` file writes it, and the agent's own session rewrites it
    mid-run, so guarding it manufactured a false error in agent-driven runs.
    """
    out: dict[str, tuple[int, int]] = {}
    targets: list[Path] = []
    for root in _TRIPWIRE_ROOTS:
        if root.is_dir():
            targets.extend(root.rglob("*"))
    targets.append(Path(__file__).resolve().parent.parent / ".env")
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

    Three notes: any writer counts — a live ``nexus serve`` sharing this machine
    will trip the wire (stop it before a full run); the protected set is
    deliberately the D25–D27 rationale only (case/credential store + LLM config)
    after register D21 removed the IDE-agent file, which no test writes and the
    agent's own session rewrites; and ``tests/test_credential_tripwire.py`` is
    the canary that proves it fires.
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
            + (f"\n  ... {len(lines) - 40} more" if len(lines) > 40 else "")
            + "\n\n"
            + _tripwire_hint(lines),
            pytrace=False,
        )


#: What each protected path is, so a failure says whether it is a real
#: credential incident or the LLM config. Matched on the path as the snapshot
#: records it — absolute, so no `~` prefix.
_TRIPWIRE_CLASSES = (
    (".nexus", "case/credential store", "real incident"),
    (".env", "LLM key / endpoint", "real incident if a test wrote it"),
)


def _tripwire_hint(lines: list[str]) -> str:
    """Classify the touched paths so the reader knows what they are looking at."""
    out = ["What was touched:"]
    for fragment, label, meaning in _TRIPWIRE_CLASSES:
        hits = [line for line in lines if fragment in line]
        if hits:
            out.append(f"  - {label}: {len(hits)} path(s) — {meaning}")
    out.append(
        "  A path that is neither protected case state nor the LLM config is "
        "not case data and not a credential: compare its mtime with the run "
        "window before treating this as a test failure (register D21)."
    )
    return "\n".join(out)


# ---------------------------------------------------------------------------
# WO-V2 (D27) — Elasticsearch index tripwire
# ---------------------------------------------------------------------------
#
# The case store and the password store are redirected per test. Elasticsearch
# is not: it is a shared service on the operator's machine, and a test - or a
# thread it left running past teardown - that points at the cluster creates a
# real `nexus-case-*` index there. Nothing else notices, and one such index
# made `n4_hits` take the ES path against another run's leftovers and return a
# confident zero while the CSV pack beside it was full.
#
# Cheap by design: two `_cat/indices` calls for the whole session, whatever the
# suite size. `NEXUS_ES_LEAK_PROBE=1` additionally checks after every test and
# prints the nodeid that caused a change, which is how the culprit is found.
# The probe disables itself the moment the cluster does not answer, so a
# stopped Docker engine cannot turn the suite into thousands of timeouts.

_ES_PROBE_TIMEOUT = 1.5


def _env_file_es_url() -> str:
    """``NEXUS_ES_URL`` as ``.env`` defines it — the operator's real cluster.

    Read from the file, not ``os.environ``: the session fixtures may run before
    anything imports ``nexus`` (which is what loads ``.env``), and the
    function-scoped fixture deliberately empties the variable per test.
    """
    env_file = Path(__file__).resolve().parent.parent / ".env"
    try:
        text = env_file.read_text(encoding="utf-8")
    except OSError:
        return ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("NEXUS_ES_URL="):
            raw = line.partition("=")[2].strip().strip('"').strip("'")
            return raw.rstrip("/")
    return ""


def _es_answers(url: str) -> bool:
    if not url:
        return False
    try:
        import httpx

        with httpx.Client(timeout=_ES_PROBE_TIMEOUT) as client:
            return client.get(f"{url}/").status_code == 200
    except Exception:  # noqa: BLE001 — an unreachable cluster disables the probe
        return False


def _case_indexes(url: str) -> set[str]:
    """``nexus-case-*`` index names on ``url``; empty when unreachable."""
    if not url:
        return set()
    try:
        import httpx

        with httpx.Client(timeout=_ES_PROBE_TIMEOUT) as client:
            response = client.get(f"{url}/_cat/indices/nexus-case-*?h=index")
    except Exception:  # noqa: BLE001
        return set()
    if response.status_code != 200:
        return set()
    return {line.strip() for line in response.text.splitlines() if line.strip()}


_ES_PROBE_URL = ""
_ES_PROBE_LIVE = False


@pytest.fixture(scope="session", autouse=True)
def _es_index_tripwire():
    """Fail the session if the run created or removed a ``nexus-case-*`` index.

    Also keeps the real ``NEXUS_ES_URL`` out of the environment for the whole
    session. The per-test fixture empties it inside a test, but ``monkeypatch``
    restores the real value at teardown — so a thread, a session fixture or an
    MCP child that outlives its test would read the operator's cluster. This is
    the backstop for everything outside a test's window.
    """
    global _ES_PROBE_URL, _ES_PROBE_LIVE
    _ES_PROBE_URL = _env_file_es_url()
    before: set[str] = set()
    if _ES_PROBE_URL and _es_answers(_ES_PROBE_URL):
        _ES_PROBE_LIVE = True
        before = _case_indexes(_ES_PROBE_URL)
    else:
        print(
            "\n[es-tripwire] skipped: no NEXUS_ES_URL in .env, or the cluster "
            "did not answer",
            flush=True,
        )
    # Present-but-empty, NOT popped: `llm_pipeline._load_dotenv()` runs on every
    # `get_model` call and fills any ABSENT key, so a popped URL is refilled from
    # the developer's `.env` on the first model call made outside a test's own
    # window — a thread, a teardown, a session fixture. From then on every
    # per-test `monkeypatch` restores the real URL at teardown, and the tripwire
    # below detects a leak at session end instead of preventing one (D23/WO-V7).
    # Present-but-empty survives the reload, which is why the LLM keys use it too.
    saved_env = {
        key: os.environ.get(key)
        for key in ("NEXUS_ES_URL", "NEXUS_ES_AUTOINDEX")
    }
    for key in saved_env:
        os.environ[key] = ""
    yield
    for key, value in saved_env.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    if not _ES_PROBE_LIVE:
        return
    after = _case_indexes(_ES_PROBE_URL)
    created = sorted(after - before)
    removed = sorted(before - after)
    if created or removed:
        detail = [f"+ created  {name}" for name in created]
        detail += [f"- removed  {name}" for name in removed]
        pytest.fail(
            "Elasticsearch tripwire: the test run changed the operator's "
            "cluster:\n  " + "\n  ".join(detail[:40]) +
            "\n  A test must not create or delete an index on a shared ES. "
            "Point the test at a fake URL, or delete what it made "
            "(`nexus-case-test-*` naming) in a fixture teardown.",
            pytrace=False,
        )


@pytest.fixture(autouse=True)
def _es_index_probe(request):
    """Name the test that changes the ES index set. Opt-in, and self-disabling.

    Set ``NEXUS_ES_LEAK_PROBE=1`` and run the suite to find a leak: the nodeid
    is printed as soon as a test's net change to the cluster is non-zero. It is
    off by default because it costs one HTTP call per test.
    """
    if not (_ES_PROBE_LIVE and os.environ.get("NEXUS_ES_LEAK_PROBE") == "1"):
        yield
        return
    before = _case_indexes(_ES_PROBE_URL)
    yield
    after = _case_indexes(_ES_PROBE_URL)
    if before != after:
        print(
            f"\n[es-leak] {request.node.nodeid}"
            f"  created={sorted(after - before)}"
            f"  removed={sorted(before - after)}",
            flush=True,
        )
