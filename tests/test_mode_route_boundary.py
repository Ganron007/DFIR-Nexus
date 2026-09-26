"""The per-case mode boundary must hold on every mode-owned portal route.

Regression for the debug-mode exposure probe: 22 of 29 mode-owned endpoints
answered a case stored in a different mode (six of them with live data), because
each handler had to opt into the guard individually and most did not. The guard
now lives at route registration (:func:`nexus.dashboard.app._mode_route`), so a
new endpoint cannot ship unguarded by omission.

The check is deliberately structural — it walks the built route table rather
than calling 29 endpoints — so it stays fast and cannot be satisfied by a subset
of handlers.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml
from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.dashboard.app import _mode_route, create_dashboard

MODE_PREFIX = re.compile(r"^/portal/api/mode([123])/")

#: Mode-agnostic by design: a mapping read, not a mode surface.
UNGATED_BY_DESIGN = {"/portal/api/mode-mapping"}


def _mode_routes() -> list[tuple[str, int, set[str]]]:
    out = []
    for route in create_dashboard():
        path = getattr(route, "path", "")
        m = MODE_PREFIX.match(path)
        if not m:
            continue
        if path in UNGATED_BY_DESIGN:
            continue
        methods = {x for x in (getattr(route, "methods", set()) or set()) if x in {"GET", "POST"}}
        out.append((path, int(m.group(1)), methods))
    return out


def _client_for(monkeypatch, tmp_path, *, wrong_mode: int, expected: int) -> TestClient:
    """A client whose active case is stored in `wrong_mode`."""
    from nexus.config import settings

    cases_root = tmp_path / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))

    case_dir = cases_root / "CASE-BOUNDARY"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "CASE.yaml").write_text(
        yaml.safe_dump(
            {
                "case_id": "CASE-BOUNDARY",
                "name": "Boundary",
                "investigation_mode": str(wrong_mode),
                "mode_scheme": 2,
            }
        ),
        encoding="utf-8",
    )
    assert settings.cases_root == cases_root
    return TestClient(Starlette(routes=create_dashboard()))


def test_every_mode_owned_route_is_registered_through_the_guard():
    """No mode-owned route may be registered as a bare Route()."""
    src = Path("src/nexus/dashboard/app.py").read_text(encoding="utf-8")
    bare = re.findall(r'Route\("(/portal/api/mode[123][^"]*)"', src)
    assert bare == [], f"registered without the mode guard: {bare}"


def test_mode_routes_are_discovered():
    routes = _mode_routes()
    assert len(routes) >= 29, f"expected the full mode surface, found {len(routes)}"
    for path, _mode, methods in routes:
        assert methods, f"{path} has no HTTP method"


@pytest.mark.parametrize(
    "path,mode",
    [
        ("/portal/api/mode1/ask", 1),
        ("/portal/api/mode1/suggestions", 1),
        ("/portal/api/mode1/select", 1),
        ("/portal/api/mode1/iterate", 1),
        ("/portal/api/mode1/save-answer", 1),
        ("/portal/api/mode1/corroborate", 1),
        ("/portal/api/mode1/propose-draft", 1),
        ("/portal/api/mode2/plan", 2),
        ("/portal/api/mode2/execute", 2),
        ("/portal/api/mode2/run/steer", 2),
        ("/portal/api/mode2/run/pause", 2),
        ("/portal/api/mode2/run/resume", 2),
        ("/portal/api/mode2/run/stop", 2),
        ("/portal/api/mode2/run/stage", 2),
        ("/portal/api/mode3/run/steer", 3),
        ("/portal/api/mode3/run/pause", 3),
        ("/portal/api/mode3/run/resume", 3),
        ("/portal/api/mode3/run/stop", 3),
        ("/portal/api/mode3/run/stage", 3),
    ],
)
def test_wrong_mode_case_is_refused_with_409(monkeypatch, tmp_path, path, mode):
    """Each endpoint must answer 409 for a case stored in another mode."""
    client = _client_for(monkeypatch, tmp_path, wrong_mode={1: 2, 2: 3, 3: 1}[mode], expected=mode)
    resp = client.post(path, json={}, headers={"X-Nexus-Case": "CASE-BOUNDARY"})
    assert resp.status_code == 409, f"{path} answered {resp.status_code}: {resp.text[:200]}"
    body = resp.json()
    assert body["case_mode"] == {1: 2, 2: 3, 3: 1}[mode]
    assert body["expected_mode"] == mode


@pytest.mark.parametrize(
    "path,mode",
    [
        ("/portal/api/mode1/full-run/status", 1),
        ("/portal/api/mode2/run/status", 2),
        ("/portal/api/mode3/run/status", 3),
        ("/portal/api/mode3/run/board", 3),
    ],
)
def test_wrong_mode_status_reads_are_refused_with_409(monkeypatch, tmp_path, path, mode):
    """The read-only status/board endpoints are part of the boundary too."""
    client = _client_for(monkeypatch, tmp_path, wrong_mode={1: 2, 2: 3, 3: 1}[mode], expected=mode)
    resp = client.get(path, headers={"X-Nexus-Case": "CASE-BOUNDARY"})
    assert resp.status_code == 409, f"{path} answered {resp.status_code}: {resp.text[:200]}"
    assert resp.json()["expected_mode"] == mode


def test_matching_mode_is_not_blocked(monkeypatch, tmp_path):
    """The guard must not refuse a case that IS in the right mode."""
    cases_root = tmp_path / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    case_dir = cases_root / "CASE-SAMEMODE"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "CASE.yaml").write_text(
        yaml.safe_dump(
            {"case_id": "CASE-SAMEMODE", "name": "Same", "investigation_mode": "1", "mode_scheme": 2}
        ),
        encoding="utf-8",
    )
    client = TestClient(Starlette(routes=create_dashboard()))
    resp = client.post(
        "/portal/api/mode1/ask", json={"question": "what is here"},
        headers={"X-Nexus-Case": "CASE-SAMEMODE"},
    )
    assert resp.status_code != 409


def test_case_without_a_stored_mode_is_left_alone(monkeypatch, tmp_path):
    """Pre-mode cases (no investigation_mode) must still run, for backward compat."""
    cases_root = tmp_path / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    case_dir = cases_root / "CASE-LEGACY"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "CASE.yaml").write_text(
        yaml.safe_dump({"case_id": "CASE-LEGACY", "name": "Legacy"}), encoding="utf-8"
    )
    client = TestClient(Starlette(routes=create_dashboard()))
    resp = client.post(
        "/portal/api/mode1/ask", json={"question": "q"},
        headers={"X-Nexus-Case": "CASE-LEGACY"},
    )
    assert resp.status_code != 409


def test_no_active_case_still_reports_404(monkeypatch, tmp_path):
    """Relaxing the mode guard must not change the 'no case' contract."""
    cases_root = tmp_path / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    client = TestClient(Starlette(routes=create_dashboard()))
    resp = client.post("/portal/api/mode1/ask", json={"question": "q"})
    assert resp.status_code == 404
    assert "No active case" in resp.json()["error"]


def test_mode_route_leaves_unprefixed_paths_unguarded():
    """The helper must not silently guard a non-mode path."""
    calls = []

    async def handler(request):  # pragma: no cover - not called
        calls.append(1)
        return None

    route = _mode_route("/portal/api/case/thing", handler, ["GET"])
    assert route.endpoint is handler
