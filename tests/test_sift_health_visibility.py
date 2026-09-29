"""The health badge shows SIFT HOST state even when the lane is not selected.

Operator report 2026-09-30: the cockpit said "SIFT off" while the SIFT host was
running. `selected` is the case's lane choice; `reachable` is a machine-level
fact and must be visible for unselected cases too — probed in the background so
a slow/absent host never stalls the cheap health poll.
"""
from __future__ import annotations

import time

from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.dashboard.app import create_dashboard


def _client() -> TestClient:
    return TestClient(Starlette(routes=create_dashboard()))


def test_health_reports_cached_host_state_for_unselected_case(monkeypatch):
    import nexus.dashboard.app as app_mod

    monkeypatch.setattr(app_mod, "_SIFT_PROBE_CACHE", {"result": (time.time(), True, "ok")})
    monkeypatch.setattr(app_mod, "_SIFT_PROBE_INFLIGHT", False)

    body = _client().get("/portal/api/system/health").json()
    sift = body["sift"]
    assert sift["selected"] is False
    assert sift["reachable"] is True
    assert sift["message"] == "ok"


def test_stale_sift_cache_refreshes_in_the_background(tmp_path, monkeypatch):
    import nexus.case.sift_sync as sift_sync
    import nexus.dashboard.app as app_mod

    monkeypatch.setattr(app_mod, "_SIFT_PROBE_CACHE", {})
    monkeypatch.setattr(app_mod, "_SIFT_PROBE_INFLIGHT", False)
    calls: list[int] = []

    def _fake_probe():
        calls.append(1)
        return True, "background-ok"

    monkeypatch.setattr(sift_sync, "sift_reachable", _fake_probe)

    client = _client()
    t0 = time.time()
    body = client.get("/portal/api/system/health").json()
    assert time.time() - t0 < 5, "the health poll must not wait on the probe"
    assert body["sift"]["reachable"] is None  # nothing probed yet

    deadline = time.time() + 10
    while time.time() < deadline and not app_mod._SIFT_PROBE_CACHE.get("result"):
        time.sleep(0.05)
    cached = app_mod._SIFT_PROBE_CACHE.get("result")
    assert cached and cached[1] is True and calls

    body2 = client.get("/portal/api/system/health").json()
    assert body2["sift"]["reachable"] is True
    assert body2["sift"]["message"] == "background-ok"

    # And the cached value is served without a second probe within the minute.
    calls_before = len(calls)
    client.get("/portal/api/system/health")
    assert len(calls) == calls_before
