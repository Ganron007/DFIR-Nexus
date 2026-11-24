"""Adversarial regression tests for P0 security remediations (WP-AUD-01..04)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from nexus.cli.main import build_http_app
from nexus.dashboard.app import _pipeline_run_status_path, create_dashboard
from nexus.portal.rate_limit import PortalRateLimitMiddleware
from nexus.portal.session import PORTAL_SESSION_COOKIE, PortalSessionMiddleware
from nexus.utils.constants import ENV_PORTAL_PASSWORD, MissingProductionEnvError, check_required_env

# ---------------------------------------------------------------------------
# P0-1 / WP-AUD-01: Signed Portal Session Auth & Fail-Closed Remote Bind
# ---------------------------------------------------------------------------


def test_p0_1_remote_bind_refuses_unauthenticated_portal_endpoints(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("NEXUS_AUDIT_SECRET", "audit-secret-for-test-0123456789")
    monkeypatch.setenv("NEXUS_PORTAL_PASSWORD", "correct-horse-battery-staple")
    monkeypatch.setenv("NEXUS_BEARER_TOKEN", "bearer-token-for-test-0123456789")
    monkeypatch.setenv("NEXUS_CHALLENGE_PBKDF2_ITERATIONS", "1000")

    from nexus.app import create_server

    app = build_http_app(create_server(host="0.0.0.0"), host="0.0.0.0", port=4508)
    with TestClient(app) as client:
        # Sensitive portal APIs must refuse unauthenticated callers
        assert client.get("/portal/api/fs/list").status_code == 401
        assert client.post("/portal/api/setup/env", json={}).status_code == 401
        assert client.post("/portal/api/pipeline/run", json={"mode": "tools"}).status_code == 401
        assert client.get("/portal/api/cases").status_code == 401

        # Traversal attempts on exempt paths must never bypass auth
        assert client.get("/portal/app/assets/../api/cases").status_code in (401, 403)
        assert client.get("/portal/login/../api/fs/list").status_code in (401, 403)

        # Browser navigation redirects to login; health & login stay reachable
        nav = client.get("/portal/app/", headers={"Accept": "text/html"}, follow_redirects=False)
        assert nav.status_code == 302
        assert nav.headers["location"].startswith("/portal/login")

        assert client.get("/health").status_code == 200
        assert client.get("/portal/login").status_code == 200
        status_before = client.get("/portal/api/auth/status").json()
        assert status_before == {"required": True, "configured": True, "authenticated": False}

        # Wrong password rejected without session cookie
        bad = client.post("/portal/api/auth/login", json={"password": "wrong-password"})
        assert bad.status_code == 401
        assert PORTAL_SESSION_COOKIE not in client.cookies

        # Correct password issues HttpOnly signed session cookie and unlocks portal APIs
        good = client.post(
            "/portal/api/auth/login",
            json={"password": "correct-horse-battery-staple"},
        )
        assert good.status_code == 200
        assert good.json()["ok"] is True
        assert PORTAL_SESSION_COOKIE in client.cookies

        status_after = client.get("/portal/api/auth/status").json()
        assert status_after["authenticated"] is True
        assert client.get("/portal/api/cases").status_code == 200
        assert client.get(f"/portal/api/fs/list?path={tmp_path}").status_code == 200

        # Logout clears cookie and re-locks endpoints
        assert client.post("/portal/api/auth/logout").status_code == 200
        assert client.get("/portal/api/cases").status_code == 401


def test_p0_1_html_login_flow_and_open_redirect_guard(monkeypatch):
    monkeypatch.setenv("NEXUS_AUDIT_SECRET", "audit-secret-for-test-0123456789")
    monkeypatch.setenv("NEXUS_PORTAL_PASSWORD", "portal-secret-pw")
    monkeypatch.setenv("NEXUS_CHALLENGE_PBKDF2_ITERATIONS", "1000")

    async def protected(_request):
        return JSONResponse({"ok": True})

    app = Starlette(
        routes=[Route("/portal/api/cases", protected, methods=["GET"])],
        middleware=[Middleware(PortalSessionMiddleware)],
    )
    with TestClient(app) as client:
        # Open-redirect payload in `next` must neutralize to /portal/app/
        res = client.post(
            "/portal/login",
            data={"password": "portal-secret-pw", "next": "//evil.example/phish"},
            follow_redirects=False,
        )
        assert res.status_code == 303
        assert res.headers["location"] == "/portal/app/"
        assert client.get("/portal/api/cases").status_code == 200


def test_p0_1_tampered_expired_and_rotated_cookies_rejected():
    async def protected(_request):
        return JSONResponse({"ok": True})

    mw_app = Starlette(
        routes=[Route("/portal/api/cases", protected, methods=["GET"])],
        middleware=[
            Middleware(
                PortalSessionMiddleware,
                password="first-password",
                secret="shared-signing-secret",
                ttl_seconds=10,
                pbkdf2_iterations=100,
            )
        ],
    )
    with TestClient(mw_app) as client:
        assert client.post("/portal/api/auth/login", json={"password": "first-password"}).status_code == 200
        cookie = client.cookies.get(PORTAL_SESSION_COOKIE, "")
        assert cookie

        # Tampered signature fails
        parts = cookie.split(".")
        tampered = ".".join([parts[0], parts[1], parts[2], ("0" * 64 if parts[3][0] != "0" else "f" * 64)])
        assert TestClient(mw_app, cookies={PORTAL_SESSION_COOKIE: tampered}).get("/portal/api/cases").status_code == 401

        # Password rotation with same audit secret invalidates old cookie immediately
        rotated_app = Starlette(
            routes=[Route("/portal/api/cases", protected, methods=["GET"])],
            middleware=[
                Middleware(
                    PortalSessionMiddleware,
                    password="second-password",
                    secret="shared-signing-secret",
                    ttl_seconds=10,
                    pbkdf2_iterations=100,
                )
            ],
        )
        assert TestClient(rotated_app, cookies={PORTAL_SESSION_COOKIE: cookie}).get("/portal/api/cases").status_code == 401

    # Expired TTL rejects token
    mw_direct = PortalSessionMiddleware(
        protected,
        password="pw",
        secret="s",
        ttl_seconds=1,
        pbkdf2_iterations=100,
    )
    tok, _ = mw_direct.issue_token(now=1000.0)
    assert mw_direct.verify_token(tok, now=1001.0) is True
    assert mw_direct.verify_token(tok, now=1002.0) is False


def test_p0_1_fail_closed_when_password_unset_and_loopback_no_regression(monkeypatch):
    monkeypatch.delenv(ENV_PORTAL_PASSWORD, raising=False)
    monkeypatch.setenv("NEXUS_AUDIT_SECRET", "s")
    monkeypatch.setenv("NEXUS_BEARER_TOKEN", "b")
    with pytest.raises(MissingProductionEnvError) as exc:
        check_required_env(host="0.0.0.0", port=4508)
    assert ENV_PORTAL_PASSWORD in str(exc.value)

    async def protected(_request):
        return JSONResponse({"ok": True})

    # Fail-closed direct middleware construction with empty password
    unconfigured = Starlette(
        routes=[Route("/portal/api/cases", protected, methods=["GET"])],
        middleware=[Middleware(PortalSessionMiddleware, password="", pbkdf2_iterations=100)],
    )
    with TestClient(unconfigured) as client:
        assert client.get("/portal/api/cases").status_code == 401
        assert client.post("/portal/api/auth/login", json={"password": ""}).status_code == 401

    # Loopback keeps zero regression
    from nexus.app import create_server

    loopback_app = build_http_app(create_server(host="127.0.0.1"), host="127.0.0.1", port=4508)
    with TestClient(loopback_app) as client:
        assert client.get("/portal/api/cases").status_code == 200
        assert client.get("/portal/").status_code == 200


# ---------------------------------------------------------------------------
# P0-2 / WP-AUD-02: Proxy-Aware X-Forwarded-For & Bounded Rate-Limit Buckets
# ---------------------------------------------------------------------------


def test_p0_2_untrusted_x_forwarded_for_ignored_and_auth_limit_applies():
    app = Starlette(
        routes=[
            Route("/portal/api/cases", lambda _r: JSONResponse({"ok": True})),
            Route("/portal/api/auth/login", lambda _r: JSONResponse({"ok": True}), methods=["POST"]),
        ],
        middleware=[
            Middleware(
                PortalRateLimitMiddleware,
                limit_per_minute=2,
                auth_limit_per_minute=1,
                path_prefix="/portal",
                auth_path_prefix=("/portal/api/commit", "/portal/api/auth"),
            )
        ],
    )
    with TestClient(app) as client:
        # Spoofed X-Forwarded-For values from an untrusted peer must share one bucket
        assert client.get("/portal/api/cases", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 200
        assert client.get("/portal/api/cases", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 200
        assert client.get("/portal/api/cases", headers={"X-Forwarded-For": "3.3.3.3"}).status_code == 429

        # Login path falls under auth_path_prefix stricter limit
        assert client.post("/portal/api/auth/login").status_code == 200
        assert client.post("/portal/api/auth/login").status_code == 429


def test_p0_2_trusted_proxy_peels_right_to_left_and_caps_buckets():
    mw = PortalRateLimitMiddleware(
        lambda scope, receive, send: None,  # type: ignore[arg-type]
        limit_per_minute=10,
        trusted_proxies=["10.0.0.0/8"],
        max_keys=3,
    )

    def _fake_req(peer_ip: str, xff: str = "") -> Request:
        headers = [(b"x-forwarded-for", xff.encode())] if xff else []
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/portal/api/cases",
            "headers": headers,
            "client": (peer_ip, 12345),
        }
        return Request(scope)

    # Attacker prepended 9.9.9.9, trusted proxy appended true client 198.51.100.42
    assert mw._client_ip(_fake_req("10.1.2.3", "9.9.9.9, 198.51.100.42, 10.0.0.5")) == "198.51.100.42"
    # Untrusted peer cannot spoof even when trusted_proxies is configured
    assert mw._client_ip(_fake_req("203.0.113.9", "198.51.100.42")) == "203.0.113.9"

    # Hard cap prevents unbounded dict growth
    now = time.time()
    for i in range(10):
        ip = f"198.51.100.{i + 1}"
        mw._sweep_and_bound(mw._hits, ip, now + i)
        mw._hits[ip].append(now + i)
    assert len(mw._hits) <= 3


# ---------------------------------------------------------------------------
# P0-3 / WP-AUD-03: Strict pipeline run_id Validation & Containment
# ---------------------------------------------------------------------------


def test_p0_3_pipeline_status_rejects_run_id_traversal(tmp_path: Path, monkeypatch):
    cases_root = tmp_path / "cases"
    case_dir = cases_root / "CASE-P03"
    runs_dir = case_dir / "analysis" / "pipeline_runs"
    runs_dir.mkdir(parents=True)
    # Secret JSON outside pipeline_runs
    secret = case_dir / "secret.json"
    secret.write_text(json.dumps({"secret": "do-not-leak"}), encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"outside": True}), encoding="utf-8")

    # Valid run record
    (runs_dir / "valid-run-01.json").write_text(
        json.dumps({"run_id": "valid-run-01", "mode": "tools", "status": "complete"}),
        encoding="utf-8",
    )

    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", cases_root)
    app = Starlette(routes=create_dashboard())
    with TestClient(app) as client:
        headers = {"X-Nexus-Case": "CASE-P03"}
        for payload in (
            "../secret",
            "../../secret",
            "../../../outside",
            "..\\..\\secret",
            "..",
            ".",
            "valid/../../secret",
            "a" * 129,
        ):
            resp = client.get("/portal/api/pipeline/status", params={"run_id": payload}, headers=headers)
            assert resp.status_code == 400, f"payload {payload!r} returned {resp.status_code}: {resp.text}"
            assert "do-not-leak" not in resp.text
            assert "outside" not in resp.text

        with pytest.raises(ValueError):
            _pipeline_run_status_path(case_dir, "../../secret")

        ok = client.get("/portal/api/pipeline/status", params={"run_id": "valid-run-01"}, headers=headers)
        assert ok.status_code == 200
        assert ok.json()["status"] == "complete"


# ---------------------------------------------------------------------------
# P0-4 / WP-AUD-04: validate_case_id() + Containment in Recovery Router
# ---------------------------------------------------------------------------


def test_p0_4_recovery_router_blocks_case_id_traversal(tmp_path: Path, monkeypatch):
    cases_root = tmp_path / "cases"
    case_a = cases_root / "CASE-AAA"
    (case_a / "extractions").mkdir(parents=True)
    # Sibling directory outside cases_root with recovery artifacts that must never be readable
    escape_dir = tmp_path / "SECRET-OUTSIDE"
    rb_dir = escape_dir / "extractions" / "RBCmd"
    rb_dir.mkdir(parents=True)
    (rb_dir / "20261112_RBCmd_Output.csv").write_text(
        "SourceFile,DeletedOn,OriginalPath,FileSize\n$I1,2026-11-12,C:\\secret.txt,10\n",
        encoding="utf-8",
    )

    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", cases_root)
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    (tmp_path / "active_case").write_text("CASE-AAA", encoding="utf-8")

    app = Starlette(routes=create_dashboard())
    with TestClient(app) as client:
        # Query param traversal attempts across recovery endpoints
        for endpoint in (
            "/portal/api/case/recovery/summary",
            "/portal/api/case/recovery/rdp",
            "/portal/api/case/recovery/thumbcache",
            "/portal/api/case/recovery/recycle-bin",
            "/portal/api/case/recovery/deleted-files",
            "/portal/api/case/recovery/export",
        ):
            for bad in ("../SECRET-OUTSIDE", "..\\SECRET-OUTSIDE", "CASE-AAA/../../SECRET-OUTSIDE"):
                r = client.get(endpoint, params={"case_id": bad})
                assert r.status_code == 404, f"{endpoint}?case_id={bad!r} -> {r.status_code}"

        # Encoded path param traversal (literal path segment with ../)
        r_path = client.get("/portal/api/case/..%2FSECRET-OUTSIDE/recovery/recycle-bin")
        assert r_path.status_code == 404

        # Symlink inside cases_root pointing outside cases_root must also fail containment
        symlink_case = cases_root / "CASE-SYM"
        try:
            symlink_case.symlink_to(escape_dir, target_is_directory=True)
        except OSError:
            pass
        else:
            r_sym = client.get("/portal/api/case/CASE-SYM/recovery/recycle-bin")
            assert r_sym.status_code == 404

        # Legitimate case works
        good = client.get("/portal/api/case/CASE-AAA/recovery/summary")
        assert good.status_code == 200
        assert good.json()["case_id"] == "CASE-AAA"
