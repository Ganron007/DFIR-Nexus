"""Simple tests for the portal challenge and rate-limit modules."""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nexus.portal.challenge import ChallengeStore

STARLETTE_AVAILABLE = True
_import_error: Exception | None = None
try:
    from starlette.applications import Starlette
    from starlette.middleware import Middleware
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    from nexus.portal.rate_limit import PortalRateLimitMiddleware
    from nexus.portal.security import SecurityHeadersMiddleware
except ImportError as exc:  # pragma: no cover - starlette is optional
    STARLETTE_AVAILABLE = False
    _import_error = exc

passed = 0
failed = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {label}" + (f" - {detail}" if detail else ""))
    else:
        failed += 1
        print(f"  FAIL: {label}" + (f" - {detail}" if detail else ""))


def _client_proof(password: str, challenge: dict[str, str]) -> str:
    """Compute the expected HMAC proof for a challenge."""
    salt = bytes.fromhex(challenge["salt"])
    nonce = bytes.fromhex(challenge["nonce"])
    iterations = int(challenge["iterations"])
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return hmac.new(password_hash, nonce, hashlib.sha256).hexdigest()


def test_challenge_basic() -> None:
    store = ChallengeStore()
    challenge = store.create_challenge("super-secret")
    check(
        "create_challenge returns fields",
        all(k in challenge for k in ("challenge_id", "nonce", "salt", "iterations")),
    )

    proof = _client_proof("super-secret", challenge)
    check("valid proof accepted", store.verify_response(challenge["challenge_id"], proof))
    check(
        "challenge consumed after success",
        not store.verify_response(challenge["challenge_id"], proof),
    )

    challenge2 = store.create_challenge("super-secret")
    check(
        "invalid proof rejected",
        not store.verify_response(challenge2["challenge_id"], "deadbeef"),
    )
    check("unknown challenge rejected", not store.verify_response("invalid-id", proof))


def test_challenge_expiry_and_purge() -> None:
    store = ChallengeStore(challenge_ttl=0)
    challenge = store.create_challenge("pw")
    time.sleep(0.01)
    check(
        "expired challenge rejected",
        not store.verify_response(challenge["challenge_id"], "aabb"),
    )
    # Purge should remove any expired record that is still present.
    store2 = ChallengeStore(challenge_ttl=0)
    store2.create_challenge("pw")
    time.sleep(0.01)
    check("purge_expired removes record", store2.purge_expired() == 1)


def test_challenge_custom_iterations() -> None:
    store = ChallengeStore(pbkdf2_iterations=100_000)
    challenge = store.create_challenge("pw")
    check("custom iterations returned", challenge["iterations"] == "100000")


def _hello_app() -> Starlette:
    async def ok(request):  # noqa: ARG001
        return PlainTextResponse("ok")

    return Starlette(routes=[Route("/", ok)])


if STARLETTE_AVAILABLE:

    def test_rate_limit_general() -> None:
        app = Starlette(
            routes=[Route("/portal", lambda r: PlainTextResponse("ok"))],
            middleware=[
                Middleware(
                    PortalRateLimitMiddleware,
                    limit_per_minute=2,
                    auth_limit_per_minute=1,
                    path_prefix="/portal",
                )
            ],
        )
        client = TestClient(app)
        check("rate limit pass 1", client.get("/portal").status_code == 200)
        check("rate limit pass 2", client.get("/portal").status_code == 200)
        check("rate limit block 3", client.get("/portal").status_code == 429)

    def test_rate_limit_auth_stricter() -> None:
        app = Starlette(
            routes=[Route("/api/auth/login", lambda r: PlainTextResponse("ok"))],
            middleware=[
                Middleware(
                    PortalRateLimitMiddleware,
                    limit_per_minute=10,
                    auth_limit_per_minute=1,
                    path_prefix="/",
                )
            ],
        )
        client = TestClient(app)
        check("auth pass 1", client.get("/api/auth/login").status_code == 200)
        check("auth block 2", client.get("/api/auth/login").status_code == 429)

    def test_rate_limit_path_prefix() -> None:
        app = Starlette(
            routes=[
                Route("/portal", lambda r: PlainTextResponse("ok")),
                Route("/mcp", lambda r: PlainTextResponse("ok")),
            ],
            middleware=[
                Middleware(
                    PortalRateLimitMiddleware,
                    limit_per_minute=1,
                    path_prefix="/portal",
                )
            ],
        )
        client = TestClient(app)
        check("portal limited", client.get("/portal").status_code == 200)
        check("portal second blocked", client.get("/portal").status_code == 429)
        check("mcp not limited", client.get("/mcp").status_code == 200)

    def test_security_headers() -> None:
        app = Starlette(
            routes=[
                Route("/portal", lambda r: PlainTextResponse("ok")),
                Route("/mcp", lambda r: PlainTextResponse("ok")),
            ],
            middleware=[Middleware(SecurityHeadersMiddleware, path_prefix="/portal")],
        )
        client = TestClient(app)
        r1 = client.get("/portal")
        r2 = client.get("/mcp")
        check(
            "security headers on portal",
            r1.headers.get("X-Frame-Options") == "DENY"
            and r1.headers.get("Referrer-Policy") == "no-referrer",
        )
        check("security headers not on mcp", "X-Frame-Options" not in r2.headers)


if __name__ == "__main__":
    test_challenge_basic()
    test_challenge_expiry_and_purge()
    test_challenge_custom_iterations()
    if STARLETTE_AVAILABLE:
        test_rate_limit_general()
        test_rate_limit_auth_stricter()
        test_rate_limit_path_prefix()
        test_security_headers()
    else:
        print(f"  SKIP: starlette not installed ({_import_error}) — rate-limit/header tests skipped")
    print()
    print(f"=== {passed} PASSED, {failed} FAILED ===")
    sys.exit(0 if failed == 0 else 1)
