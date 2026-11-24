"""Signed session cookie authentication for the Examiner Portal (WP-AUD-01 / P0-1)."""

from __future__ import annotations

import hashlib
import hmac
import html
import logging
import os
import secrets
import time
from collections.abc import Callable
from typing import Any, cast
from urllib.parse import parse_qs, quote

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from nexus.utils.constants import (
    DEFAULT_PORTAL_SESSION_TTL,
    ENV_AUDIT_SECRET,
    ENV_PORTAL_PASSWORD,
    ENV_PORTAL_SESSION_TTL,
)

logger = logging.getLogger(__name__)

PORTAL_SESSION_COOKIE = "nexus_portal_session"
_DEFAULT_PBKDF2_ITERATIONS = 600_000
_MIN_PORTAL_TTL = 60


def portal_password() -> str:
    """Return the configured Examiner Portal password, or ``""`` when unset."""
    return os.environ.get(ENV_PORTAL_PASSWORD, "").strip()


def portal_signing_secret() -> str:
    """Return the configured HMAC signing secret, or ``""`` when unset."""
    return os.environ.get(ENV_AUDIT_SECRET, "").strip()


def portal_session_ttl() -> int:
    """Return portal session TTL in seconds (env ``NEXUS_PORTAL_SESSION_TTL``)."""
    raw = os.environ.get(ENV_PORTAL_SESSION_TTL, "").strip()
    if not raw:
        return DEFAULT_PORTAL_SESSION_TTL
    try:
        parsed = int(raw)
    except ValueError:
        return DEFAULT_PORTAL_SESSION_TTL
    return parsed if parsed >= 1 else DEFAULT_PORTAL_SESSION_TTL


def _is_public_portal_path(path: str) -> bool:
    """Return True only for unauthenticated login/auth and static SPA asset paths."""
    if ".." in path or "\\" in path:
        return False
    if path in (
        "/portal/login",
        "/portal/api/auth/login",
        "/portal/api/auth/logout",
        "/portal/api/auth/status",
        "/portal/app/logo.svg",
    ):
        return True
    return path.startswith("/portal/app/assets/")


def _safe_next_url(candidate: str | None) -> str:
    """Sanitize post-login redirect targets to internal ``/portal`` paths."""
    target = (candidate or "").strip()
    if (
        not target
        or not target.startswith("/portal")
        or target.startswith("//")
        or "\\" in target
        or "\r" in target
        or "\n" in target
    ):
        return "/portal/app/"
    return target


def _wants_html(request: Request) -> bool:
    path = request.url.path
    if path.startswith("/portal/api/"):
        return False
    accept = (request.headers.get("accept") or "").lower()
    return "text/html" in accept or "application/xhtml+xml" in accept


def _render_login_html(next_url: str, error: str = "") -> str:
    err_block = (
        f"<div class='err' role='alert'>{html.escape(error)}</div>"
        if error
        else ""
    )
    safe_next = html.escape(_safe_next_url(next_url), quote=True)
    return (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>DFIR-Nexus — Portal Sign In</title>"
        "<style>"
        "body{margin:0;background:#0d1117;color:#e6edf3;font-family:system-ui,-apple-system,sans-serif;"
        "display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}"
        ".card{width:100%;max-width:400px;background:#161b22;border:1px solid #30363d;"
        "border-radius:10px;padding:28px;box-shadow:0 8px 24px rgba(0,0,0,.4)}"
        "h1{margin:0 0 8px;font-size:20px;font-weight:600}"
        "p{margin:0 0 20px;color:#8b949e;font-size:14px;line-height:1.4}"
        "label{display:block;font-size:13px;font-weight:500;margin-bottom:6px}"
        "input[type=password]{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:6px;"
        "border:1px solid #30363d;background:#0d1117;color:#e6edf3;font-size:14px;margin-bottom:16px}"
        "button{width:100%;padding:10px 14px;border:0;border-radius:6px;background:#238636;"
        "color:#fff;font-size:14px;font-weight:600;cursor:pointer}"
        "button:hover{background:#2ea043}"
        ".err{margin-bottom:14px;padding:10px 12px;border-radius:6px;background:rgba(248,81,73,.12);"
        "border:1px solid rgba(248,81,73,.4);color:#ffa198;font-size:13px}"
        "</style></head><body><main class='card'>"
        "<h1>DFIR-Nexus Examiner Portal</h1>"
        "<p>Sign in with the configured portal password to access investigation desks.</p>"
        f"{err_block}"
        "<form method='post' action='/portal/login'>"
        f"<input type='hidden' name='next' value='{safe_next}'>"
        "<label for='portal-password'>Portal Password</label>"
        "<input id='portal-password' name='password' type='password' autocomplete='current-password' required autofocus>"
        "<button type='submit'>Sign in</button>"
        "</form></main></body></html>"
    )


class PortalSessionMiddleware(BaseHTTPMiddleware):
    """Require a signed ``HttpOnly`` session cookie on all ``/portal/**`` routes.

    Exempts only ``/portal/login``, ``/portal/api/auth/*``, and static SPA assets
    (``/portal/app/assets/**``, ``/portal/app/logo.svg``). Fails closed when the
    portal password is unset so remote misconfiguration never exposes case data.
    """

    def __init__(
        self,
        app: Callable[..., Any],
        *,
        password: str | None = None,
        secret: str | None = None,
        ttl_seconds: int | None = None,
        pbkdf2_iterations: int | None = None,
    ) -> None:
        super().__init__(app)
        resolved_pw = portal_password() if password is None else password.strip()
        resolved_secret = portal_signing_secret() if secret is None else secret.strip()
        self._ttl = portal_session_ttl() if ttl_seconds is None else max(1, int(ttl_seconds))
        self._iterations = (
            int(os.environ.get("NEXUS_CHALLENGE_PBKDF2_ITERATIONS", str(_DEFAULT_PBKDF2_ITERATIONS)))
            if pbkdf2_iterations is None
            else max(1, int(pbkdf2_iterations))
        )
        self._has_password = bool(resolved_pw)
        self._salt = secrets.token_bytes(16)
        if resolved_pw:
            pw_bytes = resolved_pw.encode("utf-8")
            self._password_hash: bytes | None = hashlib.pbkdf2_hmac(
                "sha256", pw_bytes, self._salt, self._iterations
            )
            pw_tag = hashlib.sha256(pw_bytes).digest()
        else:
            self._password_hash = None
            pw_tag = b""
        base_secret = (
            resolved_secret.encode("utf-8")
            if resolved_secret
            else secrets.token_bytes(32)
        )
        # Bind cookie MAC key to the configured password hash so rotating
        # NEXUS_PORTAL_PASSWORD invalidates existing sessions immediately.
        self._signing_key = hmac.new(
            base_secret, b"nexus-portal-session-v1:" + pw_tag, hashlib.sha256
        ).digest()

    def verify_password(self, candidate: str) -> bool:
        """Verify ``candidate`` using PBKDF2-HMAC-SHA256 + constant-time compare."""
        if not self._has_password or self._password_hash is None or not candidate:
            return False
        derived = hashlib.pbkdf2_hmac(
            "sha256", candidate.encode("utf-8"), self._salt, self._iterations
        )
        return hmac.compare_digest(derived, self._password_hash)

    def issue_token(self, *, now: float | None = None) -> tuple[str, int]:
        """Create a signed session cookie value and return ``(token, expires_at)``."""
        issued = int(time.time() if now is None else now)
        expires = issued + self._ttl
        nonce = secrets.token_hex(16)
        payload = f"{issued}.{expires}.{nonce}"
        sig = hmac.new(self._signing_key, payload.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{payload}.{sig}", expires

    def verify_token(self, token: str, *, now: float | None = None) -> bool:
        """Validate cookie format, HMAC signature, and expiration."""
        if not self._has_password or not token:
            return False
        parts = token.split(".")
        if len(parts) != 4:
            return False
        issued_s, expires_s, nonce, sig_hex = parts
        if not (issued_s.isdigit() and expires_s.isdigit() and len(nonce) == 32 and len(sig_hex) == 64):
            return False
        try:
            bytes.fromhex(nonce)
            bytes.fromhex(sig_hex)
        except ValueError:
            return False
        payload = f"{issued_s}.{expires_s}.{nonce}"
        expected = hmac.new(self._signing_key, payload.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig_hex, expected):
            return False
        current = time.time() if now is None else now
        return current <= int(expires_s)

    def _set_session_cookie(self, response: Response, request: Request, token: str) -> None:
        is_https = request.url.scheme == "https"
        response.set_cookie(
            key=PORTAL_SESSION_COOKIE,
            value=token,
            max_age=self._ttl,
            path="/portal",
            httponly=True,
            samesite="lax",
            secure=is_https,
        )

    async def _handle_login(self, request: Request, *, html_flow: bool) -> Response:
        if not self._has_password:
            return JSONResponse(
                {"error": "portal authentication unavailable: NEXUS_PORTAL_PASSWORD not configured"},
                status_code=401,
            )
        password = ""
        next_url = _safe_next_url(request.query_params.get("next"))
        ctype = (request.headers.get("content-type") or "").lower()
        raw_body = await request.body()
        if "application/json" in ctype:
            import json

            try:
                data = json.loads(raw_body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                data = {}
            if isinstance(data, dict):
                password = str(data.get("password") or "")
                if data.get("next"):
                    next_url = _safe_next_url(str(data.get("next")))
        else:
            parsed = parse_qs(raw_body.decode("utf-8", errors="replace"), keep_blank_values=True)
            password = (parsed.get("password") or [""])[0]
            if parsed.get("next"):
                next_url = _safe_next_url(parsed["next"][0])

        if not self.verify_password(password):
            if html_flow:
                return HTMLResponse(_render_login_html(next_url, "Invalid portal password."), status_code=401)
            return JSONResponse({"error": "invalid portal password"}, status_code=401)

        token, expires_at = self.issue_token()
        if html_flow:
            resp: Response = RedirectResponse(url=next_url, status_code=303)
        else:
            resp = JSONResponse({"ok": True, "expires_at": expires_at, "ttl": self._ttl})
        self._set_session_cookie(resp, request, token)
        return resp

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        path = request.url.path
        if not (path == "/portal" or path.startswith("/portal/")):
            return cast(Response, await call_next(request))

        # Traversal in any /portal path never bypasses authentication.
        if ".." in path or "\\" in path:
            return JSONResponse({"error": "forbidden"}, status_code=403)

        if path == "/portal/login":
            if request.method == "POST":
                return await self._handle_login(request, html_flow=True)
            if not self._has_password:
                return HTMLResponse(
                    _render_login_html("/portal/app/", "Portal authentication unavailable: NEXUS_PORTAL_PASSWORD is not configured."),
                    status_code=401,
                )
            next_url = _safe_next_url(request.query_params.get("next"))
            cookie = request.cookies.get(PORTAL_SESSION_COOKIE, "")
            if self.verify_token(cookie):
                return RedirectResponse(url=next_url, status_code=302)
            return HTMLResponse(_render_login_html(next_url))

        if path == "/portal/api/auth/login" and request.method == "POST":
            return await self._handle_login(request, html_flow=False)

        if path == "/portal/api/auth/logout" and request.method == "POST":
            resp = JSONResponse({"ok": True})
            resp.delete_cookie(key=PORTAL_SESSION_COOKIE, path="/portal")
            return resp

        if path == "/portal/api/auth/status" and request.method == "GET":
            cookie = request.cookies.get(PORTAL_SESSION_COOKIE, "")
            return JSONResponse(
                {
                    "required": True,
                    "configured": self._has_password,
                    "authenticated": self.verify_token(cookie),
                }
            )

        if _is_public_portal_path(path):
            return cast(Response, await call_next(request))

        cookie = request.cookies.get(PORTAL_SESSION_COOKIE, "")
        if self.verify_token(cookie):
            return cast(Response, await call_next(request))

        if _wants_html(request):
            target = _safe_next_url(path + (f"?{request.url.query}" if request.url.query else ""))
            return RedirectResponse(url=f"/portal/login?next={quote(target, safe='/')}", status_code=302)
        return JSONResponse(
            {"error": "unauthorized", "detail": "portal authentication required"},
            status_code=401,
        )
