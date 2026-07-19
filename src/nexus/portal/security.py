"""Security-headers middleware for the Examiner Portal."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

DEFAULT_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'"
    ),
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to responses, optionally limited by path prefix."""

    def __init__(
        self,
        app: Callable[..., Any],
        *,
        headers: dict[str, str] | None = None,
        path_prefix: str = "/",
    ) -> None:
        super().__init__(app)
        self._headers = DEFAULT_SECURITY_HEADERS if headers is None else dict(headers)
        self._path_prefix = path_prefix

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        response = cast(Response, await call_next(request))
        if self._path_prefix == "/" or request.url.path.startswith(self._path_prefix):
            for key, value in self._headers.items():
                response.headers[key] = value
        return response
