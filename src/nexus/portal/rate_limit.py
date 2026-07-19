"""Per-IP rate limiting for the Examiner Portal."""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable
from typing import Any, cast

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class PortalRateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory per-IP sliding window with an optional path-prefix filter."""

    def __init__(
        self,
        app: Callable[..., Any],
        *,
        limit_per_minute: int = 120,
        auth_limit_per_minute: int = 30,
        window_seconds: float = 60.0,
        path_prefix: str = "/",
        auth_path_prefix: str = "/api/auth/",
    ) -> None:
        super().__init__(app)
        self._limit = max(1, limit_per_minute)
        self._auth_limit = max(1, auth_limit_per_minute)
        self._window = float(window_seconds)
        self._path_prefix = path_prefix
        self._auth_path_prefix = auth_path_prefix
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._auth_hits: dict[str, list[float]] = defaultdict(list)

    def _client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        if request.client:
            return request.client.host
        return "unknown"

    def _prune(self, bucket: dict[str, list[float]], key: str, now: float) -> None:
        cutoff = now - self._window
        bucket[key] = [t for t in bucket[key] if t > cutoff]

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        path = request.url.path
        if self._path_prefix != "/" and not path.startswith(self._path_prefix):
            return cast(Response, await call_next(request))

        now = time.time()
        ip = self._client_ip(request)
        is_auth = path.startswith(self._auth_path_prefix)
        bucket = self._auth_hits if is_auth else self._hits
        limit = self._auth_limit if is_auth else self._limit
        self._prune(bucket, ip, now)
        if len(bucket[ip]) >= limit:
            return JSONResponse({"error": "rate limit exceeded"}, status_code=429)
        bucket[ip].append(now)
        return cast(Response, await call_next(request))
