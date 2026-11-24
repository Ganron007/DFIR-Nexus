"""Per-IP rate limiting for the Examiner Portal."""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from typing import Any, cast

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from nexus.utils.constants import ENV_TRUSTED_PROXIES

logger = logging.getLogger(__name__)
_IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.environ.get(name, "") or default).strip())
    except (TypeError, ValueError):
        return default


def _parse_trusted_proxies(raw: Iterable[str] | str | None) -> tuple[_IPNetwork, ...]:
    if raw is None:
        raw = os.environ.get(ENV_TRUSTED_PROXIES, "")
    items = raw.split(",") if isinstance(raw, str) else list(raw)
    nets: list[_IPNetwork] = []
    for item in items:
        text = str(item).strip()
        if not text:
            continue
        try:
            nets.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid NEXUS_TRUSTED_PROXIES entry: %r", text)
    return tuple(nets)


class PortalRateLimitMiddleware(BaseHTTPMiddleware):
    """In-memory per-IP sliding window with proxy-aware IP and bounded buckets.

    Defaults are configurable so a busy local SPA (and the E2E suite) do not
    trip the safety net: ``NEXUS_PORTAL_RATE_LIMIT`` / ``NEXUS_PORTAL_AUTH_RATE_LIMIT``.
    ``X-Forwarded-For`` is honored only when the immediate peer belongs to
    ``NEXUS_TRUSTED_PROXIES`` (or ``trusted_proxies``).
    """

    def __init__(
        self,
        app: Callable[..., Any],
        *,
        limit_per_minute: int | None = None,
        auth_limit_per_minute: int | None = None,
        window_seconds: float = 60.0,
        path_prefix: str = "/",
        auth_path_prefix: str | tuple[str, ...] = "/api/auth/",
        trusted_proxies: Iterable[str] | str | None = None,
        max_keys: int = 10_000,
    ) -> None:
        super().__init__(app)
        if limit_per_minute is None:
            limit_per_minute = _env_int("NEXUS_PORTAL_RATE_LIMIT", 600)
        if auth_limit_per_minute is None:
            auth_limit_per_minute = _env_int("NEXUS_PORTAL_AUTH_RATE_LIMIT", 60)
        self._limit = max(1, limit_per_minute)
        self._auth_limit = max(1, auth_limit_per_minute)
        self._window = float(window_seconds)
        self._path_prefix = path_prefix
        self._auth_prefixes = (
            (auth_path_prefix,)
            if isinstance(auth_path_prefix, str)
            else tuple(auth_path_prefix)
        )
        self._trusted_proxies = _parse_trusted_proxies(trusted_proxies)
        self._max_keys = max(1, int(max_keys))
        self._hits: dict[str, list[float]] = defaultdict(list)
        self._auth_hits: dict[str, list[float]] = defaultdict(list)

    def _is_trusted_proxy(self, ip_text: str) -> bool:
        if not self._trusted_proxies or not ip_text:
            return False
        try:
            addr = ipaddress.ip_address(ip_text)
        except ValueError:
            return False
        return any(addr in net for net in self._trusted_proxies)

    def _client_ip(self, request: Request) -> str:
        peer = request.client.host if request.client else ""
        if self._is_trusted_proxy(peer):
            forwarded = request.headers.get("x-forwarded-for") or ""
            parts = [p.strip() for p in forwarded.split(",") if p.strip()]
            # Walk right-to-left skipping known trusted hops so a spoofed
            # leftmost header supplied by the client cannot bypass limits.
            for candidate in reversed(parts):
                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    continue
                if not self._is_trusted_proxy(candidate):
                    return candidate
            for candidate in reversed(parts):
                try:
                    ipaddress.ip_address(candidate)
                    return candidate
                except ValueError:
                    continue
        return peer or "unknown"

    def _prune(self, bucket: dict[str, list[float]], key: str, now: float) -> None:
        cutoff = now - self._window
        fresh = [t for t in bucket.get(key, ()) if t > cutoff]
        if fresh:
            bucket[key] = fresh
        else:
            bucket.pop(key, None)

    def _sweep_and_bound(self, bucket: dict[str, list[float]], incoming_key: str, now: float) -> None:
        if incoming_key in bucket or len(bucket) < self._max_keys:
            return
        cutoff = now - self._window
        stale_keys = [k for k, ts_list in bucket.items() if not any(t > cutoff for t in ts_list)]
        for k in stale_keys:
            bucket.pop(k, None)
        while len(bucket) >= self._max_keys:
            oldest_key = min(bucket, key=lambda k: bucket[k][-1] if bucket[k] else 0.0)
            bucket.pop(oldest_key, None)

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        path = request.url.path
        if self._path_prefix != "/" and not path.startswith(self._path_prefix):
            return cast(Response, await call_next(request))

        now = time.time()
        ip = self._client_ip(request)
        is_auth = any(path.startswith(prefix) for prefix in self._auth_prefixes)
        bucket = self._auth_hits if is_auth else self._hits
        limit = self._auth_limit if is_auth else self._limit
        self._prune(bucket, ip, now)
        if len(bucket.get(ip, ())) >= limit:
            return JSONResponse({"error": "rate limit exceeded"}, status_code=429)
        self._sweep_and_bound(bucket, ip, now)
        bucket[ip].append(now)
        return cast(Response, await call_next(request))
