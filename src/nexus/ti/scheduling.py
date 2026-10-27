"""Provider admission, documented pacing and bounded retry; no result cache."""
from __future__ import annotations

import asyncio
import math
import threading
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from nexus.ti.constants import TI_IOC_WORKERS, TI_LOOKUP_TIMEOUT_SECONDS, TI_PROVIDER_POLICIES
from nexus.ti.schemas import TIResult


@dataclass
class _Pace:
    active: int = 0
    next_start: float = 0.0
    waiters: list[tuple[asyncio.AbstractEventLoop, asyncio.Event]] = field(default_factory=list)


_lock = threading.Lock()
_pacing: dict[tuple[str, str], _Pace] = {}


def _state(key: tuple[str, str]) -> _Pace:
    with _lock:
        return _pacing.setdefault(key, _Pace())


@asynccontextmanager
async def _provider_slot(key: tuple[str, str], limit: int):
    state = _state(key)
    loop = asyncio.get_running_loop()
    while True:
        with _lock:
            if state.active < limit:
                state.active += 1
                break
            event = asyncio.Event()
            waiter = (loop, event)
            state.waiters.append(waiter)
        try:
            await event.wait()
        except BaseException:
            with _lock:
                state.waiters = [item for item in state.waiters if item is not waiter]
            raise
    try:
        yield state
    finally:
        with _lock:
            state.active -= 1
            waiters, state.waiters = state.waiters, []
        for waiting_loop, event in waiters:
            if not waiting_loop.is_closed():
                try:
                    waiting_loop.call_soon_threadsafe(event.set)
                except RuntimeError:
                    if not waiting_loop.is_closed():
                        raise


async def _request_turn(state: _Pace, interval: float, deadline: float | None = None) -> bool:
    while True:
        with _lock:
            now = time.monotonic()
            wait = max(0.0, state.next_start - now)
            if deadline is not None and (now >= deadline or wait >= deadline - now):
                return False
            if wait <= 0:
                state.next_start = now + interval
                return True
        await asyncio.sleep(wait)


def _defer(state: _Pace, seconds: float) -> None:
    with _lock:
        state.next_start = max(state.next_start, time.monotonic() + seconds)


def _retry_after(value: str | None) -> float | None:
    if not value:
        return None
    try:
        delay = float(value)
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
            delay = (when - datetime.now(UTC)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return None
    return max(0.0, delay) if math.isfinite(delay) else None


def _with_history(result: TIResult, failures: list[dict]) -> TIResult:
    if failures:
        result.raw = {**result.raw, "nexus_attempt_failures": list(failures)}
    return result


async def run_provider_lookup(
    provider: str,
    account: str,
    request: Callable[[], Awaitable[TIResult]],
    on_error: Callable[[Exception], TIResult],
) -> TIResult:
    policy = TI_PROVIDER_POLICIES.get(provider)
    interval = (policy.period_seconds / policy.requests
                if policy and policy.requests and policy.period_seconds else 0.0)
    limit = TI_IOC_WORKERS if interval else 1
    retry_limit = policy.retry_limit if policy and policy.retry_limit else 1  # Operator: one header-driven retry.
    failures: list[dict] = []
    async with _provider_slot((provider, account), limit) as state:
        # Queueing honors an earlier server cooldown. Once admitted, the
        # provider work/retries share the existing bounded timeout, never a
        # larger per-attempt or total network-work timeout.
        await _request_turn(state, interval)
        deadline = time.monotonic() + TI_LOOKUP_TIMEOUT_SECONDS
        for attempt in range(retry_limit + 1):
            remaining = deadline - time.monotonic()
            try:
                if remaining <= 0:
                    raise TimeoutError("provider lookup exhausted its unchanged timeout")
                async with asyncio.timeout(remaining):
                    result = await request()
            except TimeoutError:
                result = on_error(TimeoutError("provider lookup exhausted its unchanged timeout"))
            if result.status != "error":
                return _with_history(result, failures)
            detail = result.raw.get("nexus_failure") or {}
            status = detail.get("http_status")
            failures.append({"provider": result.provider, "ioc": result.value,
                             "attempt": attempt + 1, "reason": result.error,
                             "http_status": status, "retry_after": detail.get("retry_after")})
            retryable_status = isinstance(status, int) and (status == 429 or 500 <= status <= 599)
            delay = _retry_after(detail.get("retry_after")) if retryable_status else None
            if delay is None and policy and status in policy.retry_statuses and policy.backoff_factor is not None:
                # urllib3 Retry used by the vendor SDK: no delay on the first
                # retry, then factor * 2**(consecutive_errors - 1).
                delay = 0.0 if attempt == 0 else policy.backoff_factor * (2 ** attempt)
            if delay is not None:
                _defer(state, delay)
            if delay is None or attempt >= retry_limit:
                return _with_history(result, failures)
            if not await _request_turn(state, interval, deadline):
                result.raw = {**result.raw, "retry_not_attempted_reason":
                              "documented delay exceeds the remaining unchanged lookup timeout"}
                return _with_history(result, failures)
    raise AssertionError("provider retry loop returned no result")
