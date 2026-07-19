"""Tests for nexus.utils.async_utils."""

from __future__ import annotations

import asyncio

import pytest

from nexus.utils.async_utils import run_async


async def _coro(value: str) -> str:
    return f"result-{value}"


def test_run_async_no_event_loop() -> None:
    assert run_async(_coro("x")) == "result-x"


async def _use_run_async() -> str:
    return run_async(_coro("nested"))


def test_run_async_inside_running_loop() -> None:
    result = asyncio.run(_use_run_async())
    assert result == "result-nested"


async def _raising_coro() -> str:
    raise ValueError("boom")


def test_run_async_propagates_exception() -> None:
    with pytest.raises(ValueError, match="boom"):
        run_async(_raising_coro())
