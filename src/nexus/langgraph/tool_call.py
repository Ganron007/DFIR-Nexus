"""Client-side guard for MCP tool calls.

The MCP transport carries a timeout for the *tool's* own work: ``timeout`` is
handed to the tool, which kills its subprocess when the budget expires. It
carries **none for the transport itself**. If the server process dies, the
streamable-HTTP session drops mid-request, or a stdio child exits, ``ainvoke``
never returns — no error, no progress, no output.

A pipeline that hangs is worse than one that fails. It burns the operator's
session, holds the run record at ``running``, and reports nothing at all.

``call_tool`` bounds the whole round-trip: the tool's own budget plus a margin
for transport and serialisation. On expiry it raises :class:`ToolCallTimeout`
naming the tool and the budget, so the lane records a real FAIL reason with the
tool call it was waiting on instead of waiting forever.

Budgets are deliberately generous — a false timeout on a long forensic parse is
its own defect. The margin exists to catch a *dead* transport, not a slow tool.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

#: Round-trip budget used when a call declares no tool timeout of its own
#: (control calls: case_init, case_activate, listing tools).
DEFAULT_CALL_TIMEOUT_S = 300.0

#: Added on top of the tool's own budget. Covers request serialisation, the
#: server's queueing, and the response body for large artifact listings.
DEFAULT_MARGIN_S = 120.0

#: Never issue a round-trip budget below this, so a tiny declared timeout
#: cannot turn a healthy call into a spurious transport failure.
MIN_CALL_TIMEOUT_S = 30.0


class ToolCallTimeout(RuntimeError):
    """An MCP tool call exceeded its client-side transport budget."""


def call_timeout(tool_timeout: float | None) -> float:
    """Round-trip budget for one call.

    ``tool_timeout`` is the budget handed *to the tool* (its subprocess kill
    time). ``None`` means the call declares none, so the transport default
    applies. Override the defaults with ``NEXUS_MCP_CALL_TIMEOUT`` and
    ``NEXUS_MCP_CALL_MARGIN``.
    """
    if tool_timeout is None:
        try:
            return max(
                float(os.environ.get("NEXUS_MCP_CALL_TIMEOUT", DEFAULT_CALL_TIMEOUT_S)),
                MIN_CALL_TIMEOUT_S,
            )
        except (TypeError, ValueError):
            return DEFAULT_CALL_TIMEOUT_S
    try:
        base = float(tool_timeout)
    except (TypeError, ValueError):
        base = 0.0
    try:
        margin = float(os.environ.get("NEXUS_MCP_CALL_MARGIN", DEFAULT_MARGIN_S))
    except (TypeError, ValueError):
        margin = DEFAULT_MARGIN_S
    return max(base + margin, MIN_CALL_TIMEOUT_S)


async def call_tool(
    tool: Any,
    payload: dict[str, Any],
    *,
    timeout: float | None = None,
    label: str = "",
) -> Any:
    """Invoke an MCP tool with a bounded round-trip.

    Returns the tool's raw response. Raises :class:`ToolCallTimeout` when the
    transport does not answer within the budget — the caller records that as a
    failed step naming the tool it was waiting on.
    """
    budget = call_timeout(timeout)
    try:
        return await asyncio.wait_for(tool.ainvoke(payload), timeout=budget)
    except TimeoutError as exc:
        name = label or str(getattr(tool, "name", "") or "tool")
        declared = f"{timeout:g}s" if isinstance(timeout, (int, float)) else "none"
        raise ToolCallTimeout(
            f"{name} did not answer within {budget:.0f}s "
            f"(tool budget {declared} + transport margin) — "
            "the MCP transport is unresponsive"
        ) from exc
