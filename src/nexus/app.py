"""Unified DFIR-Nexus MCP server.

Platform-aware: registers only tools available on the current machine.
On Linux/SIFT: SIFT forensic tools, case management, RAG, triage, OpenCTI.
On Windows: Windows forensic tools (Zimmerman, Sysinternals, KAPE).

For multi-machine setups, run on each machine and configure the LLM
client to connect to all instances via `nexus setup client`.

Supports two transport modes:
  - stdio: LLM client spawns nexus as a subprocess (zero config)
  - http:  Standalone HTTP server on :4508 (multi-client, web dashboard)

Usage:
    nexus serve                # stdio mode (local LLM)
    nexus serve --http         # HTTP mode on :4508
    nexus serve --http --port 8080

Multi-machine:
    # On SIFT (Linux):
    nexus serve --http --host 0.0.0.0 --port 4508
    # On Windows examiner host:
    nexus setup client --sift http://192.168.77.135:4508/mcp
"""

import logging
import sys

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter

logger = logging.getLogger(__name__)

_IS_LINUX = sys.platform == "linux"
_IS_WINDOWS = sys.platform == "win32"

_INSTRUCTIONS = """
DFIR-Nexus is a unified digital forensic investigation platform.

INVESTIGATION WORKFLOW
1. case_init("Case Name")       — create a case
2. evidence_register(path)      — hash evidence, establish chain of custody
3. ingest_auto / run_command    — analyze evidence (auto-detect parser or direct tool)
4. record_finding(title, ...)   — stage finding as DRAFT
5. record_timeline_event(...)   — chronological narrative
6. nexus approve                — human reviews and APPROVES/REJECTS
7. generate_report(profile)     — produce IR report from approved findings

HUMAN-IN-THE-LOOP
All findings stage as DRAFT. Only a human examiner can approve them
via the CLI (nexus approve) or the Examiner Portal. The AI cannot
approve its own findings — this is structural, not optional.

PROVENANCE
Every tool execution is audit-logged with SHA-256 hashes. Findings
must reference audit_id values from the audit log.
"""


# ── WO-1 (D46): sync tools run in worker threads, never on the serving loop ──
# The MCP SDK invokes sync tool functions inline on the serving event loop
# (mcp 1.26 func_metadata: `return fn(**args)`) - one slow tool froze the whole
# portal (measured > 900 s) and silently serialized parallel tool calls.
import functools as _functools
import inspect as _inspect
import threading as _threading

import anyio as _anyio

#: Case-file writers: read-modify-write on flat JSON / CASE.yaml (or their
#: SQLite mirrors). The blocked loop used to serialize these by accident; once
#: tools run in worker threads they must keep that serialization explicitly or
#: two concurrent writers can lose an update. Long exec/read tools
#: (run_windows_command, run_command, ingest_auto, convert_pcap, forensic_rag_*,
#: triage checks, TI/web/VR) deliberately do NOT take this lock.
_CASE_WRITER_TOOLS = frozenset({
    "record_finding",
    "record_timeline_event",
    "add_todo",
    "update_todo",
    "complete_todo",
    "evidence_register",
    "record_action",
    "case_init",
    "case_activate",
    "case_close",
    "import_case",
    "set_case_metadata",
    "generate_report",
})
_case_write_lock = _threading.Lock()


def _mcp_offload_tool(fn):
    """Wrap a sync tool so it executes in a worker thread (WO-1)."""
    if _inspect.iscoroutinefunction(fn):
        return fn

    @_functools.wraps(fn)
    async def _async(*args, **kwargs):
        call = _functools.partial(fn, *args, **kwargs)
        if fn.__name__ in _CASE_WRITER_TOOLS:

            def _locked():
                with _case_write_lock:
                    return call()

            return await _anyio.to_thread.run_sync(_locked)
        return await _anyio.to_thread.run_sync(call)

    return _async


def apply_tool_offload(server) -> None:
    """Wrap ``server.tool`` so every sync tool registers off-loop (WO-1/D46).

    Enabled by default; ``NEXUS_MCP_TOOL_OFFLOAD=0`` restores the old inline
    behaviour (used by tests to compare tool schemas). Signature/docstring are
    preserved via ``functools.wraps`` (``inspect.signature`` follows
    ``__wrapped__``), so the SDK builds the same argument model.
    """
    import os as _os

    if _os.environ.get("NEXUS_MCP_TOOL_OFFLOAD", "1").strip().lower() in ("0", "false", "no"):
        return

    orig_tool = server.tool

    def _tool(*args, **kwargs):
        if len(args) == 1 and callable(args[0]) and not kwargs:
            # bare `@server.tool` form
            return orig_tool()(_mcp_offload_tool(args[0]))
        deco = orig_tool(*args, **kwargs)

        def apply(fn):
            return deco(_mcp_offload_tool(fn))

        return apply

    server.tool = _tool


def in_process_tool(server, name: str):
    """The original sync callable for a registered tool (WO-1 note).

    MCP transport calls the async offload wrappers; a caller in the same
    process (a script, a test, a setup route) needs the sync original, which
    the wrap keeps via ``functools.wraps``. Prefer this over reaching into
    ``server._tool_manager`` directly.
    """
    import inspect

    return inspect.unwrap(server._tool_manager._tools[name].fn)


def in_process_tools(server) -> dict:
    """A tool-manager-shaped mapping whose ``.fn`` attributes are sync."""
    import inspect

    class _SyncToolProxy:
        __slots__ = ("fn",)

        def __init__(self, fn):
            self.fn = fn

    return {
        name: _SyncToolProxy(inspect.unwrap(tool.fn))
        for name, tool in server._tool_manager._tools.items()
    }


def create_server(host: str = "127.0.0.1") -> FastMCP:
    """Create the MCP server.

    ``host`` is the client-facing bind identity used for MCP DNS-rebinding
    Host allowlisting. Pass the same value as ``nexus serve --host`` so
    remote lab clients (SIFT IP) are accepted. Extra hosts via
    ``NEXUS_MCP_ALLOWED_HOSTS`` (comma-separated).
    """
    from nexus.mcp_security import build_transport_security

    transport_security = build_transport_security(host)
    server = FastMCP(
        "dfir-nexus",
        instructions=_INSTRUCTIONS,
        host=host,
        transport_security=transport_security,
    )
    audit = AuditWriter("nexus")

    # WO-1 (D46): every tool module below registers sync functions; wrap
    # server.tool first so they run in worker threads instead of blocking the
    # serving loop (case-file writers keep one shared lock).
    apply_tool_offload(server)

    # ── Universal modules (pure Python, any platform) ──
    from nexus.tools import case, forensic, report
    forensic.register_tools(server, audit)
    case.register_tools(server, audit)
    report.register_tools(server, audit)

    # ── Knowledge base tools ──
    from nexus.tools import opencti, rag
    rag.register_tools(server, audit)
    opencti.register_tools(server, audit)

    # ── Triage (cross-platform, uses SQLite baselines) ──
    from nexus.triage import register_tools as triage_register
    triage_register(server, audit)

    # ── Advanced analysis (REVAMP-V2 features) ──
    from nexus.tools import analysis
    analysis.register_tools(server, audit)

    # ── Mode 2/3 backbone (WP 9.10/9.11) — evidence/index under MCP ──
    from nexus.tools import evidence_index
    evidence_index.register_tools(server, audit)

    from nexus.tools import detection_tools, ti_tools, vr_tools
    ti_tools.register_tools(server, audit)
    detection_tools.register_tools(server, audit)
    vr_tools.register_tools(server, audit)

    from nexus.tools import web
    web.register_tools(server, audit)

    # ── Platform-specific modules ──

    if _IS_LINUX:
        from nexus.tools import sift
        sift.register_tools(server, audit)
        logger.info("Registered SIFT/Linux forensic tools")
    else:
        logger.info("Not on Linux — skipping SIFT tools")

    if _IS_WINDOWS:
        from nexus.tools import windows
        windows.register_tools(server, audit)
        logger.info("Registered Windows forensic tools")
    else:
        logger.info("Not on Windows — skipping Windows tools")

    tool_count = _count_tools(server)
    logger.info("DFIR-Nexus ready: %s tools registered on %s (host=%s)", tool_count, sys.platform, host)

    import os
    preload = os.environ.get("NEXUS_RAG_PRELOAD", "1").strip().lower() in ("1", "true", "yes")
    mode = os.environ.get("NEXUS_PIPELINE_MODE", "").strip().lower()
    if mode in {"tools", "tools_only", "toolsonly", "no_llm", "nollm"}:
        preload = False
    if preload:
        try:
            from nexus.tools.rag import _get_index
            _get_index().load()
            logger.info("RAG embedder preloaded (NEXUS_RAG_PRELOAD)")
        except Exception as exc:  # noqa: BLE001
            logger.warning("RAG preload failed: %s", exc)

    return server


def _count_tools(server: FastMCP) -> int:
    """Count registered tools."""
    try:
        tools = server._tool_manager._tools if hasattr(server, "_tool_manager") else []
        return len(tools)
    except Exception:
        return 0
