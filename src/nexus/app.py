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

    from nexus.tools import detection_tools, ti_tools, vr_tools
    ti_tools.register_tools(server, audit)
    detection_tools.register_tools(server, audit)
    vr_tools.register_tools(server, audit)

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
