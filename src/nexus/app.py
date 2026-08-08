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
    nexus serve --http --port 4508
    # On Windows:
    nexus serve --http --port 4508
    # From LLM client:
    nexus setup client --sift 10.0.0.2:4508 --windows 10.0.0.5:4508
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


def create_server() -> FastMCP:
    server = FastMCP("dfir-nexus", instructions=_INSTRUCTIONS)
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
    logger.info(f"DFIR-Nexus ready: {tool_count} tools registered on {sys.platform}")

    return server


def _count_tools(server: FastMCP) -> int:
    """Count registered tools."""
    try:
        tools = server._tool_manager._tools if hasattr(server, '_tool_manager') else []
        return len(tools)
    except Exception:
        return 0
