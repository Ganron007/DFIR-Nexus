"""MCP knowledge tools — WP 9.11 (backbone, knowledge plane: KB under MCP).

The examiner's custom KB is local/private (never leaked or shared); these
tools make it live-queryable for Mode 2 grounding and Mode 3 mid-run
procedure lookup. Gated by ``NEXUS_KB_DIR`` (or the default KB root) —
**inert when the KB is absent** so nothing here is a hard dependency
(public users without a KB live with the default RAG).

Policy: KB content is methodology/context, never case evidence (FD-001);
exports are canonical-only and secret-redacted.
"""
from __future__ import annotations

import contextlib
import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter
from nexus.knowledge.kb_bridge import kb_root

logger = logging.getLogger(__name__)

_SUBPROCESS_TIMEOUT = 120.0
_MAX_TEXT = 4000


def _kb_py() -> Path | None:
    root = kb_root()
    return (root / "kb" / "kb.py") if root else None


def _run_kb(*args: str) -> dict[str, Any]:
    """Run a kb.py command; returns a parsed dict or an error payload."""
    kb = _kb_py()
    root = kb_root()
    if not kb or not root:
        return {"error": "KB not configured (NEXUS_KB_DIR unset and default KB absent)",
                "available": False}
    try:
        res = subprocess.run(
            [sys.executable, str(kb), *args, "--out", str(root / "kb")],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=_SUBPROCESS_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"error": f"kb {args[0]} timed out after {_SUBPROCESS_TIMEOUT:.0f}s",
                "available": True}
    if res.returncode != 0:
        return {"error": f"kb {args[0]} failed: {(res.stderr or res.stdout)[-300:]}",
                "available": True}
    import json

    with contextlib.suppress(json.JSONDecodeError):
        return {**json.loads(res.stdout), "available": True}
    return {"available": True, "text": res.stdout[:_MAX_TEXT]}


def do_kb_search(query: str, folder: str = "", signal: str = "", limit: int = 5,
                 audit: AuditWriter | None = None) -> dict[str, Any]:
    """Search the KB (BM25/FTS5) — the core behind the MCP tool + binding."""
    started = time.monotonic()
    if not query.strip():
        return {"error": "query is required"}
    args = ["find", query.strip(), "--limit", str(max(1, min(int(limit), 20)))]
    if folder.strip():
        args += ["--folder", folder.strip()]
    if signal.strip() in ("command", "cve", "attack", "tool", "path"):
        args += ["--signal", signal.strip()]
    out = _run_kb(*args, "--json")
    out.setdefault("note", "KB content is methodology/context — never case evidence (FD-001)")
    if audit:
        audit.log(tool="kb_search", params={"query": query[:200], "folder": folder},
                  result_summary={"hits": len(out.get("hits") or [])},
                  elapsed_ms=round((time.monotonic() - started) * 1000, 1))
    return out


def do_kb_read(chunk_id: str, audit: AuditWriter | None = None) -> dict[str, Any]:
    """Read the exact text of one chunk (bounded) with its citation."""
    if not chunk_id.strip():
        return {"error": "chunk_id is required"}
    out = _run_kb("read", chunk_id.strip(), "--json")
    text = str(out.get("text") or "")
    if text and len(text) > _MAX_TEXT:
        out["text"] = text[:_MAX_TEXT] + "\n…(truncated — use `around`/export for more)"
    if audit:
        audit.log(tool="kb_read", params={"chunk_id": chunk_id[:80]},
                  result_summary={"chars": len(text)})
    return out


def do_kb_cite(chunk_id: str, audit: AuditWriter | None = None) -> dict[str, Any]:
    """Resolve a citation to its document/lines/heading (provenance)."""
    if not chunk_id.strip():
        return {"error": "chunk_id is required"}
    out = _run_kb("cite", chunk_id.strip())
    if audit:
        audit.log(tool="kb_cite", params={"chunk_id": chunk_id[:80]},
                  result_summary={"resolved": bool(out.get("chunk_id"))})
    return out


def do_kb_verify_cites(skill: str, audit: AuditWriter | None = None) -> dict[str, Any]:
    """Verify the KB citations of one installed skill resolve (provenance)."""
    safe = "".join(c for c in skill.strip() if c.isalnum() or c in "._-").strip("._")
    if not safe:
        return {"error": "skill id is required"}
    import nexus

    path = Path(nexus.__file__).parent / "data" / "knowledge" / "skills" / f"{safe}.yaml"
    if not path.is_file():
        return {"error": f"unknown skill: {safe}", "available": kb_root() is not None}
    out = _run_kb("verify-cites", str(path))
    if audit:
        audit.log(tool="kb_verify_cites", params={"skill": safe}, result_summary={})
    return out


def do_kb_topics(folder: str, limit: int = 40, audit: AuditWriter | None = None) -> dict[str, Any]:
    """List candidate procedure topics (documents) for a KB folder."""
    if not folder.strip():
        return {"error": "folder is required"}
    out = _run_kb("topics", folder.strip(), "--limit", str(max(1, min(int(limit), 200))))
    if audit:
        audit.log(tool="kb_topics", params={"folder": folder[:120]},
                  result_summary={"docs": out.get("docs")})
    return out


def do_kb_coverage_map(audit: AuditWriter | None = None) -> dict[str, Any]:
    """Scope × distilled matrix — which KB scopes feed which skills."""
    out = _run_kb("coverage-map")
    if audit:
        audit.log(tool="kb_coverage_map", params={}, result_summary={})
    return out


def do_kb_list_packs(audit: AuditWriter | None = None) -> dict[str, Any]:
    """List the prebuilt, citation-annotated agent packs (KB-4)."""
    from nexus.knowledge.kb_bridge import list_packs

    out = {"available": kb_root() is not None, "packs": list_packs()}
    if audit:
        audit.log(tool="kb_list_packs", params={}, result_summary={"packs": len(out["packs"])})
    return out


def register_tools(server: FastMCP, audit: AuditWriter):
    @server.tool()
    def kb_search(query: str, folder: str = "", signal: str = "", limit: int = 5) -> dict:
        """Search the knowledge base (BM25/FTS5, sub-second, chunk-cited).

        Returns procedure excerpts with exact citations
        (`chunk_id | rel_path:line_start-line_end`) — methodology grounding for
        the examiner/LLM, never case evidence.
        """
        return do_kb_search(query=query, folder=folder, signal=signal, limit=limit, audit=audit)

    @server.tool()
    def kb_read(chunk_id: str) -> dict:
        """Read the exact text of one chunk (bounded) with its citation."""
        return do_kb_read(chunk_id=chunk_id, audit=audit)

    @server.tool()
    def kb_cite(chunk_id: str) -> dict:
        """Resolve a citation to its document/lines/heading (provenance)."""
        return do_kb_cite(chunk_id=chunk_id, audit=audit)

    @server.tool()
    def kb_verify_cites(skill: str) -> dict:
        """Verify the KB citations of one installed skill resolve (provenance).

        `skill` is a skill id (e.g. `memory_process_analysis`) — resolved
        against the installed skills directory; arbitrary file paths are not
        accepted over MCP.
        """
        return do_kb_verify_cites(skill=skill, audit=audit)

    @server.tool()
    def kb_topics(folder: str, limit: int = 40) -> dict:
        """List candidate procedure topics (documents) for a KB folder."""
        return do_kb_topics(folder=folder, limit=limit, audit=audit)

    @server.tool()
    def kb_coverage_map() -> dict:
        """Scope × distilled matrix — which KB scopes feed which skills."""
        return do_kb_coverage_map(audit=audit)

    @server.tool()
    def kb_list_packs() -> dict:
        """List the prebuilt, citation-annotated agent packs (KB-4)."""
        return do_kb_list_packs(audit=audit)
