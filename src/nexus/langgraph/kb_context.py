"""Deterministic KB context — Mode 2 initial interpretation input.

Queries the examiner's local KB (BM25/FTS5 via ``kb.py``, gated by
``NEXUS_KB_DIR``) for the case's question, artifact families, and top
entities, then renders a compact context block for the interpret agent.

KB content is methodology/context — never case evidence (FD-001).
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_MAX_QUERIES = 4
_MAX_HITS_PER_QUERY = 3
_MAX_SNIPPET = 320


def _search(query: str, limit: int = _MAX_HITS_PER_QUERY) -> dict[str, Any]:
    from nexus.tools.kb import do_kb_search

    return do_kb_search(query, limit=limit)


def build_kb_context(
    *,
    question: str = "",
    families: list[str] | None = None,
    entities: list[str] | None = None,
    max_queries: int = _MAX_QUERIES,
) -> dict[str, Any]:
    """Run bounded KB lookups for the case and render a prompt block."""
    queries: list[str] = []
    q = re.sub(r"\s+", " ", str(question or "")).strip()
    if q:
        queries.append(q[:200])
    for fam in (families or [])[:2]:
        queries.append(f"{fam} artifacts methodology")
    for ent in (entities or [])[:2]:
        queries.append(str(ent)[:60])
    queries = list(dict.fromkeys(queries))[:max_queries]

    hits: list[dict[str, Any]] = []
    errors: list[str] = []
    for query in queries:
        res = _search(query)
        if res.get("error"):
            errors.append(str(res["error"])[:160])
            if not res.get("available", True):
                break  # KB not configured — no point trying more
            continue
        for h in (res.get("hits") or [])[:_MAX_HITS_PER_QUERY]:
            if isinstance(h, dict):
                hits.append({"query": query, **h})
    return {"queries": queries, "hits": hits, "errors": errors}


def render_kb_markdown(ctx: dict[str, Any]) -> str:
    """Compact markdown block for the interpret prompt + kb_context.md."""
    hits = ctx.get("hits") or []
    lines = ["# Knowledge base (examiner-curated — context, never evidence)", ""]
    if not hits:
        reason = "; ".join(ctx.get("errors") or []) or "no KB hits for this case"
        lines.append(f"(no KB context available — {reason})")
        return "\n".join(lines) + "\n"
    for h in hits[:12]:
        title = (
            h.get("title")
            or h.get("path")
            or h.get("chunk_id")
            or h.get("id")
            or "kb"
        )
        snippet = re.sub(r"\s+", " ", str(h.get("snippet") or h.get("text") or ""))[:_MAX_SNIPPET]
        lines.append(f"- [{title}] {snippet}")
    lines.append("")
    lines.append(
        "Use KB notes for procedures, caveats and terminology; cite the page "
        "titles when you rely on them. They are never case evidence (FD-001)."
    )
    return "\n".join(lines) + "\n"


def write_kb_context(case_dir: Path, ctx: dict[str, Any]) -> Path | None:
    """Persist analysis/kb_context.md (best-effort)."""
    try:
        analysis = Path(case_dir) / "analysis"
        analysis.mkdir(parents=True, exist_ok=True)
        path = analysis / "kb_context.md"
        path.write_text(render_kb_markdown(ctx), encoding="utf-8")
        return path
    except OSError as exc:
        log.warning("kb_context write failed: %s", exc)
        return None
