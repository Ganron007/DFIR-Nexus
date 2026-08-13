"""MCP Sigma / detection search — local index, optional translate extra."""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter


def _default_sigma_root() -> Path:
    repo = Path(__file__).resolve().parents[3] / "Evidence-files" / "10-sigma" / "rules"
    if repo.is_dir():
        return repo
    return Path.home() / ".nexus" / "data" / "sigma" / "rules"


def _index_dir() -> Path:
    p = Path.home() / ".nexus" / "data" / "detection-index"
    p.mkdir(parents=True, exist_ok=True)
    return p


def register_tools(server: FastMCP, audit: AuditWriter) -> None:
    @server.tool()
    def detection_sigma_install(source_dir: str = "", force: bool = False) -> dict:
        """Index Sigma YAML from Evidence-files/10-sigma/rules or source_dir into ~/.nexus/data/detection-index."""
        from nexus.detection.indexer import DetectionIndexer

        src = Path(source_dir) if source_dir else _default_sigma_root()
        if not src.is_dir():
            return {"ok": False, "error": f"Sigma rules dir missing: {src}"}
        dest = _index_dir()
        if force:
            for old in dest.glob("*.json"):
                old.unlink()
        indexer = DetectionIndexer(dest)
        n = indexer.index_sigma_directory(src)
        audit.log(tool="detection_sigma_install", params={"src": str(src)}, result_summary={"n": n})
        return {"ok": True, "indexed": n, "source": str(src), "index": str(dest)}

    @server.tool()
    def detection_search(query: str = "", technique_id: str = "", limit: int = 10) -> dict:
        """Search the local detection index. Run detection_sigma_install first if empty."""
        from nexus.detection.search import DetectionSearcher

        searcher = DetectionSearcher(_index_dir())
        hits = searcher.search(
            technique_id=technique_id or None,
            query=query or None,
        )
        rows = []
        for rule in hits[:limit]:
            if hasattr(rule, "to_dict"):
                rows.append(rule.to_dict())
            else:
                rows.append({
                    "id": getattr(rule, "id", ""),
                    "title": getattr(rule, "title", ""),
                    "technique_ids": getattr(rule, "technique_ids", []),
                })
        audit.log(tool="detection_search", params={"q": query, "t": technique_id}, result_summary={"n": len(rows)})
        return {"hits": rows, "returned": len(rows), "index": str(_index_dir())}

    @server.tool()
    def sigma_translate(yaml_content: str, target: str = "kql") -> dict:
        """Translate a Sigma YAML string. Requires pip extra [detection]."""
        try:
            from nexus.detection.sigma_repo import sigma_translate as _tr
        except ImportError as exc:
            return {"ok": False, "error": f"detection extra missing: {exc}. pip install -e '.[detection]'"}
        try:
            out = _tr(yaml_content, target=target)
            return {"ok": True, "target": target, "translated": out}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "hint": "pip install -e '.[detection]'"}
