"""KB-6 — offline-safe bridge from DFIR-Nexus to the doc_extract KB.

Reads prebuilt export packs (KB-4) and resolves citations on demand. Returns
empty results when the KB is absent, so nothing here is a hard dependency.

Contract: see ``G:\\doc_extract\\KB-6-PRODUCT-BRIDGE.md``.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

_DEFAULT_ROOT = Path(r"G:\doc_extract")
_CITATION_RE = re.compile(r"<!--\s*([^>]+?)\s*-->")


def kb_root() -> Path | None:
    """KB root (``NEXUS_KB_DIR`` or the default), or None when absent."""
    candidates = []
    env = os.environ.get("NEXUS_KB_DIR")
    if env:
        candidates.append(Path(env))
    candidates.append(_DEFAULT_ROOT)
    for cand in candidates:
        if (cand / "kb" / "kb.py").is_file():
            return cand
    return None


def exports_dir() -> Path | None:
    root = kb_root()
    return (root / "kb" / "exports") if root else None


def list_packs() -> list[dict]:
    """Prebuilt export packs with their manifest summary."""
    base = exports_dir()
    if not base or not base.is_dir():
        return []
    out: list[dict] = []
    for sub in sorted(p for p in base.iterdir() if p.is_dir()):
        info: dict = {"name": sub.name, "path": str(sub)}
        manifest = sub / "manifest.json"
        if manifest.is_file():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    info.update({
                        "selection": data.get("selection"),
                        "docs": data.get("docs"),
                        "chunks": data.get("chunks"),
                        "generated": data.get("generated"),
                    })
            except (OSError, json.JSONDecodeError):
                pass
        out.append(info)
    return out


def _text_files(pack_dir: Path):
    for f in sorted(pack_dir.rglob("*")):
        if f.is_file() and f.suffix in (".md", ".yaml") and f.name != "manifest.json":
            yield f


def search_pack(pack_dir: str | Path, query: str, limit: int = 5) -> list[dict]:
    """Substring search over a pack's text files, returning cited snippets.

    All whitespace-separated query tokens must appear on the line (AND). The
    nearest preceding ``<!-- ... -->`` citation marker is attached.
    """
    pack = Path(pack_dir)
    if not pack.is_dir():
        return []
    tokens = [t.lower() for t in str(query).split() if t.strip()]
    if not tokens:
        return []
    results: list[dict] = []
    for f in _text_files(pack):
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            low = line.lower()
            if not line.strip() or not all(tok in low for tok in tokens):
                continue
            citation = ""
            for j in range(i, max(-1, i - 6), -1):
                m = _CITATION_RE.search(lines[j])
                if m:
                    citation = m.group(1).strip()
                    break
            results.append({
                "file": f.name,
                "line": i + 1,
                "text": line.strip()[:300],
                "citation": citation,
            })
            if len(results) >= limit:
                return results
    return results


def cite(chunk_id: str) -> dict:
    """Resolve one chunk citation via ``kb.py cite`` (empty if unavailable)."""
    root = kb_root()
    if not root or not chunk_id:
        return {}
    kb = root / "kb" / "kb.py"
    try:
        res = subprocess.run(
            [sys.executable, str(kb), "cite", str(chunk_id), "--out", str(root / "kb")],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    except (OSError, subprocess.SubprocessError):
        return {}
    if res.returncode != 0:
        return {}
    try:
        data = json.loads(res.stdout)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}
