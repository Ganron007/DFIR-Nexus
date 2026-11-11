"""Context assembly manifest per run (WP 15.9, T2-38).

Records which context blocks entered each model call, with their sizes (chars/tokens),
truncation, and failures, along with versions of knowledge registries.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.utils import atomic

log = logging.getLogger(__name__)


def record_context_manifest(
    case_dir: Path | str,
    run_id: str,
    blocks: list[dict[str, Any]],
    *,
    knowledge_versions: dict[str, Any] | None = None,
    failures: list[str] | None = None,
) -> Path:
    """Persist context assembly record for a run."""
    case_dir = Path(case_dir).resolve()
    manifest_dir = case_dir / "analysis"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / "context_manifest.json"
    run_manifest_path = manifest_dir / f"context_manifest-{run_id}.json"

    total_chars = sum(int(b.get("chars") or 0) for b in blocks)
    total_tokens = sum(int(b.get("tokens") or 0) for b in blocks)

    if knowledge_versions is None:
        knowledge_versions = {}
        try:
            from nexus.analysis.layers import layer_status

            knowledge_versions["layers"] = layer_status()
        except Exception:
            pass

    data = {
        "case_id": case_dir.name,
        "run_id": run_id,
        "at": datetime.now(UTC).isoformat(),
        "total_chars": total_chars,
        "total_tokens": total_tokens,
        "blocks": blocks,
        "knowledge_versions": knowledge_versions,
        "failures": list(failures or []),
    }

    content = json.dumps(data, indent=2, sort_keys=True)
    tmp_path = manifest_path.with_name(f"{manifest_path.name}.tmp")
    tmp_path.write_text(content, encoding="utf-8")
    atomic.replace(tmp_path, manifest_path)

    run_tmp = run_manifest_path.with_name(f"{run_manifest_path.name}.tmp")
    run_tmp.write_text(content, encoding="utf-8")
    atomic.replace(run_tmp, run_manifest_path)

    return manifest_path


def load_context_manifest(case_dir: Path | str, run_id: str | None = None) -> dict[str, Any] | None:
    """Load context manifest for a case or specific run."""
    case_dir = Path(case_dir).resolve()
    if run_id:
        p = case_dir / "analysis" / f"context_manifest-{run_id}.json"
        if p.is_file():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass
    p = case_dir / "analysis" / "context_manifest.json"
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
    return None
