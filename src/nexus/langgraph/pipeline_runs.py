"""Immutable execution runs within a stable investigation case."""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,95}$")


@dataclass(frozen=True)
class PipelineRun:
    run_id: str
    mode: str
    path: Path
    parent_run_id: str = ""

    @property
    def extractions(self) -> Path:
        return self.path / "extractions"

    @property
    def analysis(self) -> Path:
        return self.path / "analysis"

    @property
    def reports(self) -> Path:
        return self.path / "reports"


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise


def _new_run_id(mode: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    return f"RUN-{stamp}-{mode}-{uuid4().hex[:8]}"


def load_manifest(run_dir: Path) -> dict[str, Any]:
    return json.loads((Path(run_dir) / "manifest.json").read_text(encoding="utf-8"))


def create_run(
    case_dir: Path,
    mode: str,
    evidence_paths: list[str] | None = None,
    *,
    parent_run_id: str = "",
    run_id: str = "",
) -> PipelineRun:
    case_dir = Path(case_dir)
    mode = mode.strip().lower()
    if mode not in {"tools", "coverage", "design", "interpret"}:
        raise ValueError(f"Unsupported pipeline run mode: {mode}")
    rid = run_id.strip() or _new_run_id(mode)
    if not _RUN_ID.fullmatch(rid):
        raise ValueError("run_id must be 2-96 alphanumeric, hyphen, or underscore characters")
    if parent_run_id and not _RUN_ID.fullmatch(parent_run_id):
        raise ValueError("Invalid parent_run_id")

    run_dir = case_dir / "runs" / rid
    run_dir.mkdir(parents=True, exist_ok=False)
    for name in ("extractions", "analysis", "reports", "ledger"):
        (run_dir / name).mkdir()
    pointer_path = case_dir / "active_runs.json"
    pointers: dict[str, str] = {}
    if pointer_path.is_file():
        try:
            loaded = json.loads(pointer_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                pointers = {str(k): str(v) for k, v in loaded.items()}
        except (OSError, json.JSONDecodeError):
            pointers = {}
    pointer_key = "tools" if mode in {"tools", "coverage", "design"} else mode
    previous_active = pointers.get(pointer_key, "")
    now = datetime.now(UTC).isoformat()
    _atomic_json(run_dir / "manifest.json", {
        "run_id": rid,
        "case_id": case_dir.name,
        "mode": mode,
        "parent_run_id": parent_run_id,
        "evidence_paths": [str(p) for p in evidence_paths or []],
        "status": "running",
        "created_at": now,
        "completed_at": "",
        "previous_active_run_id": previous_active,
    })
    pointers[mode] = rid
    pointers[pointer_key] = rid
    _atomic_json(pointer_path, pointers)
    return PipelineRun(rid, mode, run_dir, parent_run_id)


def finalize_run(run: PipelineRun, status: str, error: str = "") -> None:
    manifest = load_manifest(run.path)
    manifest["status"] = status
    manifest["completed_at"] = datetime.now(UTC).isoformat()
    if error:
        manifest["error"] = error[:2000]
    _atomic_json(run.path / "manifest.json", manifest)
    pointer_path = run.path.parent.parent / "active_runs.json"
    pointers: dict[str, str] = {}
    if pointer_path.is_file():
        try:
            loaded = json.loads(pointer_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                pointers = {str(k): str(v) for k, v in loaded.items()}
        except (OSError, json.JSONDecodeError):
            pointers = {}
    pointer_key = "tools" if run.mode in {"tools", "coverage", "design"} else run.mode
    if status == "completed":
        pointers[run.mode] = run.run_id
        pointers[pointer_key] = run.run_id
    elif pointers.get(pointer_key) == run.run_id:
        previous = str(manifest.get("previous_active_run_id") or "")
        if previous:
            pointers[pointer_key] = previous
        else:
            pointers.pop(pointer_key, None)
        if pointers.get(run.mode) == run.run_id:
            pointers.pop(run.mode, None)
    _atomic_json(pointer_path, pointers)


def resolve_run(case_dir: Path, mode: str = "tools", run_id: str = "") -> PipelineRun:
    case_dir = Path(case_dir)
    rid = run_id.strip()
    if not rid:
        pointer_path = case_dir / "active_runs.json"
        if not pointer_path.is_file():
            raise ValueError(f"No active {mode} run in case {case_dir.name}")
        pointers = json.loads(pointer_path.read_text(encoding="utf-8"))
        rid = str(pointers.get(mode) or "")
    if not rid or not _RUN_ID.fullmatch(rid):
        raise ValueError(f"No active {mode} run in case {case_dir.name}")
    run_dir = case_dir / "runs" / rid
    if not run_dir.is_dir():
        raise ValueError(f"Run not found: {rid}")
    manifest = load_manifest(run_dir)
    return PipelineRun(rid, str(manifest.get("mode") or mode), run_dir, str(manifest.get("parent_run_id") or ""))


def resolve_tools_extractions(case_dir: Path, run_id: str = "") -> Path:
    try:
        return resolve_run(case_dir, "tools", run_id).extractions
    except ValueError:
        return Path(case_dir) / "extractions"
