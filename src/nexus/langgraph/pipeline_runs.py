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


def configured_model() -> dict[str, str]:
    """Provider and model of the model this process will actually call.

    D48: this used to be a second ``.env`` parser beside ``get_model``, so the
    run record could name one model while the seats called another — 36c ran
    its three modes on two models and the records did not show it. The record
    is now read from what ``get_model`` built, so it cannot disagree.

    ``none`` means no model was built in this process. A deterministic
    (no-LLM) run records that, and it is not read as "a model ran".
    """
    from nexus.langgraph.llm_pipeline import built_model_record

    return built_model_record()


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


def reap_stale_running_runs(cases_root: Path | None = None) -> list[str]:
    """Mark lane run records a dead process left 'running' as interrupted.

    Tools/mode runs execute as threads inside the server process, so a server
    restart or crash kills them with no chance to finalize - the status record
    stays ``running`` and the portal presents a ghost run forever (found
    2026-09-29: CASE-4EFD5EB2 still said running ~10 h after its server had
    exited, and it fed the impression of two cases running at once). Called
    once at server startup, when no lane thread can be alive by construction.
    """
    from nexus.config import settings

    root = Path(cases_root) if cases_root is not None else settings.cases_root
    reaped: list[str] = []
    if not root.is_dir():
        return reaped
    for case_dir in sorted(root.glob("CASE-*")):
        runs_dir = case_dir / "analysis" / "pipeline_runs"
        if not runs_dir.is_dir():
            continue
        for rec_path in sorted(runs_dir.glob("*.json")):
            try:
                record = json.loads(rec_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(record, dict) or record.get("status") != "running":
                continue
            record["status"] = "interrupted"
            record["stop_reason"] = "server restart before the run finished"
            record["finished_at"] = datetime.now(UTC).isoformat()
            try:
                _atomic_json(rec_path, record)
            except OSError:
                continue
            reaped.append(f"{case_dir.name}/{record.get('run_id') or rec_path.stem}")
    return reaped


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
    # A coverage/design/interpret run built on an earlier run records it as the
    # parent so reuse chains stay resolvable (resolve_tools_extractions).
    if (
        not parent_run_id
        and mode in {"coverage", "design", "interpret"}
        and previous_active
        and _RUN_ID.fullmatch(previous_active)
    ):
        parent_run_id = previous_active
    now = datetime.now(UTC).isoformat()
    # WO-K8: a toggle must be asserted ON THE RUN RECORD, not only in the process
    # environment. `layer_status()` is a read-only snapshot of the two ablation
    # switches, so an ablation number can be read against what was actually
    # active when the run was created.
    try:
        from nexus.analysis.layers import layer_status

        layers = layer_status()
    except Exception:  # noqa: BLE001 - a run must not fail to record a niceity
        layers = {}
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
        "layers": layers,
        "model": configured_model(),
    })
    pointers[mode] = rid
    pointers[pointer_key] = rid
    _atomic_json(pointer_path, pointers)
    return PipelineRun(rid, mode, run_dir, parent_run_id)


def finalize_run(run: PipelineRun, status: str, error: str = "") -> None:
    manifest = load_manifest(run.path)
    manifest["status"] = status
    manifest["completed_at"] = datetime.now(UTC).isoformat()
    # WO-K7: the run record carries what the run could and could not observe, so
    # a zero-finding run is not read as "nothing happened".
    try:
        from nexus.analysis.absence import record as _absence_record

        manifest["absence"] = _absence_record(run.path.parent.parent)
    except Exception:  # noqa: BLE001 - never fail a finalize on a report nicety
        manifest["absence"] = {}
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
    return _load_run(case_dir, rid, mode)


def _load_run(case_dir: Path, rid: str, mode: str = "tools") -> PipelineRun:
    if not rid or not _RUN_ID.fullmatch(rid):
        raise ValueError(f"No active {mode} run in case {case_dir.name}")
    run_dir = case_dir / "runs" / rid
    if not run_dir.is_dir():
        raise ValueError(f"Run not found: {rid}")
    manifest = load_manifest(run_dir)
    return PipelineRun(
        rid, str(manifest.get("mode") or mode), run_dir,
        str(manifest.get("parent_run_id") or ""),
    )


_DATA_SUFFIXES = (".csv", ".json", ".jsonl", ".txt", ".log", ".gz", ".zip")


def _extractions_have_data(extractions: Path) -> bool:
    """True when a run's extractions dir holds parsed output (not just _meta)."""
    if not extractions.is_dir():
        return False
    for path in extractions.rglob("*"):
        if (
            path.is_file()
            and not path.name.startswith("_")
            and path.name.lower().endswith(_DATA_SUFFIXES)
        ):
            return True
    return False


def _run_dir_has_data(run_dir: Path) -> bool:
    """Parsed output may sit in ``extractions/`` or ``sift/extractions/``.

    SIFT-run cases keep their whole product set under ``sift/extractions``
    (G7, 2026-09-29: SIFT-only runs were judged data-less, so the indexer
    walked nothing and reported 0 docs).
    """
    run_dir = Path(run_dir)
    return _extractions_have_data(run_dir / "extractions") or _extractions_have_data(
        run_dir / "sift" / "extractions"
    )


def resolve_tools_extractions(case_dir: Path, run_id: str = "") -> Path:
    """Extractions of the active tools run, following reuse chains.

    A ``coverage``/``design`` run created with ``--from-case`` reuses an earlier
    tools run and owns no parsed files itself. Resolution must therefore skip
    data-less runs (following ``parent_run_id`` → ``previous_active_run_id``,
    then newest-run-with-data) instead of returning an empty directory that
    would blind the briefing, the indexer and the entity census.
    """
    case_dir = Path(case_dir)
    run: PipelineRun | None = None
    try:
        run = resolve_run(case_dir, "tools", run_id)
    except ValueError:
        run = None

    # When no explicit run was asked for, the NEWEST run with data is the lane
    # that actually ran. Following the pointer chain first landed on a stale run
    # (SC1: the pointer chain reached the 07:55 run while the 09:41 lane run —
    # 425 OK rows — held the real output), which blinded the family census.
    if not run_id.strip():
        runs_dir = case_dir / "runs"
        if runs_dir.is_dir():
            for candidate in sorted(
                runs_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True,
            ):
                if candidate.is_dir() and _run_dir_has_data(candidate):
                    return candidate / "extractions"

    seen: set[str] = set()
    while run is not None and run.run_id not in seen:
        seen.add(run.run_id)
        if _run_dir_has_data(run.path):
            return run.extractions
        manifest = load_manifest(run.path)
        nxt = run.parent_run_id or str(manifest.get("previous_active_run_id") or "")
        try:
            run = _load_run(case_dir, nxt) if nxt else None
        except ValueError:
            run = None
    runs_dir = case_dir / "runs"
    if runs_dir.is_dir():
        candidates = sorted(
            runs_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True,
        )
        for run_dir in candidates:
            if _run_dir_has_data(run_dir):
                return run_dir / "extractions"
    return case_dir / "extractions"
