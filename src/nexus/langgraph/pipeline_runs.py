"""Immutable execution runs within a stable investigation case."""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

log = logging.getLogger(__name__)

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
        reaped.extend(f"{case_dir.name}/{rid}" for rid in reap_dead_runs(case_dir))
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


def process_alive(pid: Any) -> bool:
    """True while the process ``pid`` is running on this machine; False when it has exited.

    Used for run manifests written by a CLI process: no server reaps them, so a crash would
    otherwise leave a run 'running' for ever. ``os.kill(pid, 0)`` is a probe on POSIX only (on
    Windows it would send CTRL_C_EVENT), so Windows asks the kernel for the exit code instead.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def reap_dead_runs(case_dir: Path) -> list[str]:
    """Mark a run whose manifest says 'running' and whose process has exited as interrupted.

    A CLI run that is stopped (Ctrl+C, a closed terminal, a crash) leaves its manifest at
    'running', and no server reaps it: the 2026-10-14 Mode 1 run read 'running' after its
    process was gone. Only a manifest that names its process is judged; one with no pid is left
    to the server's startup reaper.
    """
    reaped: list[str] = []
    for manifest_path in sorted((Path(case_dir) / "runs").glob("*/manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(manifest, dict) or manifest.get("status") != "running":
            continue
        if "pid" not in manifest or process_alive(manifest.get("pid")):
            continue
        manifest["status"] = "interrupted"
        manifest["completed_at"] = datetime.now(UTC).isoformat()
        manifest["error"] = (
            f"its process (pid {manifest.get('pid')}) exited before the run finished")
        try:
            _atomic_json(manifest_path, manifest)
        except OSError:
            continue
        reaped.append(str(manifest.get("run_id") or manifest_path.parent.name))
    return reaped


def live_analysis_runs(case_dir: Path) -> list[dict[str, str]]:
    """Mode 1 analysis runs (interpret, coverage, design) still running on this case.

    Two records name them: the run manifest every pipeline run writes, and the portal's own
    ``analysis/pipeline_runs/M1-*.json``. A manifest that names its process counts only while
    that process lives.
    """
    case_dir = Path(case_dir)
    out: list[dict[str, str]] = []
    for manifest_path in sorted((case_dir / "runs").glob("*/manifest.json")):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(manifest, dict) or manifest.get("status") != "running":
            continue
        if str(manifest.get("mode") or "") not in ("interpret", "coverage", "design"):
            continue
        if "pid" in manifest and not process_alive(manifest.get("pid")):
            continue
        out.append({"run_id": str(manifest.get("run_id") or manifest_path.parent.name),
                    "status": "running", "source": "pipeline_run"})
    portal_dir = case_dir / "analysis" / "pipeline_runs"
    for rec_path in sorted(portal_dir.glob("M1-*.json")) if portal_dir.is_dir() else []:
        try:
            record = json.loads(rec_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(record, dict) and record.get("status") == "running":
            out.append({"run_id": str(record.get("run_id") or rec_path.stem),
                        "status": "running", "source": "pipeline_runs"})
    return out


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
        # The process that runs it, so a busy check can tell a live run from one a crashed
        # process left 'running' (D133). The CLI has no reaper for its runs.
        "pid": os.getpid(),
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


def has_completed_tools_run(case_dir: Path) -> bool:
    """True when the case has a committed tools run with output: the input interpret reads.

    An interpret run reads an existing lane run. Without one there is nothing to interpret,
    and the run would call the model over an empty case, so the start is refused instead.
    """
    runs_dir = Path(case_dir) / "runs"
    if not runs_dir.is_dir():
        return False
    return any(
        run.is_dir() and _run_committed(run) and _run_dir_has_data(run)
        for run in runs_dir.iterdir()
    )


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


def _run_committed(run_dir: Path) -> bool:
    """True when the run's manifest says it completed (R10)."""
    try:
        return str(load_manifest(Path(run_dir)).get("status") or "") == "completed"
    except (OSError, ValueError):
        return False


# Runs already reported as not completed in this process. The resolver runs on every
# lookup while a lane is still running, so the warning is logged once per run.
_INCOMPLETE_RUNS_WARNED: set[str] = set()


#: Case folders that hold what a tool wrote. Nothing under them is examiner evidence.
TOOL_OUTPUT_FOLDERS = ("runs", "extractions", "ingest", "analysis", "reports", "ledger")


def is_tool_output(path: Path, case_root: Path) -> bool:
    """True when a path sits in one of the case's tool-output folders.

    A tool's output is never evidence. A run inherits the evidence list of the run before it, and that list
    can hold the stdout files of its tools: planned as evidence, each one becomes a "no recognized evidence
    shape" row (CASE-C5B04D31, 2026-10-11: 184 such paths in one run's manifest).
    """
    for folder in TOOL_OUTPUT_FOLDERS:
        try:
            path.resolve().relative_to((case_root / folder).resolve())
            return True
        except (ValueError, OSError):
            continue
    return False


def drop_tool_outputs(paths: list[str], case_root: Path) -> list[str]:
    """The paths that are not tool output, in their order."""
    return [p for p in paths if not is_tool_output(Path(p), case_root)]


def resolve_tools_extractions(case_dir: Path, run_id: str = "") -> Path:
    """Extractions of the active tools run, following reuse chains.

    A ``coverage``/``design`` run created with ``--from-case`` reuses an earlier
    tools run and owns no parsed files itself. Resolution must therefore skip
    data-less runs (following ``parent_run_id`` → ``previous_active_run_id``,
    then newest-run-with-data) instead of returning an empty directory that
    would blind the briefing, the indexer and the entity census.
    """
    case_dir = Path(case_dir)
    requested_run_id = run_id.strip()
    run: PipelineRun | None = None
    try:
        run = resolve_run(case_dir, "tools", requested_run_id)
    except ValueError:
        if requested_run_id:
            raise
        run = None
    requested_run = run

    # When no explicit run was asked for, the NEWEST run with data is the lane
    # that actually ran. Following the pointer chain first landed on a stale run
    # (SC1: the pointer chain reached the 07:55 run while the 09:41 lane run —
    # 425 OK rows — held the real output), which blinded the family census.
    if not run_id.strip():
        # R10 (third-eye review): the committed run is authoritative. The active
        # pointer names it, and it is used when its manifest says it completed.
        # Otherwise recovery takes the newest COMPLETED run with data and logs why;
        # only when no completed run has data does it fall back to the newest data,
        # with a warning, so a failed run's partial output is never silent.
        if run is not None and _run_committed(run.path) and _run_dir_has_data(run.path):
            return run.extractions
        runs_dir = case_dir / "runs"
        if runs_dir.is_dir():
            ordered = sorted(
                runs_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True,
            )
            for candidate in ordered:
                if (candidate.is_dir() and _run_committed(candidate)
                        and _run_dir_has_data(candidate)):
                    if run is not None and run.run_id != candidate.name:
                        log.warning("tools run %s is not committed; resolving the "
                                    "completed run %s", run.run_id, candidate.name)
                    return candidate / "extractions"
            for candidate in ordered:
                if candidate.is_dir() and _run_dir_has_data(candidate):
                    warned_key = str(candidate)
                    if warned_key not in _INCOMPLETE_RUNS_WARNED:
                        _INCOMPLETE_RUNS_WARNED.add(warned_key)
                        log.warning("no completed tools run has data; resolving %s, "
                                    "which did not complete", candidate.name)
                    return candidate / "extractions"

    seen: set[str] = set()
    while run is not None and run.run_id not in seen:
        seen.add(run.run_id)
        if _run_dir_has_data(run.path):
            return run.extractions
        manifest = load_manifest(run.path)
        # Only follow previous_active_run_id for an implicit lookup. A named
        # tools run's previous active run is history, not a reuse dependency;
        # reading it would turn an empty/incomplete run into stale evidence.
        nxt = run.parent_run_id
        if not requested_run_id:
            nxt = nxt or str(manifest.get("previous_active_run_id") or "")
        try:
            run = _load_run(case_dir, nxt) if nxt else None
        except ValueError:
            run = None
    if requested_run_id:
        # A named run is a hard scope boundary. If it and its declared reuse
        # chain have no parsed output, return the named run's empty extraction
        # root instead of silently borrowing another run's evidence.
        assert requested_run is not None
        return requested_run.extractions
    runs_dir = case_dir / "runs"
    if runs_dir.is_dir():
        candidates = sorted(
            runs_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True,
        )
        for run_dir in candidates:
            if _run_dir_has_data(run_dir):
                return run_dir / "extractions"
    return case_dir / "extractions"
