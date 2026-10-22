"""Immutable execution runs within a stable investigation case."""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

log = logging.getLogger(__name__)

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,95}$")
_MODE_RUN_PREFIXES = {"M2-": "mode2_runs", "M3-": "mode3_runs"}
_MODE_RUN_LIVE_STATUSES = {"running", "planned", "verified", "assessed"}


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


def _windows_process_alive(pid: int, kernel32: Any = None) -> bool:
    """Query a Windows process conservatively; an access failure is not proof of exit."""
    import ctypes
    from ctypes import wintypes

    kernel32 = kernel32 or ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel32.GetLastError.restype = wintypes.DWORD
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        # OpenProcess reports ERROR_INVALID_PARAMETER (87) when no process has this PID.
        # Access denied and every other failure leave liveness unknown, so fail closed.
        return int(kernel32.GetLastError()) != 87
    try:
        code = wintypes.DWORD()
        kernel32.GetExitCodeProcess.argtypes = (
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
        )
        kernel32.GetExitCodeProcess.restype = wintypes.BOOL
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return True
        return code.value == 259  # STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def process_alive(pid: Any) -> bool:
    """Return False only when the process ``pid`` is confirmed to have exited.

    Used for run manifests written by a CLI process: no server reaps them, so a crash would
    otherwise leave a run 'running' for ever. ``os.kill(pid, 0)`` is a probe on POSIX only (on
    Windows it would send CTRL_C_EVENT), so Windows asks the kernel for the exit code instead.
    A permission or query error is not proof of exit; treat it as live so the reaper cannot
    overwrite a run whose process could not be inspected.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return True
    if pid <= 0:
        return True
    if os.name == "nt":
        return _windows_process_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True  # only ProcessLookupError above confirms absence
    return True


def run_owner_alive(pid: Any, thread_id: Any = None) -> bool:
    """Whether a run's recorded process/thread owner is still executing.

    Mode 2/3 can run in dashboard worker threads inside the long-lived web
    server. A PID-only check would keep those records busy after their worker
    thread exits, so same-process records also name the owning native thread.
    For a different process, the PID remains the available liveness signal.
    """
    if not process_alive(pid):
        return False
    try:
        owner_pid = int(pid)
        owner_thread_id = int(thread_id)
    except (TypeError, ValueError):
        return True
    if owner_pid == os.getpid():
        return any(getattr(thread, "native_id", None) == owner_thread_id
                   for thread in threading.enumerate())
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenThread.restype = wintypes.HANDLE
        kernel32.OpenThread.argtypes = [
            wintypes.DWORD, wintypes.BOOL, wintypes.DWORD,
        ]
        kernel32.GetProcessIdOfThread.restype = wintypes.DWORD
        kernel32.GetProcessIdOfThread.argtypes = [wintypes.HANDLE]
        kernel32.GetExitCodeThread.restype = wintypes.BOOL
        kernel32.GetExitCodeThread.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel32.OpenThread(0x0800, False, owner_thread_id)  # THREAD_QUERY_LIMITED_INFORMATION
        if not handle:
            # Access denied is inconclusive; other errors mean that native
            # thread no longer exists. Preserve the busy state if uncertain.
            return ctypes.get_last_error() == 5
        try:
            thread_owner_pid = kernel32.GetProcessIdOfThread(handle)
            if thread_owner_pid == 0:
                return True
            if thread_owner_pid != owner_pid:
                return False
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeThread(handle, ctypes.byref(code)):
                return True
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    task_dir = Path(f"/proc/{owner_pid}/task/{owner_thread_id}")
    if Path("/proc").is_dir():
        return task_dir.is_dir()
    # On platforms without a cross-process thread query, keep the conservative
    # process-level answer rather than interrupting a possibly live run.
    return process_alive(owner_pid)


def _mode_run_paths(case_dir: Path | str, run_id: str) -> tuple[Path, Path]:
    """Return validated record and append-only recovery marker paths."""
    run_id = str(run_id or "")
    if not _RUN_ID.fullmatch(run_id):
        raise ValueError("invalid run id")
    sub = next((value for prefix, value in _MODE_RUN_PREFIXES.items()
                if run_id.startswith(prefix)), "")
    if not sub:
        raise ValueError("only Mode 2 and Mode 3 runs can be recovered")
    root = Path(case_dir)
    return (
        root / "analysis" / sub / f"{run_id}.json",
        root / "analysis" / "run_recoveries" / f"{run_id}.json",
    )


def read_mode_run_recovery(case_dir: Path | str, run_id: str) -> dict[str, Any] | None:
    """Read a valid append-only lifecycle event for one Mode 2/3 run."""
    try:
        record_path, recovery_path = _mode_run_paths(case_dir, run_id)
        raw_record = record_path.read_bytes()
        recovery = json.loads(recovery_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if (not isinstance(recovery, dict)
            or recovery.get("run_id") != run_id
            or recovery.get("event_type") != "run.recovered"
            or recovery.get("to_status") != "interrupted"
            or recovery.get("source_record_sha256")
            != hashlib.sha256(raw_record).hexdigest()):
        return None
    return recovery


def mode_run_recovery_exists(case_dir: Path | str, run_id: str) -> bool:
    """Whether a recovery marker exists, including one that fails validation.

    Callers that would start or resume a run use this to fail closed on a
    malformed or stale marker instead of reusing the run id and overwriting
    its source record.
    """
    try:
        _record_path, recovery_path = _mode_run_paths(case_dir, run_id)
    except ValueError:
        return False
    return recovery_path.exists()


def recover_mode_run(
    case_dir: Path | str,
    run_id: str,
    *,
    confirmed_no_worker: bool = False,
) -> dict[str, Any]:
    """Append an interrupted transition without rewriting the run record.

    Ownerless legacy records require an explicit examiner confirmation because
    their age and file timestamps cannot prove that a worker has exited.
    """
    record_path, recovery_path = _mode_run_paths(case_dir, run_id)
    try:
        raw_record = record_path.read_bytes()
        record = json.loads(raw_record.decode("utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"run record not found: {run_id}") from exc
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"run record is unreadable: {run_id}") from exc
    if not isinstance(record, dict) or str(record.get("run_id") or "") != run_id:
        raise ValueError(f"run record identity does not match: {run_id}")

    record_digest = hashlib.sha256(raw_record).hexdigest()
    if recovery_path.exists():
        existing = read_mode_run_recovery(case_dir, run_id)
        if existing is not None and existing.get("source_record_sha256") == record_digest:
            return existing
        raise ValueError(f"a recovery event already exists but does not match the run: {run_id}")

    status = str(record.get("status") or "")
    if status not in _MODE_RUN_LIVE_STATUSES:
        raise ValueError(f"run is {status or 'unknown'}; only a live run can be recovered")

    pid = record.get("process_pid")
    thread_id = record.get("process_thread_id")
    if pid is None:
        if not confirmed_no_worker:
            raise ValueError(
                "this legacy run has no owner metadata; confirm the no-worker check explicitly")
        reason = "examiner confirmed no worker is live for this ownerless legacy run"
    else:
        try:
            pid = int(pid)
        except (TypeError, ValueError) as exc:
            raise ValueError("run owner PID is invalid; cannot prove the worker exited") from exc
        if pid <= 0:
            raise ValueError("run owner PID is invalid; cannot prove the worker exited")
        if run_owner_alive(pid, thread_id):
            raise ValueError(f"run owner is still live (pid {pid}, thread {thread_id})")
        if process_alive(pid):
            reason = f"run worker thread {thread_id} exited while process {pid} remains live"
        else:
            reason = f"run process {pid} has exited"

    recovery: dict[str, Any] = {
        "schema": 1,
        "event_type": "run.recovered",
        "run_id": run_id,
        "from_status": status,
        "to_status": "interrupted",
        "recorded_at": datetime.now(UTC).isoformat(),
        "reason": reason,
        "source_record_sha256": record_digest,
        "process_pid": pid,
        "process_thread_id": thread_id,
        "confirmed_no_worker": bool(confirmed_no_worker),
    }
    recovery_path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(recovery, sort_keys=True) + "\n").encode("utf-8")
    try:
        fd = os.open(str(recovery_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        existing = read_mode_run_recovery(case_dir, run_id)
        if existing is not None and existing.get("source_record_sha256") == record_digest:
            return existing
        raise ValueError(f"a recovery event already exists for {run_id}") from None
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return recovery


def effective_mode_run_record(
    case_dir: Path | str,
    run_id: str,
    record: dict[str, Any],
) -> dict[str, Any]:
    """Overlay an append-only recovery event for readers; preserve stored JSON."""
    recovery = read_mode_run_recovery(case_dir, run_id)
    if recovery is None:
        return record
    effective = dict(record)
    effective["status"] = "interrupted"
    effective["stop_reason"] = "recovered_interrupted"
    effective["error"] = str(recovery.get("reason") or "run explicitly recovered")
    effective["finished_at"] = str(recovery.get("recorded_at") or "")
    effective["recovery_event"] = recovery
    return effective


def reap_dead_runs(case_dir: Path) -> list[str]:
    """Mark dead Mode 1/2/3 runs interrupted before the busy guard reads them.

    A CLI run that is stopped (Ctrl+C, a closed terminal, a crash) leaves its manifest at
    'running', and no server reaps it: the 2026-10-14 Mode 1 run read 'running' after its
    process was gone. Mode 2/3 records similarly outlive failed CLI processes and dashboard
    worker threads. New owner-bound records are recovered by an append-only event; ownerless
    legacy records remain busy until an explicit recovery.
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

    for sub, prefix in (("mode2_runs", "M2-"), ("mode3_runs", "M3-")):
        records_dir = Path(case_dir) / "analysis" / sub
        for record_path in sorted(records_dir.glob(f"{prefix}*.json")):
            try:
                record = json.loads(record_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if (not isinstance(record, dict)
                    or record.get("status") not in _MODE_RUN_LIVE_STATUSES):
                continue
            pid = record.get("process_pid")
            thread_id = record.get("process_thread_id")
            # No owner means no safe process-liveness inference. An examiner
            # must use recover_mode_run after checking the live process list.
            if pid is None or run_owner_alive(pid, thread_id):
                continue
            try:
                recovery = recover_mode_run(case_dir, record_path.stem)
            except (OSError, ValueError):
                continue
            if recovery:
                reaped.append(str(record.get("run_id") or record_path.stem))
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
