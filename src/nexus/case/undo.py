"""Import undo/redo stack for case data.

Multi-level per-case stack that captures state snapshots before each import
operation. Provides rollback to restore a case to its previous state.

Backed by JSON files on disk (one snapshot directory per case). All functions
are pure data-structure operations — no database dependencies.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class Snapshot:
    """A point-in-time snapshot of case state before an import."""

    id: str
    case_id: str
    timestamp: str
    description: str
    # The actual case data at snapshot time
    case_data: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    # Which import triggered this snapshot
    import_source: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class UndoRedoState:
    """Per-case undo/redo state.

    Maintains two stacks:
    - ``undo_stack``: snapshots that can be restored (most recent last)
    - ``redo_stack``: snapshots that were undone (for redo operations)
    """

    case_id: str
    undo_stack: list[Snapshot] = field(default_factory=list)
    redo_stack: list[Snapshot] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "undo_stack": [s.to_dict() for s in self.undo_stack],
            "redo_stack": [s.to_dict() for s in self.redo_stack],
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def create_snapshot(
    base_path: str | Path,
    *,
    case_id: str,
    case_data: dict[str, Any],
    findings: list[dict[str, Any]] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    timeline: list[dict[str, Any]] | None = None,
    description: str = "",
    import_source: str = "",
) -> Snapshot:
    """Create a new snapshot and push it onto the undo stack.

    Call this *before* an import modifies case data. The snapshot captures
    the current state so it can be restored via ``rollback``.

    Args:
        base_path: Root directory for snapshot storage.
        case_id: The case this snapshot belongs to.
        case_data: Current case metadata dict.
        findings: Current findings list.
        evidence: Current evidence list.
        timeline: Current timeline entries.
        description: Human-readable description of why the snapshot was taken.
        import_source: Identifier of the import that triggered this snapshot.

    Returns:
        The created Snapshot object.
    """
    snapshot = Snapshot(
        id=f"SNAP-{uuid.uuid4().hex[:12].upper()}",
        case_id=case_id,
        timestamp=datetime.now(UTC).isoformat(),
        description=description or f"Pre-import snapshot for {import_source or 'unknown'}",
        case_data=case_data,
        findings=findings or [],
        evidence=evidence or [],
        timeline=timeline or [],
        import_source=import_source,
    )

    state = _load_state(base_path, case_id)
    state.undo_stack.append(snapshot)
    # Clear redo stack on new action (standard undo/redo behavior)
    state.redo_stack.clear()

    _save_state(base_path, state)
    _save_snapshot_file(base_path, snapshot)

    log.debug("Created snapshot %s for case %s", snapshot.id, case_id)
    return snapshot


def undo(
    base_path: str | Path,
    case_id: str,
) -> Snapshot | None:
    """Pop the most recent snapshot from the undo stack (rollback).

    Moves the snapshot to the redo stack so the operation can be redone.

    Args:
        base_path: Root directory for snapshot storage.
        case_id: The case to rollback.

    Returns:
        The restored Snapshot, or None if the undo stack is empty.
    """
    state = _load_state(base_path, case_id)
    if not state.undo_stack:
        log.info("Undo stack empty for case %s", case_id)
        return None

    snapshot = state.undo_stack.pop()
    state.redo_stack.append(snapshot)
    _save_state(base_path, state)

    log.info("Undo: restored snapshot %s for case %s", snapshot.id, case_id)
    return snapshot


def redo(
    base_path: str | Path,
    case_id: str,
) -> Snapshot | None:
    """Pop the most recent snapshot from the redo stack (re-apply).

    Moves the snapshot back to the undo stack.

    Args:
        base_path: Root directory for snapshot storage.
        case_id: The case to redo.

    Returns:
        The re-applied Snapshot, or None if the redo stack is empty.
    """
    state = _load_state(base_path, case_id)
    if not state.redo_stack:
        log.info("Redo stack empty for case %s", case_id)
        return None

    snapshot = state.redo_stack.pop()
    state.undo_stack.append(snapshot)
    _save_state(base_path, state)

    log.info("Redo: re-applied snapshot %s for case %s", snapshot.id, case_id)
    return snapshot


def rollback(
    base_path: str | Path,
    case_id: str,
    *,
    snapshot_id: str | None = None,
) -> Snapshot | None:
    """Rollback a case to a specific snapshot (or the most recent one).

    Unlike ``undo``, this does not move the snapshot to the redo stack —
    it permanently restores to that point. Use ``snapshot_id`` to target
    a specific snapshot, or ``None`` for the most recent.

    Args:
        base_path: Root directory for snapshot storage.
        case_id: The case to rollback.
        snapshot_id: Optional specific snapshot ID to restore.

    Returns:
        The restored Snapshot, or None if not found.
    """
    state = _load_state(base_path, case_id)
    if not state.undo_stack:
        log.info("No snapshots available for case %s", case_id)
        return None

    if snapshot_id:
        target = None
        for i, snap in enumerate(state.undo_stack):
            if snap.id == snapshot_id:
                target = state.undo_stack.pop(i)
                break
        if target is None:
            log.warning("Snapshot %s not found in undo stack for case %s", snapshot_id, case_id)
            return None
    else:
        target = state.undo_stack.pop()

    # Clear redo stack on rollback (destructive operation)
    state.redo_stack.clear()
    _save_state(base_path, state)

    log.info("Rollback to snapshot %s for case %s", target.id, case_id)
    return target


def get_undo_stack(
    base_path: str | Path,
    case_id: str,
) -> list[Snapshot]:
    """List all snapshots in the undo stack (oldest first).

    Args:
        base_path: Root directory for snapshot storage.
        case_id: The case to inspect.

    Returns:
        List of Snapshot objects, ordered oldest to newest.
    """
    state = _load_state(base_path, case_id)
    return list(state.undo_stack)


def get_redo_stack(
    base_path: str | Path,
    case_id: str,
) -> list[Snapshot]:
    """List all snapshots in the redo stack (oldest first).

    Args:
        base_path: Root directory for snapshot storage.
        case_id: The case to inspect.

    Returns:
        List of Snapshot objects, ordered oldest to newest.
    """
    state = _load_state(base_path, case_id)
    return list(state.redo_stack)


def clear_undo_redo(
    base_path: str | Path,
    case_id: str,
) -> None:
    """Clear both undo and redo stacks for a case.

    Does NOT delete the snapshot files on disk (audit trail preserved).

    Args:
        base_path: Root directory for snapshot storage.
        case_id: The case to clear.
    """
    state = UndoRedoState(case_id=case_id)
    _save_state(base_path, state)
    log.info("Cleared undo/redo stacks for case %s", case_id)


def restore_snapshot(snapshot: Snapshot) -> dict[str, Any]:
    """Extract the full case state from a snapshot for restoration.

    The caller is responsible for writing this data back to the case store.

    Args:
        snapshot: The snapshot to restore from.

    Returns:
        Dict with keys ``case_data``, ``findings``, ``evidence``, ``timeline``.
    """
    return {
        "case_data": snapshot.case_data,
        "findings": snapshot.findings,
        "evidence": snapshot.evidence,
        "timeline": snapshot.timeline,
    }


# ---------------------------------------------------------------------------
# File I/O helpers
# ---------------------------------------------------------------------------


def _state_dir(base_path: str | Path, case_id: str) -> Path:
    """Return the directory for a case's undo/redo state."""
    return Path(base_path) / _sanitize_case_id(case_id) / "undo_redo"


def _state_file(base_path: str | Path, case_id: str) -> Path:
    """Return the path to the state JSON file."""
    return _state_dir(base_path, case_id) / "state.json"


def _snapshot_dir(base_path: str | Path, case_id: str) -> Path:
    """Return the directory for individual snapshot files."""
    return _state_dir(base_path, case_id) / "snapshots"


def _load_state(base_path: str | Path, case_id: str) -> UndoRedoState:
    """Load undo/redo state from disk (returns empty state if missing)."""
    state_path = _state_file(base_path, case_id)
    if not state_path.exists():
        return UndoRedoState(case_id=case_id)

    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        undo_stack = [_dict_to_snapshot(d) for d in data.get("undo_stack", [])]
        redo_stack = [_dict_to_snapshot(d) for d in data.get("redo_stack", [])]
        return UndoRedoState(
            case_id=data.get("case_id", case_id),
            undo_stack=undo_stack,
            redo_stack=redo_stack,
        )
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        log.warning("Corrupt undo state for case %s: %s", case_id, exc)
        return UndoRedoState(case_id=case_id)


def _save_state(base_path: str | Path, state: UndoRedoState) -> None:
    """Persist undo/redo state to disk (atomic write)."""
    state_path = _state_file(base_path, state.case_id)
    state_path.parent.mkdir(parents=True, exist_ok=True)

    tmp_path = state_path.with_suffix(".tmp")
    tmp_path.write_text(
        json.dumps(state.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    tmp_path.replace(state_path)


def _save_snapshot_file(base_path: str | Path, snapshot: Snapshot) -> None:
    """Save an individual snapshot file for audit trail."""
    snap_dir = _snapshot_dir(base_path, snapshot.case_id)
    snap_dir.mkdir(parents=True, exist_ok=True)
    snap_file = snap_dir / f"{snapshot.id}.json"
    snap_file.write_text(
        json.dumps(snapshot.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _dict_to_snapshot(data: dict[str, Any]) -> Snapshot:
    """Convert a dict back to a Snapshot dataclass."""
    return Snapshot(
        id=data.get("id", ""),
        case_id=data.get("case_id", ""),
        timestamp=data.get("timestamp", ""),
        description=data.get("description", ""),
        case_data=data.get("case_data", {}),
        findings=data.get("findings", []),
        evidence=data.get("evidence", []),
        timeline=data.get("timeline", []),
        import_source=data.get("import_source", ""),
    )


def _sanitize_case_id(case_id: str) -> str:
    """Sanitize case ID for safe filesystem use (block path traversal)."""
    cleaned = case_id.replace("..", "").replace("/", "").replace("\\", "")
    return cleaned or "unknown"
