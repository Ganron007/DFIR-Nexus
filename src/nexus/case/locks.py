"""WO-14: one process-wide lock per case for flat-file read-modify-write.

Architecture invariant #8 (atomic writes) stops a mid-write corruption; it does
not stop two writers from losing an update between a read and a write. WO-1
moved MCP tools into worker threads and removed the accidental serialization
the blocking loop provided; this module restores it explicitly for the flat
case files (``findings.json``, ``timeline.json``, ``iocs.json``,
``todos.json``, ``evidence_registry.json``, ``CASE.yaml``).

Scope: **one process** (the ``serve`` process / the CLI process). Cross-process
safety — a CLI ``nexus approve`` racing a running ``serve`` — is out of scope
and recorded as open in ``Docs/internal/NEXT-WORK-ORDERS.md`` (WO-14).

Reentrant by design: a locked caller may call another locked helper (staging a
finding also rebuilds the timeline, for example).
"""
from __future__ import annotations

import functools
import inspect
import threading
from pathlib import Path

_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()


def _case_key(case_dir: Path | str) -> str:
    try:
        return str(Path(case_dir).resolve())
    except OSError:  # pragma: no cover - unresolvable path
        return str(case_dir)


def case_lock(case_dir: Path | str) -> threading.RLock:
    """The process-wide, reentrant lock for one case's flat-file writes."""
    key = _case_key(case_dir)
    with _LOCKS_GUARD:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _LOCKS[key] = lock
        return lock


def lock_case_writes(fn=None, *, case_arg: str | int = "case_dir"):
    """Serialize a case-file writer under its case's lock (WO-14).

    Resolves the case from the call's ``case_dir`` argument (by name, or by
    positional index when the parameter is not literally named ``case_dir``).
    When the case cannot be resolved the function runs unchanged, so a call
    that is about to fail on an unknown case does not deadlock first.
    """

    def _deco(f):
        sig = inspect.signature(f)
        params = list(sig.parameters)

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            case_dir = None
            if isinstance(case_arg, int):
                if 0 <= case_arg < len(args):
                    case_dir = args[case_arg]
                elif case_arg < len(params) and params[case_arg] in kwargs:
                    case_dir = kwargs[params[case_arg]]
            else:
                if case_arg in kwargs:
                    case_dir = kwargs.get(case_arg)
                elif case_arg in params:
                    idx = params.index(case_arg)
                    if idx < len(args):
                        case_dir = args[idx]
            if case_dir is None:
                return f(*args, **kwargs)
            with case_lock(case_dir):
                return f(*args, **kwargs)

        return wrapper

    if fn is not None:
        return _deco(fn)
    return _deco
