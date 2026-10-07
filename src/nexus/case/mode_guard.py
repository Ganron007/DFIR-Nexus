"""WO-R1F item 3 — one mode per case, with lineage.

A case is opened in ONE mode. `D5 = A` (operator, 2026-10-02): modes stay
segregated and are compared as **sibling cases**. The API enforced that
(`dashboard._wrong_mode_error` → 409), but the CLI path did not, so SC1 ended up
with all three modes run on one case and its findings staged four times over
(the reviewer, R1: "all modes ran on one case; findings were staged twice or
more").

This is the shared guard both entry points call. The API keeps its own error
shape; this raises a single exception type the CLI renders and the API maps to
409, so there is one rule with two presentations rather than two rules.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class ModeConflictError(RuntimeError):
    """This case belongs to another mode."""

    def __init__(self, stored: int, expected: int):
        from nexus.langgraph.mode_mapping import mode_label

        self.stored = stored
        self.expected = expected
        super().__init__(
            f"This case is {mode_label(stored)}. "
            f"That action belongs to {mode_label(expected)}. "
            "Run each mode as its own SIBLING case on the same evidence "
            "(D5 = A); `nexus cross-mode` compares them."
        )


def stored_mode(case_dir: Path | str) -> int | None:
    """The canonical mode this case was opened in, or None when unset."""
    import yaml

    case_yaml = Path(case_dir) / "CASE.yaml"
    if not case_yaml.is_file():
        return None
    try:
        meta = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return None
    if not isinstance(meta, dict):
        return None
    raw = meta.get("investigation_mode") or ""
    if not raw:
        return None
    from nexus.langgraph.mode_mapping import resolve_stored_mode

    return resolve_stored_mode(raw, meta.get("mode_scheme"))


def stamp_mode(case_dir: Path | str, mode: int) -> bool:
    """Record the case's mode at its first mode run. Idempotent.

    Returns True when the file changed. Written with the same atomic writer the
    rest of the case stack uses, so a crash mid-write cannot corrupt CASE.yaml.
    """
    import yaml

    case_yaml = Path(case_dir) / "CASE.yaml"
    if not case_yaml.is_file():
        return False
    try:
        meta = yaml.safe_load(case_yaml.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return False
    if not isinstance(meta, dict):
        return False
    if meta.get("investigation_mode"):
        return False
    meta["investigation_mode"] = int(mode)
    meta["mode_scheme"] = "canonical"
    # `sort_keys=False` keeps CASE.yaml human-readable in its own order.
    case_yaml.write_text(yaml.safe_dump(meta, sort_keys=False), encoding="utf-8")
    return True


def check_mode(case_dir: Path | str, mode: int, *, stamp: bool = True) -> None:
    """Refuse a mode that is not this case's. Stamp the mode when unset.

    Refusing is the point: a Mode 1 case cannot start a Mode 2 or Mode 3 run, and
    the reverse. Raising (rather than returning) means no caller can forget to
    check the result.
    """
    current = stored_mode(case_dir)
    if current is None:
        if stamp:
            stamp_mode(case_dir, mode)
        return
    if current != int(mode):
        raise ModeConflictError(current, int(mode))


def mode_of_case(case_dir: Path | str) -> dict[str, Any]:
    """What a caller needs to report the case's mode honestly."""
    from nexus.langgraph.mode_mapping import mode_label

    current = stored_mode(case_dir)
    return {
        "mode": current,
        "label": mode_label(current) if current is not None else "",
    }
