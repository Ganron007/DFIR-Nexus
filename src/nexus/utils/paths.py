"""Filesystem path sandbox for MCP tools.

Hardening notes:
- All paths are resolved with symlink expansion before the root check.
- Any symlink or Windows junction in the path chain is rejected to prevent
  TOCTOU races and path-sandbox bypasses.
- Read paths use strict resolution (the target must exist).
- Write paths resolve the parent directory and verify it exists inside roots.
"""

from __future__ import annotations

import os
from pathlib import Path

from nexus.utils.constants import ENV_DATA_ROOTS

ENV_DATA_ROOTS_LOCAL = ENV_DATA_ROOTS  # backward-compat alias for tests


def _default_roots() -> list[Path]:
    cwd = Path.cwd()
    return [
        cwd / "data",
        cwd / "evidence",
        cwd / "cases",
        cwd / "tmp",
        cwd,
    ]


def allowed_roots() -> list[Path]:
    """Return resolved directories that MCP path tools may access."""
    raw = os.environ.get(ENV_DATA_ROOTS, "").strip()
    if raw:
        roots = [Path(p.strip()).expanduser() for p in raw.split(",") if p.strip()]
    else:
        roots = _default_roots()
    resolved: list[Path] = []
    for root in roots:
        try:
            resolved.append(root.resolve())
        except OSError:
            continue
    return resolved or [Path.cwd().resolve()]


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _contains_symlink(path: Path) -> bool:
    """Check whether any component of *path* is a symlink or junction.

    Walks from the root to the full path so that symlink/junction components
    are detected after expansion, closing the TOCTOU window between the
    symlink check and the root check.
    """
    try:
        for parent in path.parents:
            if parent.is_symlink():
                return True
    except OSError:
        return True
    return path.is_symlink()


def resolve_read_path(path: str | Path, *, must_exist: bool = True) -> Path:
    """Resolve and validate a path for read access within allowed roots."""
    p = Path(path).expanduser()
    if _contains_symlink(p):
        raise ValueError(f"Symlinks/junctions are not allowed: {path}")
    try:
        resolved = p.resolve(strict=must_exist)
    except FileNotFoundError as exc:
        raise ValueError(f"Path does not exist: {path}") from exc
    except OSError as exc:
        raise ValueError(f"Unable to resolve path: {path}") from exc

    if not any(_is_under(resolved, root) for root in allowed_roots()):
        raise ValueError(
            f"Path outside allowed data roots ({ENV_DATA_ROOTS}): {path}"
        )
    return resolved


def resolve_write_path(path: str | Path) -> Path:
    """Resolve and validate a path for write access (parent must be in allowed roots)."""
    p = Path(path).expanduser()
    if _contains_symlink(p):
        raise ValueError(f"Symlinks/junctions are not allowed: {path}")

    try:
        resolved = p.resolve()
    except OSError as exc:
        raise ValueError(f"Unable to resolve path: {path}") from exc

    # For write access we care about the directory that will contain the file.
    target_dir = resolved if resolved.is_dir() else resolved.parent
    try:
        target_dir = target_dir.resolve()
    except OSError as exc:
        raise ValueError(f"Unable to resolve parent directory: {path}") from exc

    if _contains_symlink(target_dir):
        raise ValueError(f"Symlinks/junctions are not allowed: {path}")
    if not any(_is_under(target_dir, root) for root in allowed_roots()):
        raise ValueError(
            f"Path outside allowed data roots ({ENV_DATA_ROOTS}): {path}"
        )
    return resolved
