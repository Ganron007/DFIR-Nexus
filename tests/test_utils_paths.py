"""Tests for nexus.utils.paths — path sandbox helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus.utils.paths import (
    ENV_DATA_ROOTS_LOCAL,
    allowed_roots,
    resolve_read_path,
    resolve_write_path,
)


def test_allowed_roots_default() -> None:
    roots = allowed_roots()
    assert any(r.name == "data" for r in roots)
    assert any(r.name == "evidence" for r in roots)


def test_allowed_roots_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    custom = tmp_path / "custom"
    custom.mkdir()
    monkeypatch.setenv(ENV_DATA_ROOTS_LOCAL, str(custom))
    roots = allowed_roots()
    assert any(_is_same(r, custom) for r in roots)


def _is_same(a: Path, b: Path) -> bool:
    return a.resolve() == b.resolve()


def test_resolve_read_path_inside_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_DATA_ROOTS_LOCAL, str(tmp_path))
    target = tmp_path / "evidence.txt"
    target.write_text("evidence")
    resolved = resolve_read_path(target)
    assert resolved.resolve() == target.resolve()


def test_resolve_read_path_outside_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_DATA_ROOTS_LOCAL, str(tmp_path / "data"))
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    with pytest.raises(ValueError, match="outside allowed"):
        resolve_read_path(outside)


def test_resolve_read_path_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_DATA_ROOTS_LOCAL, str(tmp_path))
    with pytest.raises(ValueError, match="does not exist"):
        resolve_read_path(tmp_path / "missing.txt")


def test_resolve_write_path_inside_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_DATA_ROOTS_LOCAL, str(tmp_path))
    (tmp_path / "subdir").mkdir(parents=True, exist_ok=True)
    resolved = resolve_write_path(tmp_path / "subdir" / "out.txt")
    assert resolved.resolve() == (tmp_path / "subdir" / "out.txt").resolve()


def test_resolve_write_path_outside_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_DATA_ROOTS_LOCAL, str(tmp_path / "data"))
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError, match="outside allowed"):
        resolve_write_path(tmp_path / "outside.txt")


def test_resolve_read_path_rejects_symlink(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_DATA_ROOTS_LOCAL, str(tmp_path))
    real = tmp_path / "real.txt"
    real.write_text("secret")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlinks not supported on this platform")
    with pytest.raises(ValueError, match="Symlinks"):
        resolve_read_path(link)


def test_resolve_write_path_creates_parent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_DATA_ROOTS_LOCAL, str(tmp_path))
    (tmp_path / "out").mkdir(parents=True, exist_ok=True)
    resolved = resolve_write_path(tmp_path / "out" / "new.txt")
    assert resolved == tmp_path / "out" / "new.txt"
