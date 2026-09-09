"""Tests for case cleanup tooling (post-testing hygiene).

- `nexus case clean` CLI command
- serve debug auto-clean helper
"""
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nexus.cli.case_cmd import app as case_app


@pytest.fixture()
def isolated_cases(tmp_path, monkeypatch):
    """Redirect cases_root + active-case pointer into tmp.

    settings is a singleton — patch the attribute directly so tests are
    order-independent regardless of import order.
    """
    from nexus.config import settings

    root = tmp_path / "cases"
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(root))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "cases_root", root, raising=False)
    import nexus.cli.case_cmd as cc

    monkeypatch.setattr(cc, "_ACTIVE_CASE_FILE", tmp_path / "active_case", raising=False)
    return tmp_path


def test_case_clean_removes_all(isolated_cases):
    """`case clean --yes` removes case folders + DB + active pointer."""
    from nexus.cli.case_cmd import _ACTIVE_CASE_FILE
    from nexus.config import settings

    root = settings.cases_root
    (root / "CASE-AAAABBBB").mkdir(parents=True, exist_ok=True)
    (root / "CASE-CCCCDDDD").mkdir(parents=True, exist_ok=True)
    (root / "cases.db").write_bytes(b"")
    _ACTIVE_CASE_FILE_dummy = Path("x")  # noqa: F841 — pointer reset asserted below

    result = CliRunner().invoke(case_app, ["clean", "--yes"])
    assert result.exit_code == 0, result.output
    assert "Cleaned 2 case folder(s)" in result.output
    assert not (root / "cases.db").exists()
    assert list(root.glob("CASE-*")) == []
    # active-case pointer reset to empty

    assert _ACTIVE_CASE_FILE.read_text() == ""


def test_case_clean_keep(isolated_cases):
    """`--keep` preserves named cases."""
    from nexus.config import settings

    root = settings.cases_root
    (root / "CASE-AAAABBBB").mkdir(parents=True, exist_ok=True)
    (root / "CASE-CCCCDDDD").mkdir(parents=True, exist_ok=True)

    result = CliRunner().invoke(case_app, ["clean", "--yes", "--keep", "CASE-AAAABBBB"])
    assert result.exit_code == 0, result.output
    assert "kept: CASE-AAAABBBB" in result.output
    remaining = [p.name for p in root.glob("CASE-*")]
    assert remaining == ["CASE-AAAABBBB"]


def test_case_clean_nothing_to_clean(isolated_cases):
    from nexus.cli.case_cmd import app as case_app

    result = CliRunner().invoke(case_app, ["clean", "--yes"])
    assert result.exit_code == 0
    assert "No cases to clean" in result.output


def test_debug_autoclean_cases(isolated_cases):
    """serve debug auto-clean wipes case folders + DB + active pointer."""
    from nexus.cli.main import _debug_autoclean_cases
    from nexus.config import settings

    root = settings.cases_root
    (root / "CASE-AAAABBBB").mkdir(parents=True, exist_ok=True)
    (root / "cases.db").write_bytes(b"")

    removed = _debug_autoclean_cases()
    assert removed == 1
    assert list(root.glob("CASE-*")) == []
    assert not (root / "cases.db").exists()
