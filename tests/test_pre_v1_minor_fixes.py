"""Regression tests for pre-v1 minor bug fixes and CI script isolation."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

from typer.testing import CliRunner


def test_nexus_update_check_uses_upstream_or_origin_master(monkeypatch, tmp_path):
    """nexus update --check handles repos whose trunk is origin/master (not origin/main)."""
    from nexus.cli import main as cli_main

    fake_repo = tmp_path / "repo"
    (fake_repo / ".git").mkdir(parents=True)
    cli_dir = fake_repo / "src" / "nexus" / "cli"
    cli_dir.mkdir(parents=True)
    fake_main_file = cli_dir / "main.py"
    fake_main_file.write_text("# stub", encoding="utf-8")

    monkeypatch.setattr(cli_main, "__file__", str(fake_main_file))

    def fake_run(cmd, **_kwargs):
        if cmd[:2] == ["git", "rev-parse"]:
            target = cmd[-1]
            if target == "HEAD":
                return SimpleNamespace(returncode=0, stdout="11111111aaaa\n", stderr="")
            if target == "@{u}":
                return SimpleNamespace(returncode=0, stdout="origin/master\n", stderr="")
            if target == "origin/master":
                return SimpleNamespace(returncode=0, stdout="22222222bbbb\n", stderr="")
            return SimpleNamespace(returncode=128, stdout="", stderr="fatal")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = CliRunner().invoke(cli_main.app, ["update", "--check"])
    assert result.exit_code == 0
    assert "11111111 -> 22222222" in result.output


def test_apply_env_writes_atomically_via_replace(monkeypatch, tmp_path):
    """apply_env uses atomic.replace and leaves no temp artifacts behind."""
    from nexus import envfile
    from nexus.utils import atomic

    env_path = tmp_path / ".env"
    env_path.write_text("# existing\nNEXUS_LLM_MODEL=old\n", encoding="utf-8")
    replace_calls: list[tuple[str, str]] = []
    orig_replace = atomic.replace

    def spy_replace(src, dst):
        replace_calls.append((str(src), str(dst)))
        return orig_replace(src, dst)

    monkeypatch.setattr(envfile, "env_file_path", lambda: env_path)
    monkeypatch.setattr(atomic, "replace", spy_replace)

    env: dict[str, str] = {}
    envfile.apply_env({"NEXUS_LLM_MODEL": "new-model"}, environ=env)

    assert len(replace_calls) == 1
    assert replace_calls[0][1] == str(env_path)
    assert "NEXUS_LLM_MODEL=new-model" in env_path.read_text(encoding="utf-8")
    assert not any(p.suffix == ".tmp" for p in tmp_path.iterdir())


def test_recycle_bin_handles_ragged_csv_none_cells_and_unique_ids(tmp_path):
    """parse_rbcmd_csv handles None CSV values and multi-file scans produce unique IDs."""
    from nexus.recovery.recycle_bin_browser import scan_recycle_bin

    case_dir = tmp_path / "CASE-RB-01"
    rb_dir = case_dir / "extractions" / "RBCmd"
    rb_dir.mkdir(parents=True)

    # First CSV has a ragged row with fewer columns (DictReader produces None value).
    (rb_dir / "RBCmd_1.csv").write_text(
        "SourceFile,DeletedOn,OriginalPath,FileSize\n"
        "$I1.txt,2026-11-01 00:00:00\n",
        encoding="utf-8",
    )
    (rb_dir / "RBCmd_2.csv").write_text(
        "SourceFile,DeletedOn,OriginalPath,FileSize\n"
        "$I2.exe,2026-11-02 00:00:00,C:\\Temp\\evil.exe,123\n",
        encoding="utf-8",
    )

    items = scan_recycle_bin(case_dir)
    assert len(items) == 2
    assert len({it.id for it in items}) == 2


def test_deleted_files_multi_file_scan_produces_unique_ids(tmp_path):
    """scan_deleted_files produces unique del_* IDs across multiple fls files."""
    from nexus.recovery.deleted_files_browser import scan_deleted_files

    case_dir = tmp_path / "CASE-DEL-01"
    fls_dir = case_dir / "extractions" / "fls"
    fls_dir.mkdir(parents=True)

    (fls_dir / "fls_part1.txt").write_text(
        "r/r * 101:  C:/Temp/a.exe\n", encoding="utf-8"
    )
    (fls_dir / "fls_part2.txt").write_text(
        "r/r * 202:  C:/Temp/b.exe\n", encoding="utf-8"
    )

    items = scan_deleted_files(case_dir)
    assert len(items) == 2
    assert len({it.id for it in items}) == 2


def test_ci_scripts_redirect_audit_secret_for_clean_home(tmp_path):
    """Standalone CI scripts explicitly isolate NEXUS_AUDIT_SECRET and secrets path."""
    root = Path(__file__).resolve().parent.parent
    for rel in ("tests/test_integration.py", "tests/functional_audit.py"):
        text = (root / rel).read_text(encoding="utf-8")
        assert 'NEXUS_AUDIT_SECRET' in text
        assert '_PERSISTED_SECRET_PATH' in text


def test_case_pipeline_refusal_handles_windows_and_posix_paths(tmp_path):
    """case_pipeline_refusal handles POSIX /... tokens alongside Windows /Switch:C:\\... paths."""
    from nexus.tools.windows import case_pipeline_refusal

    bound_dir = tmp_path / "evidence"
    bound_dir.mkdir()
    sample = bound_dir / "Security.evtx"
    sample.write_bytes(b"ElfFile")
    win_switch_with_path = f"/LogFileFile:{sample}"

    assert case_pipeline_refusal("logfileparser", ["logfileparser", win_switch_with_path], [bound_dir]) is None
    assert case_pipeline_refusal("evtxecmd", ["evtxecmd", f"--file={sample}"], [bound_dir]) is None
    assert case_pipeline_refusal("evtxecmd", ["evtxecmd", "-f", "/etc/passwd"], [bound_dir]) is not None
    assert case_pipeline_refusal("cmd", ["cmd", "/c", "del", "x"], [bound_dir]) is not None
