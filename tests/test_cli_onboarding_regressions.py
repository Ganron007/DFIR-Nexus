"""Regression tests for GitHub issue: README config/init commands must work.

Reported: `nexus config --examiner X` errored ("No such option") and
`nexus init "Case" --evidence ...` errored ("No such command"). Both
documented forms must work; subcommand forms must keep working.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from nexus.cli.main import app
from nexus.config import settings

runner = CliRunner()


@pytest.fixture()
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(settings, "cases_root", tmp_path / "cases")
    monkeypatch.setattr(settings, "data_root", tmp_path / "data")
    return tmp_path


class TestConfigReadmeForm:
    def test_config_examiner_flag(self, isolated_home):
        result = runner.invoke(app, ["config", "--examiner", "jane-doe"])
        assert result.exit_code == 0, result.output
        assert "Examiner set to: jane-doe" in result.output
        cfg = (isolated_home / ".nexus" / "config.yaml").read_text()
        assert "jane-doe" in cfg

    def test_config_show_flag(self, isolated_home):
        runner.invoke(app, ["config", "--examiner", "jane-doe"])
        result = runner.invoke(app, ["config", "--show"])
        assert result.exit_code == 0, result.output
        assert "jane-doe" in result.output

    def test_config_set_subcommand_still_works(self, isolated_home):
        result = runner.invoke(app, ["config", "set", "--examiner", "jane-doe"])
        assert result.exit_code == 0, result.output
        assert "Examiner set to: jane-doe" in result.output

    def test_config_show_subcommand_still_works(self, isolated_home):
        runner.invoke(app, ["config", "set", "--examiner", "jane-doe"])
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0, result.output
        assert "jane-doe" in result.output


class TestInitReadmeForm:
    def test_init_positional_case_and_evidence(self, isolated_home):
        ev = isolated_home / "disk-sample.raw"
        ev.write_bytes(b"\x00\x01\x02evidence-bytes")
        result = runner.invoke(
            app, ["init", "GitHub Issue Case", "--evidence", str(ev)]
        )
        assert result.exit_code == 0, result.output
        assert "Case created" in result.output
        assert "Evidence registered" in result.output

        from nexus.case import CaseManager

        mgr = CaseManager(settings.cases_root / "cases.db")
        cases = mgr.list_cases()
        assert len(cases) == 1
        assert cases[0].name == "GitHub Issue Case"
        evidence = mgr.list_evidence(cases[0].id)
        assert len(evidence) == 1
        assert evidence[0].file_hash_sha256
        mgr.close()

        active = (isolated_home / ".nexus" / "active_case").read_text().strip()
        assert active == cases[0].id

    def test_init_repeated_evidence(self, isolated_home):
        a = isolated_home / "a.log"
        b = isolated_home / "b.log"
        a.write_text("line one\n")
        b.write_text("line two\n")
        result = runner.invoke(
            app,
            ["init", "Multi", "--evidence", str(a), "--evidence", str(b)],
        )
        assert result.exit_code == 0, result.output
        assert result.output.count("Evidence registered") == 2

    def test_init_missing_evidence_skips_cleanly(self, isolated_home):
        result = runner.invoke(
            app, ["init", "X", "--evidence", str(isolated_home / "nope.raw")]
        )
        assert result.exit_code == 0, result.output
        assert "skipping" in result.output

    def test_init_no_args_still_ondboards(self, isolated_home):
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0, result.output
        assert "Quickstart complete" in result.output
