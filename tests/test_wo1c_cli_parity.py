"""WO-1C item 6 — CLI/API parity for the context policy and cross-mode.

D5 = C puts all three modes on one case, so the CLI and the portal must offer
the same two knobs: the context policy on each mode's run command, and a
cross-mode comparison over the runs a single case now holds.

These tests are about the surface, not the modes:

* ``nexus mode2 run --context informed`` and ``nexus mode3 run --context
  informed`` must reach the runtime with that policy (before this, the CLI had
  no flag at all and silently ran independent).
* ``nexus pipeline --context informed`` must reach ``run_pipeline``.
* ``nexus cross-mode --case <id>`` must compare one case's own runs, which is
  the shape D5 = C produces; without ``--case`` the command demanded two
  positional case ids and a one-case comparison was impossible.
* ``collect_mode_claims`` must read Mode 1's ``M1-`` run records — the
  comparison reported "Mode 1 not run" for a case whose Mode 1 run had
  produced candidates.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from nexus.analysis.cross_mode import check_cross_mode, collect_mode_claims

# --------------------------------------------------------------------------
# Mode 1 claim collection (the "not run" lie)
# --------------------------------------------------------------------------

def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_collect_mode_claims_reads_mode1_run_records(tmp_path: Path) -> None:
    """A Mode 1 analysis run's candidates are claims, like Mode 2/3's."""
    (tmp_path / "CASE.yaml").write_text("case_id: CASE-X\n", encoding="utf-8")
    _write_json(tmp_path / "findings.json", [])
    _write_json(
        tmp_path / "analysis" / "pipeline_runs" / "M1-20261009T120000-abcdef.json",
        {
            "run_id": "M1-20261009T120000-abcdef",
            "mode": "interpret",
            "status": "complete",
            "candidates": [
                {
                    "title": "lsass.exe executed",
                    "audit_ids": ["aud-1"],
                    "polarity": "affirm",
                    "claim_kind": "observation",
                }
            ],
        },
    )

    by_mode = collect_mode_claims(tmp_path)
    assert by_mode["1"], "Mode 1 run candidates must be collected"
    assert by_mode["1"][0]["mode"] == "1"


def test_collect_mode_claims_ignores_non_analysis_pipeline_runs(tmp_path: Path) -> None:
    """A tools/lane run is not an analysis run and contributes no claims."""
    _write_json(tmp_path / "findings.json", [])
    _write_json(
        tmp_path / "analysis" / "pipeline_runs" / "9f3a1c2d.json",
        {
            "run_id": "9f3a1c2d",
            "mode": "tools",
            "status": "complete",
            "candidates": [{"title": "lsass.exe executed", "audit_ids": ["aud-1"]}],
        },
    )
    _write_json(
        tmp_path / "analysis" / "pipeline_runs" / "M1-20261009T120000-abcdef.json",
        {
            "run_id": "M1-20261009T120000-abcdef",
            "mode": "coverage",
            "status": "complete",
            "candidates": [],
        },
    )
    by_mode = collect_mode_claims(tmp_path)
    assert not by_mode["1"], "a tools run must not be read as a Mode 1 analysis run"


def test_collect_mode_claims_reads_mode1_full_run(tmp_path: Path) -> None:
    """``analysis/mode1_full_run.json`` is the other Mode 1 record shape."""
    _write_json(tmp_path / "findings.json", [])
    _write_json(
        tmp_path / "analysis" / "mode1_full_run.json",
        {
            "run_id": "mode1_full_run",
            "candidates": [
                {"id": "F-1", "title": "cmd.exe executed", "audit_ids": ["aud-2"]}
            ],
        },
    )
    by_mode = collect_mode_claims(tmp_path)
    assert by_mode["1"], "the Mode 1 full-run record must be collected"
    assert by_mode["1"][0]["mode"] == "1"
    assert by_mode["1"][0]["source"] == "finding:F-1"


def test_one_case_three_modes_are_all_seen(tmp_path: Path) -> None:
    """The D5 = C shape: one case, M1 + M2 + M3, all three compared."""
    _write_json(tmp_path / "findings.json", [])
    _write_json(
        tmp_path / "analysis" / "pipeline_runs" / "M1-20261009T120000-abcdef.json",
        {
            "run_id": "M1-20261009T120000-abcdef",
            "candidates": [{"title": "lsass.exe executed", "audit_ids": ["a"]}],
        },
    )
    _write_json(
        tmp_path / "analysis" / "mode2_runs" / "M2-20261009T130000-abcdef.json",
        {
            "run_id": "M2-20261009T130000-abcdef",
            "candidates": [{"title": "lsass.exe executed", "audit_ids": ["b"]}],
        },
    )
    _write_json(
        tmp_path / "analysis" / "mode3_runs" / "M3-20261009T140000-abcdef.json",
        {
            "run_id": "M3-20261009T140000-abcdef",
            "candidates": [{"title": "lsass.exe executed", "audit_ids": ["c"]}],
        },
    )

    result = check_cross_mode(case_dir=tmp_path)
    assert result["modes_present"] == [
        "Mode 1 (LLM)", "Mode 2 (multi-role)", "Mode 3 (multi-agent)"
    ]
    assert not result["modes_missing"]
    assert result["counts"]["contradictions"] == 0
    assert result["counts"]["shared"] >= 1


# --------------------------------------------------------------------------
# CLI parity — the context policy flag
# --------------------------------------------------------------------------

def _case(tmp_path: Path, name: str) -> Path:
    case_dir = tmp_path / name
    (case_dir / "analysis").mkdir(parents=True, exist_ok=True)
    (case_dir / "CASE.yaml").write_text(f"case_id: {name}\n", encoding="utf-8")
    return case_dir


def test_mode2_run_accepts_context_flag(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`nexus mode2 run --context informed` must reach run_mode2."""
    from typer.testing import CliRunner

    from nexus.cli import main as cli_main

    seen: dict[str, Any] = {}
    case_dir = _case(tmp_path, "CASE-PARITY")
    monkeypatch.setattr("nexus.cli.mode2_cmd._case_dir", lambda c: case_dir)
    monkeypatch.setattr("nexus.langgraph.lane_gate.lane_gate_blocked",
                        lambda c: None)
    monkeypatch.setattr("nexus.case.sift_preflight.sift_preflight_message",
                        lambda c: "")

    def _fake_run(case, question, **kwargs):
        seen.update(kwargs)
        return {"run_id": "M2-x", "status": "completed", "orders": [],
                "order_index": 0, "candidates": [], "stop_reason": ""}

    monkeypatch.setattr("nexus.modes.multi_role.run_mode2", _fake_run)

    runner = CliRunner()
    result = runner.invoke(cli_main.app, ["mode2", "run", "--context", "informed",
                                          "--case", "CASE-PARITY"])
    assert result.exit_code == 0, result.output
    assert seen.get("context_policy") == "informed"


def test_mode3_run_accepts_context_flag(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """`nexus mode3 run --context informed` must reach run_mode3."""
    from typer.testing import CliRunner

    from nexus.cli import main as cli_main

    seen: dict[str, Any] = {}
    case_dir = _case(tmp_path, "CASE-PARITY3")
    monkeypatch.setattr("nexus.cli.mode3_cmd._case_dir", lambda c: case_dir)
    monkeypatch.setattr("nexus.langgraph.lane_gate.lane_gate_blocked",
                        lambda c: None)
    monkeypatch.setattr("nexus.case.sift_preflight.sift_preflight_message",
                        lambda c: "")

    def _fake_run(case, question, **kwargs):
        seen.update(kwargs)
        return {"run_id": "M3-x", "status": "completed", "candidates": []}

    monkeypatch.setattr("nexus.modes.multi_agent.run_mode3", _fake_run)

    runner = CliRunner()
    result = runner.invoke(cli_main.app, ["mode3", "run", "--context", "informed",
                                          "--case", "CASE-PARITY3"])
    assert result.exit_code == 0, result.output
    assert seen.get("context_policy") == "informed"


def test_pipeline_accepts_context_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """`nexus pipeline --context informed` must reach run_pipeline."""
    import asyncio

    from typer.testing import CliRunner

    from nexus.cli import main as cli_main

    seen: dict[str, Any] = {}
    monkeypatch.setattr(cli_main, "_resolve_case", lambda cid: None)
    monkeypatch.setattr(asyncio, "run", lambda coro, **kw: None)

    def _fake_pipeline(**kwargs):
        seen.update(kwargs)

    monkeypatch.setattr("nexus.langgraph.llm_pipeline.run_pipeline", _fake_pipeline)

    runner = CliRunner()
    result = runner.invoke(
        cli_main.app,
        ["pipeline", "--from-case", "CASE-CTX", "--mode", "interpret",
         "--context", "informed"],
    )
    assert result.exit_code == 0, result.output
    assert seen.get("context_policy") == "informed"


def test_cross_mode_case_flag_compares_one_cases_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """`nexus cross-mode --case <id>` must run the single-case comparison.

    Before this, ``cross-mode`` took two or more positional case ids and exited
    2 for anything less, so the D5 = C shape (one case, three modes) had no CLI
    at all — the examiner had to know to pass the same case twice.
    """
    from typer.testing import CliRunner

    from nexus.cli import main as cli_main

    case_dir = _case(tmp_path, "CASE-ONE")
    _write_json(
        case_dir / "analysis" / "pipeline_runs" / "M1-20261009T120000-abcdef.json",
        {"run_id": "M1-20261009T120000-abcdef",
         "candidates": [{"title": "lsass.exe executed", "audit_ids": ["a"]}]},
    )
    _write_json(
        case_dir / "analysis" / "mode2_runs" / "M2-20261009T130000-abcdef.json",
        {"run_id": "M2-20261009T130000-abcdef",
         "candidates": [{"title": "lsass.exe executed", "audit_ids": ["b"]}]},
    )
    _write_json(tmp_path / "CASE-ONE" / "findings.json", [])

    monkeypatch.setattr("nexus.config.settings.cases_root", tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli_main.app, ["cross-mode", "--case", "CASE-ONE"])
    assert result.exit_code == 0, result.output
    # Both modes were compared: they share the one entity each named, which is
    # only true if the M1 run record was read at all.
    assert "- 1-2: 1.0" in result.output
    assert "Intra-case consistency" in result.output


def test_cross_mode_positional_still_requires_two_cases(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    """The sibling form is unchanged: one positional case is still an error."""
    from typer.testing import CliRunner

    from nexus.cli import main as cli_main

    monkeypatch.setattr("nexus.config.settings.cases_root", tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli_main.app, ["cross-mode", "CASE-NOPE"])
    assert result.exit_code == 2
