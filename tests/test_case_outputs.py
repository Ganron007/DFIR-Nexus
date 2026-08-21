"""Tool-output persistence into active case extractions (design contract)."""

from __future__ import annotations

import json
from pathlib import Path

from nexus.case.outputs import persist_tool_output, resolve_active_case_dir


def test_persist_tool_output_writes_extractions_and_evidence(tmp_path: Path, monkeypatch):
    case = tmp_path / "CASE-TESTOUT"
    (case / "extractions").mkdir(parents=True)
    (case / "evidence.json").write_text("[]", encoding="utf-8")
    (case / "CASE.yaml").write_text("case_id: CASE-TESTOUT\nname: t\n", encoding="utf-8")

    active = tmp_path / "active_case"
    active.write_text(str(case), encoding="utf-8")
    monkeypatch.setattr("nexus.case.outputs._ACTIVE_CASE_FILE", active)
    monkeypatch.delenv("NEXUS_CASE_DIR", raising=False)

    # Force resolve via active_case file (skip CaseManager if it fails)
    monkeypatch.setattr(
        "nexus.case.outputs.resolve_active_case_dir",
        lambda: case,
    )

    result = persist_tool_output(
        tool_key="vol",
        stdout="Volatility 3 Framework\nWin10",
        stderr="",
        command="vol -f mem.raw windows.info",
        purpose="host profile",
        case_dir=case,
        register_evidence=True,
    )

    assert result["warning"] == ""
    files = result["output_files"]
    assert any(f["kind"] == "stdout" for f in files)
    assert any(f["kind"] == "meta" for f in files)
    stdout_path = Path(next(f["path"] for f in files if f["kind"] == "stdout"))
    assert stdout_path.is_file()
    assert "Win10" in stdout_path.read_text(encoding="utf-8")
    assert stdout_path.parent.name == "vol"

    evidence = json.loads((case / "evidence.json").read_text(encoding="utf-8"))
    assert len(evidence) == 1
    assert evidence[0]["kind"] == "tool_extraction"
    assert evidence[0]["sha256"]
    assert result["evidence_register"]["status"] == "registered"


def test_persist_without_case_warns(monkeypatch):
    monkeypatch.setattr("nexus.case.outputs.resolve_active_case_dir", lambda: None)
    result = persist_tool_output(tool_key="ls", stdout="a\n", case_dir=None)
    assert result["output_files"] == []
    assert "No active case" in result["warning"]


def test_resolve_active_case_dir_env(tmp_path: Path, monkeypatch):
    case = tmp_path / "INC-ENV"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: INC-ENV\n", encoding="utf-8")
    monkeypatch.setenv("NEXUS_CASE_DIR", str(case))
    monkeypatch.setattr(
        "nexus.case.outputs._ACTIVE_CASE_FILE",
        tmp_path / "missing_active",
    )

    class _Boom:
        def resolve_case_dir(self, *a, **k):
            raise RuntimeError("no mgr")

    monkeypatch.setattr("nexus.case_manager.CaseManager", _Boom)
    resolved = resolve_active_case_dir()
    assert resolved == case


def test_resolve_active_case_dir_relative_id(tmp_path: Path, monkeypatch):
    """ID-only active_case must resolve under settings.cases_root, not ~/.nexus/cases."""
    cases_root = tmp_path / "cases"
    case = cases_root / "INC-REL"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text("case_id: INC-REL\n", encoding="utf-8")
    active = tmp_path / "home" / ".nexus" / "active_case"
    active.parent.mkdir(parents=True)
    active.write_text("INC-REL", encoding="utf-8")
    monkeypatch.setattr("nexus.case.outputs._ACTIVE_CASE_FILE", active)
    monkeypatch.delenv("NEXUS_CASE_DIR", raising=False)

    class _Boom:
        def resolve_case_dir(self, *a, **k):
            raise RuntimeError("no mgr")

    monkeypatch.setattr("nexus.case_manager.CaseManager", _Boom)
    monkeypatch.setattr("nexus.config.settings.cases_root", cases_root)
    assert resolve_active_case_dir() == case


def test_cli_resolve_case_uses_cases_root(tmp_path: Path, monkeypatch):
    cases_root = tmp_path / "cases"
    case = cases_root / "INC-CLI"
    case.mkdir(parents=True)
    monkeypatch.setattr("nexus.config.settings.cases_root", cases_root)
    from nexus.cli.main import _resolve_case

    assert _resolve_case("INC-CLI") == case


def test_report_normalize_case_ref_strips_path(tmp_path: Path, monkeypatch):
    cases_root = tmp_path / "cases"
    case = cases_root / "INC-20260815074250"
    case.mkdir(parents=True)
    monkeypatch.setattr("nexus.config.settings.cases_root", cases_root)
    from nexus.cli.report import _normalize_case_ref

    cid, resolved = _normalize_case_ref(str(case))
    assert cid == "INC-20260815074250"
    assert resolved == case
    cid2, resolved2 = _normalize_case_ref("INC-20260815074250")
    assert cid2 == "INC-20260815074250"
    assert resolved2 == case
    from nexus.integration.dfir_report import build_dfir_markdown

    md = build_dfir_markdown(
        case_id="INC-1",
        case_name="Rocba",
        findings=[],
        evidence=[],
        case_summary="Rocba FOR500 host triage — Win10 memory + E01 disk.",
    )
    assert "Rocba FOR500 host triage" in md
    assert "Zeek" not in md
    assert "CADRE" not in md


def test_case_context_and_audit_id_harvest():
    from nexus.langgraph.llm_pipeline import (
        _audit_ids_from_messages,
        _format_case_context,
        _is_tool_audit_id,
        make_initial_state,
    )

    empty = _format_case_context({})
    assert "No examiner case narrative" in empty
    assert "APT" in empty or "threat actors" in empty

    insider = _format_case_context({
        "name": "Rocba",
        "hypothesis": "Insider threat / authorized-user misuse",
        "host": "SRL-FORGE",
    })
    assert "Insider threat" in insider
    assert "SRL-FORGE" in insider

    assert _is_tool_audit_id("nexus-e2e_host-20260812-001")
    assert _is_tool_audit_id("smoke-sansforensics-20260812-001")
    assert not _is_tool_audit_id("abc123deadbeef")

    aids = _audit_ids_from_messages([
        {"content": 'audit_id": "nexus-e2e_host-20260812-042" output_saved_to'},
        {"content": "also smoke-sansforensics-20260812-001 and garbage"},
    ])
    assert "nexus-e2e_host-20260812-042" in aids
    assert "smoke-sansforensics-20260812-001" in aids

    st = make_initial_state("H:/C", case_context={"hypothesis": "insider"})
    assert st["case_context"]["hypothesis"] == "insider"
