"""Case-start preflight gate (WIRING-PLAN 5.2) - `nexus doctor --gate`.

The contract under test:
- a **required** failure makes the gate fail (non-zero exit),
- a **warn** failure is reported but does not block,
- **Mode 2/3 refuse to run without Elasticsearch**, so for those cases ES + a
  built case index are required and the refusal is named explicitly,
- Mode 1 treats missing ES as degraded-but-working (tools lane + CSV backend),
- a probe that crashes becomes a failed item, never an exception,
- there is always an ordered fix list when the gate fails.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nexus import preflight
from nexus.preflight import REQUIRED, WARN, format_report, run_gate

runner = CliRunner()


def _case(tmp_path: Path, mode: str | None = "2", *, docs: int | None = 120) -> Path:
    """A minimal case dir: CASE.yaml with the stored mode + index_state.json."""
    case = tmp_path / "CASE-TEST01"
    (case / "analysis").mkdir(parents=True)
    if mode is not None:
        (case / "CASE.yaml").write_text(
            f"name: Test\ninvestigation_mode: \"{mode}\"\nmode_scheme: 2\n", encoding="utf-8"
        )
    if docs is not None:
        (case / "analysis" / "index_state.json").write_text(
            json.dumps({"docs": docs, "capped": False, "index": "case-test01", "indexed_at": "2026-09-26T00:00:00+00:00"}),
            encoding="utf-8",
        )
    return case


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """No network, no real case store, deterministic probes."""
    monkeypatch.setenv("NEXUS_CASE_DIR", "")
    monkeypatch.delenv("NEXUS_CASE_DIR", raising=False)
    monkeypatch.setattr(preflight, "_resolve_case", lambda: ("", None))
    monkeypatch.setattr(
        preflight, "_mcp_probe", lambda: (True, ""), raising=False
    )
    monkeypatch.setattr(preflight, "_triage_probe", lambda: (True, "present"))
    monkeypatch.setattr(preflight, "_kb_probe", lambda: (True, "kb.py"))
    monkeypatch.setattr(preflight, "_knowledge_probe", lambda: (True, "8 feeds, 7430 entries"))
    monkeypatch.setattr(preflight, "_rag_probe", lambda: (True, "bge via hf_hub_cache", True))


def test_report_ok_when_no_required_failures():
    report = preflight.GateReport()
    report.add("a", True, "fine")
    report.add("b", False, "degraded", "fix b", WARN)
    assert report.ok is True
    assert report.failures == []
    assert [w.name for w in report.warnings] == ["b"]


def test_warnings_include_not_ok_items_only():
    """A warn-severity item that passed must not be listed as a warning."""
    report = preflight.GateReport()
    report.add("a", True, "fine", "do the thing", WARN)
    assert report.warnings == []
    assert report.ok is True


def test_required_failure_fails_the_gate():
    report = preflight.GateReport()
    report.add("a", False, "broken", "fix a", REQUIRED)
    assert report.ok is False
    assert [f.name for f in report.failures] == ["a"]


def test_mode2_without_elasticsearch_is_a_required_failure(monkeypatch, tmp_path):
    case = _case(tmp_path, mode="2")
    monkeypatch.setattr(
        preflight, "_es_probe", lambda: (False, "NEXUS_ES_URL unset — CSV pack backend only")
    )
    report = run_gate(case_dir=case)
    assert report.mode == 2
    assert report.ok is False
    names = [f.name for f in report.failures]
    assert "elasticsearch" in names
    # The refusal is named, not just the probe.
    assert any("elasticsearch_required" in f.detail for f in report.failures)


def test_mode1_without_elasticsearch_is_only_a_warning(monkeypatch, tmp_path):
    case = _case(tmp_path, mode="1")
    monkeypatch.setattr(preflight, "_es_probe", lambda: (False, "unreachable"))
    report = run_gate(case_dir=case)
    assert report.mode == 1
    assert "elasticsearch" not in [f.name for f in report.failures]
    assert "elasticsearch" in [w.name for w in report.warnings]
    # The degraded path is named explicitly rather than silently accepted.
    fallback = [i for i in report.items if i.name == "csv backend fallback"]
    assert fallback and fallback[0].ok is True
    assert "Modes 2/3 will require ES" not in fallback[0].detail


def test_no_case_with_es_down_says_modes_2_3_will_require_es(monkeypatch):
    """Mode is unknown without a case, so the wording must not claim Mode 1."""
    monkeypatch.setattr(preflight, "_es_probe", lambda: (False, "unreachable"))
    report = run_gate()
    fallback = [i for i in report.items if i.name == "csv backend fallback"]
    assert fallback and "Modes 2/3 will require ES" in fallback[0].detail


def test_missing_active_case_is_a_warning_not_a_blocker(monkeypatch):
    """An empty store is the start of an investigation, not a broken environment.

    `doctor --gate` is the preflight an examiner runs *before* creating a case, so
    a hard failure here made it unusable for its own purpose.
    """
    monkeypatch.setattr(preflight, "_es_probe", lambda: (True, "ok"))
    monkeypatch.setattr(preflight, "_llm_probe", lambda: (True, "ok"))
    monkeypatch.setattr(preflight, "_rag_probe", lambda: (True, "bge via hf_hub_cache", True))
    report = run_gate()
    assert report.ok is True
    assert "active case" not in [f.name for f in report.failures]
    # It must still name the next action rather than read as "nothing to do",
    # even though the item itself passed (a warn item that is ok is not a warning).
    case_item = next(i for i in report.items if i.name == "active case")
    assert case_item.ok is True
    assert case_item.severity == WARN
    assert case_item.fix
    assert "environment verified" in case_item.detail


def test_mode2_without_llm_is_a_required_failure(monkeypatch, tmp_path):
    case = _case(tmp_path, mode="2")
    monkeypatch.setattr(preflight, "_es_probe", lambda: (True, "ok"))
    monkeypatch.setattr(preflight, "_llm_probe", lambda: (False, "unset"))
    report = run_gate(case_dir=case)
    assert "llm" in [f.name for f in report.failures]


def test_never_indexed_mode2_case_fails_on_case_index(monkeypatch, tmp_path):
    case = _case(tmp_path, mode="2", docs=None)
    monkeypatch.setattr(preflight, "_es_probe", lambda: (True, "ok"))
    monkeypatch.setattr(preflight, "_llm_probe", lambda: (True, "ok"))
    report = run_gate(case_dir=case)
    assert "case index" in [f.name for f in report.failures]


def test_probe_crash_becomes_a_failed_item_not_an_exception(monkeypatch, tmp_path):
    case = _case(tmp_path, mode="1")

    def boom() -> tuple[bool, str]:
        raise RuntimeError("es exploded")

    monkeypatch.setattr(preflight, "_es_probe", boom)
    report = run_gate(case_dir=case)
    assert any("es exploded" in i.detail for i in report.items)


def test_format_report_ends_with_pass_or_fail_and_lists_fixes():
    report = preflight.GateReport(mode=2, mode_label="multi-role", case_id="CASE-X")
    report.add("elasticsearch", False, "unreachable", "start ES", REQUIRED)
    lines = format_report(report)
    text = "\n".join(lines)
    assert "gate: FAIL" in text
    assert "Fix in this order" in text
    assert "start ES" in text
    assert "multi-role" in text


def test_format_report_pass_has_no_fix_list():
    report = preflight.GateReport(mode=1, mode_label="llm", case_id="CASE-Y")
    report.add("elasticsearch", True, "ok")
    text = "\n".join(format_report(report))
    assert "gate: PASS" in text
    assert "Fix in this order" not in text


def test_cli_gate_json_exits_zero_when_gate_passes(monkeypatch, tmp_path):
    from nexus.cli.main import app

    case = _case(tmp_path, mode="1")
    monkeypatch.setattr(preflight, "_resolve_case", lambda: (case.name, case))
    monkeypatch.setattr(preflight, "_es_probe", lambda: (True, "ok"))
    monkeypatch.setattr(preflight, "_llm_probe", lambda: (True, "ok"))
    monkeypatch.setattr(preflight, "_rag_probe", lambda: (True, "bge via hf_hub_cache", True))
    result = runner.invoke(app, ["doctor", "--gate-json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["ok"] is True
    assert payload["mode"] == 1


def test_gate_still_fails_on_a_real_environment_blocker(monkeypatch):
    """Relaxing the empty case must not relax a genuine environment failure."""
    monkeypatch.setattr(preflight, "_es_probe", lambda: (False, "unreachable"))
    monkeypatch.setattr(preflight, "_mcp_probe", lambda: (False, ""))
    report = run_gate(mode=2)
    assert report.ok is False
    assert "mcp catalog" in [f.name for f in report.failures]
    assert "elasticsearch" in [f.name for f in report.failures]


def test_cli_gate_exits_nonzero_with_fix_list(monkeypatch, tmp_path):
    from nexus.cli.main import app

    case = _case(tmp_path, mode="2")
    monkeypatch.setattr(preflight, "_resolve_case", lambda: (case.name, case))
    monkeypatch.setattr(preflight, "_es_probe", lambda: (False, "unreachable"))
    result = runner.invoke(app, ["doctor", "--gate"])
    assert result.exit_code == 1
    assert "gate: FAIL" in result.output
    assert "Fix in this order" in result.output
