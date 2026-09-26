"""Coverage audit — WIRING-PLAN 10.2.

The acceptance criterion from the plan: *"a run where an unused applicable tool
and an uncited source are both surfaced."* That is
`test_acceptance_unused_tool_and_uncited_source_both_surfaced`.

The other half of the contract is honesty: when an input is missing the section
must be ``unknown`` with a reason, never a silent pass.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from nexus.analysis import coverage_audit as ca

runner = CliRunner()

_LEDGER_OK = {
    "host": "windows",
    "tool": "hayabusa",
    "purpose": "EVTX detection",
    "status": "OK",
    "audit_id": "a" * 64,
}
_LEDGER_PENDING = {
    "host": "windows",
    "tool": "mftecmd",
    "purpose": "$MFT timeline",
    "status": "PENDING",
    "reason": "",
}
_LEDGER_FAIL = {
    "host": "windows",
    "tool": "sbecmd",
    "purpose": "shellbags",
    "status": "FAIL",
    "reason": "non-zero exit",
}


def _case(tmp_path: Path, *, ledger: list[dict] | None = None, evidence: list[dict] | None = None) -> Path:
    case = tmp_path / "CASE-AUDIT1"
    (case / "analysis").mkdir(parents=True)
    (case / "CASE.yaml").write_text(
        'name: Audit Case\ninvestigation_mode: "1"\nmode_scheme: 2\n', encoding="utf-8"
    )
    if ledger is not None:
        (case / "extractions").mkdir(exist_ok=True)
        (case / "extractions" / "_tool_lane_ledger.json").write_text(
            json.dumps(ledger), encoding="utf-8"
        )
    (case / "evidence.json").write_text(json.dumps(evidence or []), encoding="utf-8")
    return case


def _signal_map(case: Path, rows: list[tuple[str, int, str, str]]) -> None:
    lines = ["needle,hits,source,scanned"]
    lines += [f"{n},{h},{s},{sc}" for n, h, s, sc in rows]
    (case / "analysis" / "signal_map.csv").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _no_es(monkeypatch, families: dict[str, int] | None) -> None:
    """Pin the family aggregation (or make it raise when families is None)."""
    import nexus.langgraph.case_index as ci

    def fake_agg(*_a, **_k):
        if families is None:
            raise RuntimeError("cluster unreachable")
        return {
            "field": "family",
            "rows_scanned": sum(families.values()),
            "values_seen": len(families),
            "distinct": len(families),
            "distinct_approximate": True,
            "top": [{"value": f, "count": c} for f, c in families.items()],
            "buckets": None,
            "backend": "elasticsearch",
        }

    monkeypatch.setattr(ci, "es_aggregate", fake_agg)


# ── acceptance ───────────────────────────────────────────────────────────────


def test_acceptance_unused_tool_and_uncited_source_both_surfaced(monkeypatch, tmp_path):
    """The plan's acceptance case, end to end."""
    case = _case(
        tmp_path,
        ledger=[_LEDGER_OK, _LEDGER_PENDING, _LEDGER_FAIL],
        evidence=[{"name": "evidence", "file_path": str(tmp_path)}],
    )
    # An artifact that is present, declares tools, and none of them ever ran.
    from nexus.langgraph.artifact_map import ArtifactHit

    monkeypatch.setattr(
        ca,
        "_artifact_hits",
        lambda _case: (
            [
                ArtifactHit(
                    name="Prefetch",
                    slug="prefetch",
                    related_tools=["PECmd"],
                    present=True,
                    hits=[tmp_path / "a.pf"],
                    locations=["Windows/Prefetch/*.pf"],
                    reason="2 hit(s)",
                )
            ],
            "",
        ),
    )
    _no_es(monkeypatch, {"hayabusa": 900, "prefetch": 0, "mft": 40})
    # One finding that cites only the hayabusa family.
    (case / "findings.json").write_text(
        json.dumps(
            [
                {
                    "id": "F-1",
                    "title": "sdelete",
                    "evidence": [{"source": "hayabusa/rules/sdelete.csv:12"}],
                }
            ]
        ),
        encoding="utf-8",
    )
    _signal_map(case, [("sdelete", 3, "playbook-strong", "yes"), ("mimikatz", 0, "attack", "yes")])

    audit = ca.build_coverage_audit(case)
    assert audit["overall"] == "gaps"

    tools = audit["tools"]
    assert tools["status"] == "gaps"
    assert [r["tool"] for r in tools["pending"]] == ["mftecmd"]
    assert [r["tool"] for r in tools["failed"]] == ["sbecmd"]
    artifact_rows = tools["applicable_not_parsed"]
    assert artifact_rows and artifact_rows[0]["artifact"] == "Prefetch"
    assert "PECmd" in artifact_rows[0]["never_invoked"]
    assert "pecmd" in artifact_rows[0]["never_invoked_keys"]

    sources = audit["sources"]
    assert sources["status"] == "gaps"
    never = {r["family"] for r in sources["indexed_never_cited"]}
    assert {"prefetch", "mft"} <= never  # uncited sources surfaced
    assert "hayabusa" not in never  # the cited one is not reported as a gap

    needles = audit["needles"]
    assert needles["status"] == "ok"
    assert needles["zero_hit_scanned"] == 1  # mimikatz: genuinely checked, no hit


# ── tools section ────────────────────────────────────────────────────────────


def test_tools_unknown_without_a_ledger(monkeypatch, tmp_path):
    case = _case(tmp_path, ledger=None)
    _no_es(monkeypatch, {"hayabusa": 1})
    _signal_map(case, [("x", 0, "playbook", "yes")])
    audit = ca.build_coverage_audit(case)
    assert audit["tools"]["status"] == "unknown"
    assert "ledger" in audit["tools"]["reason"].lower()
    assert any(item.startswith("tools:") for item in audit["unavailable"])


def test_tools_ok_when_everything_ran(monkeypatch, tmp_path):
    case = _case(tmp_path, ledger=[_LEDGER_OK], evidence=[{"file_path": str(tmp_path)}])
    monkeypatch.setattr(ca, "_artifact_hits", lambda _c: ([], ""))
    _no_es(monkeypatch, {"hayabusa": 5})
    _signal_map(case, [("x", 1, "playbook", "yes")])
    audit = ca.build_coverage_audit(case)
    assert audit["tools"]["status"] == "ok"
    assert audit["tools"]["counts"]["ok"] == 1


# ── sources section ──────────────────────────────────────────────────────────


def test_sources_unknown_when_elasticsearch_is_down(monkeypatch, tmp_path):
    case = _case(tmp_path, ledger=[_LEDGER_OK])
    _no_es(monkeypatch, None)
    _signal_map(case, [("x", 0, "playbook", "yes")])
    audit = ca.build_coverage_audit(case)
    assert audit["sources"]["status"] == "unknown"
    assert "unavailable" in audit["sources"]["reason"].lower()
    # An unknown audit is not a pass.
    assert audit["overall"] == "unknown"


def test_sources_flags_a_family_cited_but_not_indexed(monkeypatch, tmp_path):
    case = _case(tmp_path, ledger=[_LEDGER_OK])
    _no_es(monkeypatch, {"hayabusa": 5})
    (case / "findings.json").write_text(
        json.dumps([{"id": "F-1", "evidence": [{"source": "registry_export/x.json:1"}]}]),
        encoding="utf-8",
    )
    _signal_map(case, [("x", 0, "playbook", "yes")])
    audit = ca.build_coverage_audit(case)
    assert audit["sources"]["cited_not_indexed"] == ["registry_export"]
    assert audit["sources"]["status"] == "gaps"


def test_sources_reads_families_from_the_evidence_row_source_prefix(tmp_path):
    case = _case(tmp_path, ledger=[_LEDGER_OK])
    (case / "findings.json").write_text(
        json.dumps(
            [{"id": "F", "evidence": [{"source": "hayabusa/rules/a.csv:1"}, {"source": "prefetch/PECmd/OUT/x.csv:9"}]}]
        ),
        encoding="utf-8",
    )
    families, count = ca._finding_citations(case)
    assert count == 1
    assert families == {"hayabusa", "prefetch"}


# ── needles section ──────────────────────────────────────────────────────────


def test_needles_unknown_without_a_signal_map(tmp_path):
    case = _case(tmp_path, ledger=[_LEDGER_OK])
    section = ca._needles_section(case)
    assert section["status"] == "unknown"
    assert "signal_map" in section["reason"]


def test_needles_reconcile_scanned_zero_hits_against_never_queried(tmp_path):
    case = _case(tmp_path)
    _signal_map(
        case,
        [
            ("hit-term", 7, "playbook-strong", "yes"),
            ("clean-term", 0, "attack", "yes"),
            ("never-ran", 0, "sigma", "no"),
        ],
    )
    section = ca._needles_section(case)
    assert section["requested"] == 3
    assert section["scanned"] == 2
    assert section["not_scanned"] == 1
    assert section["zero_hit_scanned"] == 1
    assert section["not_scanned_needles"] == ["never-ran"]
    assert section["status"] == "gaps"


def test_needles_pick_up_truncation_warnings_from_the_briefing(tmp_path):
    case = _case(tmp_path)
    _signal_map(case, [("x", 0, "playbook", "yes")])
    (case / "analysis" / "briefing.md").write_text(
        "# Briefing\n\n> WARNING: 2 needle(s) could NOT be queried - their 0-hit rows "
        "in `signal_map.csv` are marked `scanned=no` and are NOT evidence of absence.\n",
        encoding="utf-8",
    )
    section = ca._needles_section(case)
    assert any("NOT evidence of absence" in r for r in section["truncated_reasons"])


# ── persistence + surfaces ───────────────────────────────────────────────────


def test_write_and_load_round_trip(tmp_path):
    case = _case(tmp_path, ledger=[_LEDGER_OK])
    path, audit = ca.write_coverage_audit(case)
    assert path.name == "coverage_audit.json"
    assert path.is_file()
    loaded = ca.load_coverage_audit(case)
    assert loaded["schema"] == ca.SCHEMA_VERSION
    assert loaded["case_id"] == audit["case_id"]


def test_load_returns_empty_when_absent(tmp_path):
    case = _case(tmp_path)
    assert ca.load_coverage_audit(case) == {}


def test_summary_lines_never_hide_an_unknown_section(tmp_path):
    audit = {
        "overall": "unknown",
        "tools": {"status": "unknown", "reason": "no ledger", "counts": {}},
        "sources": {"status": "ok"},
        "needles": {"status": "ok", "requested": 1, "scanned": 1, "not_scanned": 0, "zero_hit_scanned": 1},
        "unavailable": ["tools: no ledger"],
    }
    lines = ca.summary_lines(audit)
    text = "\n".join(lines)
    assert "NOT AUDITED" in text
    assert "no ledger" in text
    assert "unavailable:" in text


def test_report_section_is_empty_without_an_audit():
    assert ca.report_section({}) == []
    assert ca.report_section({"overall": "ok"}) != []


def test_cli_rebuild_and_gate_on_gaps(monkeypatch, tmp_path):
    from nexus.cli.main import app

    case = _case(tmp_path, ledger=[_LEDGER_PENDING], evidence=[{"file_path": str(tmp_path)}])
    _no_es(monkeypatch, {"hayabusa": 3})
    _signal_map(case, [("x", 0, "playbook", "yes")])
    result = runner.invoke(app, ["coverage-audit", "--rebuild", "--case", str(case)])
    assert result.exit_code == 1  # gaps are not a pass
    assert "Coverage audit" in result.output
    assert (case / "analysis" / "coverage_audit.json").is_file()


def test_cli_reports_no_active_case(monkeypatch, tmp_path):
    from nexus.cli.main import app

    monkeypatch.setattr("nexus.case.outputs.resolve_active_case_dir", lambda: None)
    result = runner.invoke(app, ["coverage-audit"])
    assert result.exit_code == 1
    assert "No active case" in result.output


@pytest.mark.parametrize("missing", ["ledger", "index", "signal_map"])
def test_every_missing_input_degrades_to_unknown_not_ok(monkeypatch, tmp_path, missing):
    """No single absent input may produce an overall 'ok'."""
    case = _case(tmp_path, ledger=[_LEDGER_OK] if missing != "ledger" else None)
    _no_es(monkeypatch, None if missing == "index" else {"hayabusa": 1})
    if missing != "signal_map":
        _signal_map(case, [("x", 0, "playbook", "yes")])
    monkeypatch.setattr(ca, "_artifact_hits", lambda _c: ([], ""))
    audit = ca.build_coverage_audit(case)
    assert audit["overall"] in {"unknown", "gaps"}
    assert audit["overall"] != "ok"


# ── surface: the portal briefing carries the audit ───────────────────────────


def test_briefing_attaches_the_persisted_audit(monkeypatch, tmp_path):
    """The briefing gains a `coverage_audit` block; a missing audit omits it."""
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from nexus.dashboard.app import create_dashboard

    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    client = TestClient(Starlette(routes=create_dashboard()))

    created = client.post("/portal/api/case/create", json={"name": "Coverage Case", "activate": True})
    assert created.status_code == 200, created.text
    assert created.json()["case_id"]

    from nexus.case.outputs import resolve_active_case_dir

    case_dir = resolve_active_case_dir()
    assert case_dir is not None
    _no_es(monkeypatch, {"hayabusa": 4})
    (case_dir / "analysis").mkdir(parents=True, exist_ok=True)
    ca.write_coverage_audit(case_dir)

    body = client.get("/portal/api/case/briefing").json()
    assert "coverage_audit" in body
    assert body["coverage_audit"]["overall"] in {"ok", "gaps", "unknown"}
    assert body["coverage_audit"]["summary"]

    # Without the artifact the key is simply absent - never an empty "all clear".
    (case_dir / "analysis" / "coverage_audit.json").unlink()
    body2 = client.get("/portal/api/case/briefing").json()
    assert "coverage_audit" not in body2
