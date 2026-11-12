"""Tests for T2-11 EV-SEM — evidence semantics and per-class coverage statements.
"""
from __future__ import annotations

import json
from pathlib import Path

from nexus.analysis.coverage_audit import report_section
from nexus.knowledge.family_registry import (
    case_coverage_statement,
    class_of,
    completeness_of,
    family_semantics,
    get_family_registry,
    has_absence_authority,
    priority_of,
    render_coverage_statement,
)
from nexus.langgraph.briefing import case_briefing
from nexus.langgraph.case_digest import build_case_digest
from nexus.tools.evidence_index import do_index_mappings


def test_ev_sem_classes_and_priorities():
    reg = get_family_registry()

    # Detections
    for det in ("hayabusa", "chainsaw", "sigma", "deepbluecli", "yara", "zircolite"):
        assert reg.class_of(det) == "detection"
        assert class_of(det) == "detection"
        assert reg.completeness_of(det) == "filtered"
        assert completeness_of(det) == "filtered"
        assert reg.priority_of(det) == "leads"
        assert priority_of(det) == "leads"
        assert not reg.has_absence_authority(det)
        assert not has_absence_authority(det)

    # Raw artifacts
    for raw in ("evtx", "evtxecmd", "mft", "mftecmd", "recmd", "pecmd", "memprocfs", "amcache"):
        assert reg.class_of(raw) == "raw"
        assert class_of(raw) == "raw"
        assert reg.completeness_of(raw) == "complete"
        assert completeness_of(raw) == "complete"
        assert reg.priority_of(raw) == "primary"
        assert priority_of(raw) == "primary"
        assert reg.has_absence_authority(raw)
        assert has_absence_authority(raw)

    # Containers
    assert reg.class_of("generic_csv") == "container"
    assert class_of("generic_csv") == "container"
    assert reg.completeness_of("generic_csv") == "partial"
    assert completeness_of("generic_csv") == "partial"
    assert reg.priority_of("generic_csv") == "context"
    assert not reg.has_absence_authority("generic_csv")

    # Reference
    assert reg.class_of("abuseipdb") == "reference"
    assert class_of("abuseipdb") == "reference"
    assert reg.completeness_of("abuseipdb") == "sampled"
    assert completeness_of("abuseipdb") == "sampled"
    assert reg.priority_of("abuseipdb") == "context"
    assert not reg.has_absence_authority("abuseipdb")

    # Imported / Cloud
    assert reg.class_of("aws_s3_access") == "imported"
    assert class_of("aws_s3_access") == "imported"
    assert reg.completeness_of("aws_s3_access") == "partial"
    assert completeness_of("aws_s3_access") == "partial"
    assert reg.priority_of("aws_s3_access") == "context"
    assert not reg.has_absence_authority("aws_s3_access")

    # Enriched
    assert reg.class_of("plaso") == "enriched"
    assert class_of("plaso") == "enriched"
    assert reg.completeness_of("plaso") == "complete"
    assert completeness_of("plaso") == "complete"
    assert reg.priority_of("plaso") == "primary"
    assert reg.has_absence_authority("plaso")

    # Unclassified
    assert reg.class_of("unknown_future_tool_999") == "unclassified"
    assert class_of("unknown_future_tool_999") == "unclassified"
    assert reg.completeness_of("unknown_future_tool_999") == "unknown"
    assert completeness_of("unknown_future_tool_999") == "unknown"
    assert reg.priority_of("unknown_future_tool_999") == "context"
    assert not reg.has_absence_authority("unknown_future_tool_999")


def test_ev_sem_family_semantics():
    sem = family_semantics("hayabusa")
    assert sem["family"] == "hayabusa"
    assert sem["canonical"] == "hayabusa"
    assert sem["class"] == "detection"
    assert sem["completeness"] == "filtered"
    assert sem["priority"] == "leads"
    assert sem["absence_authority"] is False

    sem_evtx = family_semantics("evtx")
    assert sem_evtx["class"] == "raw"
    assert sem_evtx["completeness"] == "complete"
    assert sem_evtx["priority"] == "primary"
    assert sem_evtx["absence_authority"] is True


def test_ev_sem_case_coverage_statement_rendering(tmp_path: Path):
    family_rows = {
        "evtx": 500,
        "mftecmd": 250,
        "hayabusa": 15,
        "chainsaw": 4,
        "aws_s3_access": 100,
        "generic_csv": 50,
        "mystery_tool": 2,
    }
    stmt_data = case_coverage_statement(tmp_path, family_rows)
    assert stmt_data["raw_count"] == 2
    assert stmt_data["detection_count"] == 2
    assert stmt_data["imported_count"] == 1
    assert stmt_data["container_count"] == 1
    assert stmt_data["unclassified_count"] == 1

    text = render_coverage_statement(tmp_path, family_rows)
    assert "raw families complete (2)" in text
    assert "detection families filtered (2)" in text
    assert "imported/cloud telemetry (1)" in text
    assert "containers (1)" in text
    assert "unclassified (1)" in text


def test_ev_sem_do_index_mappings_integration(tmp_path: Path, monkeypatch):
    case_dir = tmp_path / "CASE-TEST"
    case_dir.mkdir(parents=True)
    (case_dir / "evidence.json").write_text("[]", encoding="utf-8")

    # Mock active case resolution
    monkeypatch.setattr("nexus.tools.evidence_index._resolve_active_case", lambda c_id, c_dir: (case_dir, ""))
    monkeypatch.setattr("nexus.langgraph.case_index.es_available", lambda: False)
    monkeypatch.setattr(
        "nexus.langgraph.briefing._family_inventory",
        lambda c_dir: {"evtx": {"rows": 10, "files": 1}, "hayabusa": {"rows": 2, "files": 1}},
    )

    payload = do_index_mappings(case_id="CASE-TEST", case_dir=case_dir)
    assert "family_semantics" in payload
    assert "coverage_statement" in payload
    assert "evtx" in payload["family_semantics"]
    assert payload["family_semantics"]["evtx"]["class"] == "raw"
    assert payload["family_semantics"]["hayabusa"]["class"] == "detection"

    stmt = payload["coverage_statement"]
    assert stmt["raw_count"] == 1
    assert stmt["detection_count"] == 1
    assert "raw families complete (1)" in stmt["statement"]


def test_ev_sem_coverage_audit_report_section(tmp_path: Path):
    case_dir = tmp_path / "CASE-AUDIT"
    case_dir.mkdir(parents=True)
    ev = [
        {"recognized_family": "evtx", "path": "test.evtx"},
        {"recognized_family": "hayabusa", "path": "alerts.csv"},
    ]
    (case_dir / "evidence.json").write_text(json.dumps(ev), encoding="utf-8")

    lines = report_section({"overall": "ok", "tools": {"status": "ok"}, "sources": {"status": "ok"}}, case_dir=case_dir)
    joined = "\n".join(lines)
    assert "## Coverage audit" in joined
    assert "Evidence semantics:" in joined
    assert "raw families complete (1)" in joined
    assert "detection families filtered (1)" in joined


def test_ev_sem_briefing_and_digest_coverage(tmp_path: Path):
    case_dir = tmp_path / "CASE-DIGEST"
    case_dir.mkdir(parents=True)
    ev = [
        {"recognized_family": "evtx", "path": "test.evtx"},
        {"recognized_family": "hayabusa", "path": "alerts.csv"},
    ]
    (case_dir / "evidence.json").write_text(json.dumps(ev), encoding="utf-8")

    brief = case_briefing(case_dir)
    assert "coverage_statement" in brief
    stmt = brief["coverage_statement"]
    assert "statement" in stmt

    digest = build_case_digest(case_dir, brief=brief)
    assert "coverage_statement" in digest
    assert digest["coverage_statement"]["statement"] == stmt["statement"]
