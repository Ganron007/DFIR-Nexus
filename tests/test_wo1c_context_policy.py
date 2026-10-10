"""WO-1C item 3 — the context policy: independent by default, informed labelled.

The policy is the difference between "this mode reached the same place from
the same rows" and "this mode was told the answer and agreed". Both are
legitimate; reporting them as the same thing is not.
"""
from __future__ import annotations

import json
from pathlib import Path


def test_default_policy_is_independent():
    from nexus.analysis.context_policy import DEFAULT_POLICY, normalize_policy

    assert DEFAULT_POLICY == "independent"
    assert normalize_policy("") == "independent"
    assert normalize_policy(None) == "independent"
    assert normalize_policy("banana") == "independent"
    assert normalize_policy("INFORMED") == "informed"
    assert normalize_policy(" independent ") == "independent"


def test_independent_contributes_no_context_sections(tmp_path: Path):
    from nexus.analysis.context_policy import context_sections

    # Even with a full report and drafts on disk.
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "REPORT.md").write_text("Prior conclusion: X", encoding="utf-8")
    (tmp_path / "findings.json").write_text(json.dumps([
        {"title": "T", "severity": "high", "state": "DRAFT"}
    ]), encoding="utf-8")

    assert context_sections(tmp_path, "independent") == []


def test_informed_labels_prior_analysis_as_not_evidence(tmp_path: Path):
    from nexus.analysis.context_policy import context_sections

    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "REPORT.md").write_text("Prior conclusion: X", encoding="utf-8")
    (tmp_path / "findings.json").write_text(json.dumps([
        {"title": "Mimikatz seen", "severity": "high", "state": "DRAFT"}
    ]), encoding="utf-8")

    sections = context_sections(tmp_path, "informed")
    assert len(sections) == 1
    priority, name, text = sections[0]
    assert name == "prior_analysis_context"
    # The label is load-bearing: the model must be told this is NOT evidence.
    assert "NOT evidence" in text
    assert "Prior conclusion: X" in text
    assert "Mimikatz seen" in text
    # And it is the first thing dropped when the window is tight.
    assert priority >= 90


def test_informed_ignores_approved_findings(tmp_path: Path):
    """Only DRAFT prior context is passed; signed decisions are the examiner's."""
    from nexus.analysis.context_policy import prior_context

    (tmp_path / "findings.json").write_text(json.dumps([
        {"title": "Approved one", "state": "APPROVED"},
        {"title": "Draft one", "state": "DRAFT"},
    ]), encoding="utf-8")

    ctx = prior_context(tmp_path)
    assert ctx["draft_count"] == 1
    assert ctx["drafts"][0]["title"] == "Draft one"


def test_prior_context_survives_a_missing_report(tmp_path: Path):
    from nexus.analysis.context_policy import context_sections, prior_context

    ctx = prior_context(tmp_path)
    assert ctx["report"] == ""
    assert ctx["report_present"] is False
    assert ctx["drafts"] == []
    # No context at all — no section, and the informed run is not penalised.
    assert context_sections(tmp_path, "informed") == []


def test_legacy_root_report_is_still_read(tmp_path: Path):
    from nexus.analysis.context_policy import prior_context

    (tmp_path / "REPORT.md").write_text("legacy report", encoding="utf-8")
    ctx = prior_context(tmp_path)
    assert ctx["report"] == "legacy report"


def test_corrupt_findings_file_does_not_raise(tmp_path: Path):
    from nexus.analysis.context_policy import prior_context

    (tmp_path / "findings.json").write_text("{not json", encoding="utf-8")
    ctx = prior_context(tmp_path)
    assert ctx["drafts"] == []
    assert ctx["draft_count"] == 0
