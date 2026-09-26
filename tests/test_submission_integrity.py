"""Submission integrity — WIRING-PLAN 10.4 (hardens FD-001).

The plan's acceptance criterion: *"submission tests prove rejection of unknown
refs and fabricated timestamps"*. Note the asymmetry, which the tests pin:
an unknown ``audit_id`` is **rejected**, while an implausible timestamp is
**nullified and flagged** — a bad timestamp is data quality, not forged
provenance, and rejecting it would push callers to drop the whole finding.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from nexus.analysis import integrity as ig

# Audit ids follow the runtime format: <tool>-<who>-<YYYYMMDD>-<seq>.
# _FAKE is well-formed on purpose - it must fail on *existence*, not on shape.
_REAL_AUDIT_ID = "hayabusa-tester-20260926-001"
_SECOND_AUDIT_ID = "evtxecmd-tester-20260926-002"
_FAKE_AUDIT_ID = "recmd-tester-20260926-999"  # never written to the audit log


def _case_with_audit(tmp_path: Path, *audit_ids: str) -> Path:
    """A case dir with an audit log containing the given audit ids."""
    case = tmp_path / "CASE-INT1"
    (case / "audit").mkdir(parents=True)
    (case / "CASE.yaml").write_text('name: Integrity\n', encoding="utf-8")
    with (case / "audit" / "audit_log.jsonl").open("w", encoding="utf-8") as fh:
        for i, aid in enumerate(audit_ids):
            fh.write(
                json.dumps({"audit_id": aid, "tool": f"tool_{i}", "source": "mcp", "ts": "2026-09-26T00:00:00+00:00"})
                + "\n"
            )
    return case


# ── citation existence ───────────────────────────────────────────────────────


def test_unknown_audit_id_is_rejected(tmp_path):
    case = _case_with_audit(tmp_path, _REAL_AUDIT_ID)
    finding = {"audit_ids": [_REAL_AUDIT_ID, _FAKE_AUDIT_ID], "evidence": []}
    result = ig.enforce_submission_integrity(finding, case)
    assert result["ok"] is False
    assert result["citations"]["unknown"] == [_FAKE_AUDIT_ID]
    assert result["citations"]["verified"] == [_REAL_AUDIT_ID]
    assert "citation integrity" in result["errors"][0]


def test_all_real_audit_ids_pass(tmp_path):
    case = _case_with_audit(tmp_path, _REAL_AUDIT_ID, _SECOND_AUDIT_ID)
    finding = {"audit_ids": [_REAL_AUDIT_ID, _SECOND_AUDIT_ID], "evidence": []}
    result = ig.enforce_submission_integrity(finding, case)
    assert result["ok"] is True
    assert result["errors"] == []
    assert result["citations"]["unknown"] == []


def test_no_audit_reference_at_all_is_rejected(tmp_path):
    case = _case_with_audit(tmp_path, _REAL_AUDIT_ID)
    result = ig.enforce_submission_integrity({"evidence": []}, case)
    assert result["ok"] is False
    assert "FD-001" in result["errors"][0]


def test_artifact_audit_ids_are_checked_too(tmp_path):
    """Citing via `artifacts[].audit_id` is no escape hatch."""
    case = _case_with_audit(tmp_path, _REAL_AUDIT_ID)
    finding = {
        "audit_ids": [],
        "artifacts": [{"type": "audit", "audit_id": _FAKE_AUDIT_ID}],
        "evidence": [],
    }
    result = ig.enforce_submission_integrity(finding, case)
    assert result["ok"] is False
    assert _FAKE_AUDIT_ID in result["citations"]["unknown"]


def test_duplicate_references_are_deduped(tmp_path):
    case = _case_with_audit(tmp_path, _REAL_AUDIT_ID)
    finding = {"audit_ids": [_REAL_AUDIT_ID, _REAL_AUDIT_ID], "evidence": []}
    result = ig.enforce_submission_integrity(finding, case)
    assert result["citations"]["count"] == 1
    assert result["ok"] is True


def test_missing_audit_log_makes_every_reference_unknown(tmp_path):
    """No audit directory at all cannot silently pass as 'verified'."""
    case = tmp_path / "CASE-INT2"
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text('name: x\n', encoding="utf-8")
    result = ig.enforce_submission_integrity({"audit_ids": [_REAL_AUDIT_ID]}, case)
    assert result["ok"] is False
    assert result["citations"]["unknown"] == [_REAL_AUDIT_ID]


# ── timestamps ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "n/a", "unknown", "TBD", "not available", "0", None],
)
def test_placeholder_timestamps_are_nullified(raw):
    value, flag = ig.validate_timestamp(raw)
    assert value == ""
    assert flag in {"placeholder", ""}


@pytest.mark.parametrize(
    "raw,reason",
    [
        ("2026-13-45T99:99:99Z", "unparseable"),  # ISO-shaped but impossible
        ("26-09-2026", "not_iso8601"),  # not ISO
        ("yesterday", "not_iso8601"),
        ("132537600000000000", "not_iso8601"),  # raw FILETIME integer
        ("1601-01-01T00:00:00Z", "filetime_epoch"),
        ("1985-06-01T00:00:00Z", "pre_1990"),
    ],
)
def test_implausible_timestamps_are_flagged(raw, reason):
    value, flag = ig.validate_timestamp(raw)
    assert value == ""
    assert flag == reason


def test_far_future_timestamp_is_flagged():
    future = (datetime.now(UTC) + timedelta(days=900)).isoformat()
    value, flag = ig.validate_timestamp(future)
    assert value == ""
    assert flag == "future_dated"


@pytest.mark.parametrize(
    "raw",
    ["2026-09-26T10:30:00Z", "2026-09-26T10:30:00+05:30", "2026-09-26 10:30:00", "2026-09-26"],
)
def test_plausible_iso_timestamps_survive(raw):
    value, flag = ig.validate_timestamp(raw)
    assert flag == "", f"{raw!r} was rejected: {flag}"
    assert value


def test_sanitize_nullifies_in_place_and_reports_both_sides():
    finding = {
        "event_timestamp": "yesterday",
        "evidence": [
            {"source": "hayabusa/x.csv:1", "ts": "2026-09-25T22:10:00Z"},
            {"source": "prefetch/y.csv:2", "ts": "0"},
        ],
    }
    result = ig.sanitize_timestamps(finding)
    assert finding["event_timestamp"] == ""
    assert finding["evidence"][0]["ts"] == "2026-09-25T22:10:00Z"  # kept
    assert finding["evidence"][1]["ts"] == ""  # nullified
    reasons = {n["field"]: n["reason"] for n in result["nullified"]}
    assert set(reasons) == {"event_timestamp", "evidence[1].ts"}
    assert reasons["event_timestamp"] == "not_iso8601"
    assert reasons["evidence[1].ts"] in {"placeholder", "nonpositive_epoch"}
    assert result["kept"] == 1


def test_fabricated_timestamp_warns_but_does_not_reject(tmp_path):
    """The asymmetry the plan specifies: nullify + flag, never reject."""
    case = _case_with_audit(tmp_path, _REAL_AUDIT_ID)
    finding = {"audit_ids": [_REAL_AUDIT_ID], "event_timestamp": "not-a-date", "evidence": []}
    result = ig.enforce_submission_integrity(finding, case)
    assert result["ok"] is True  # not rejected
    assert result["warnings"]
    assert "timestamp nullified" in result["warnings"][0]
    assert finding["event_timestamp"] == ""  # and the bad value is gone


# ── seal ─────────────────────────────────────────────────────────────────────


def test_seal_verifies_on_an_untouched_entry():
    entry = {"id": "F-1", "title": "x", "observation": "y", "audit_ids": [_REAL_AUDIT_ID]}
    entry["seal"] = {"algo": "sha256", "digest": ig.seal_digest(entry), "sealed_at": "now", "revision": 1}
    ok, reason = ig.verify_seal(entry)
    assert ok is True
    assert reason == "seal intact"


def test_seal_detects_a_post_staging_edit():
    entry = {"id": "F-1", "title": "x", "observation": "y"}
    entry["seal"] = {"algo": "sha256", "digest": ig.seal_digest(entry)}
    entry["observation"] = "tampered"
    ok, reason = ig.verify_seal(entry)
    assert ok is False
    assert "changed after staging" in reason


def test_seal_ignores_post_approval_bookkeeping():
    """Approving a finding must not look like tampering."""
    entry = {"id": "F-1", "title": "x", "observation": "y"}
    entry["seal"] = {"algo": "sha256", "digest": ig.seal_digest(entry)}
    entry["status"] = "APPROVED"
    entry["approved_by"] = "examiner"
    entry["approved_at"] = "2026-09-26T10:00:00Z"
    ok, _ = ig.verify_seal(entry)
    assert ok is True


def test_verify_seal_without_a_seal_says_so():
    ok, reason = ig.verify_seal({"id": "F-1"})
    assert ok is False
    assert reason == "no seal recorded"


def test_legacy_content_hash_still_recognised_as_a_seal():
    """Findings staged before the seal existed carry `content_hash` only."""
    from nexus.case_manager import _compute_content_hash

    entry = {"id": "F-1", "title": "x", "observation": "y"}
    entry["content_hash"] = _compute_content_hash(entry)
    ok, _ = ig.verify_seal(entry)
    assert ok is True


# ── end to end through the real staging path ────────────────────────────────


def _stage(tmp_path, monkeypatch, **finding):
    """Stage through the real record_finding write path on an isolated store."""
    from nexus.case_manager import CaseManager as FlatCM
    from nexus.config import settings

    cases_root = tmp_path / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))

    # The case itself is created by the SQLite stack (it owns CASE.yaml and the
    # directory layout); staging then goes through the flat manager, which is the
    # real write path used by the portal and the agent tools.
    from nexus.case import CaseManager as SqlCM

    sql = SqlCM(settings.cases_root / "cases.db")
    try:
        case = sql.create_case("Integrity Case", created_by="tester")
    finally:
        sql.close()
    case_dir = settings.cases_root / case.id
    mgr = FlatCM()
    audit_dir = case_dir / "audit"
    audit_dir.mkdir(parents=True, exist_ok=True)
    for aid in (_REAL_AUDIT_ID, _SECOND_AUDIT_ID):
        with (audit_dir / "audit_log.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"audit_id": aid, "tool": "es_search", "source": "mcp"}) + "\n")
    payload = {
        "title": finding.pop("title", "Test finding"),
        "observation": finding.pop("observation", "observed thing"),
        "interpretation": "means thing",
        "confidence": "LOW",
        "confidence_justification": "single family, single source",
        "evidence": finding.pop("evidence", [{"source": "hayabusa/rules/x.csv:1", "detail": "row"}]),
        **finding,
    }
    result = mgr.record_finding(payload, case_dir=case_dir)
    result["case_dir"] = str(case_dir)
    assert settings.cases_root == cases_root
    return result


def test_staging_rejects_a_fabricated_audit_id(tmp_path, monkeypatch):
    result = _stage(tmp_path, monkeypatch, audit_ids=[_REAL_AUDIT_ID, _FAKE_AUDIT_ID])
    assert result["status"] == "REJECTED"
    assert result["unknown_audit_ids"] == [_FAKE_AUDIT_ID]
    # The FD-001 rejection contract other callers depend on is preserved.
    assert result["missing_audit_ids"] == [_FAKE_AUDIT_ID]
    assert "evidence trail" in result["error"]


def test_staging_accepts_real_ids_and_writes_a_seal(tmp_path, monkeypatch):
    result = _stage(tmp_path, monkeypatch, audit_ids=[_REAL_AUDIT_ID, _SECOND_AUDIT_ID])
    assert result["status"] == "STAGED"
    entry = json.loads((Path(result["case_dir"]) / "findings.json").read_text(encoding="utf-8"))[0]
    assert entry["seal"]["algo"] == "sha256"
    ok, reason = ig.verify_seal(entry)
    assert ok is True, reason


def test_staging_nullifies_a_fabricated_timestamp_and_flags_it(tmp_path, monkeypatch):
    result = _stage(tmp_path, monkeypatch, audit_ids=[_REAL_AUDIT_ID], event_timestamp="2026-99-99")
    assert result["status"] == "STAGED"
    entry = json.loads((Path(result["case_dir"]) / "findings.json").read_text(encoding="utf-8"))[0]
    assert entry["event_timestamp"] == ""
    assert any("timestamp nullified" in n for n in entry.get("integrity_notes", []))


def test_approval_refuses_a_finding_edited_after_staging(tmp_path, monkeypatch):
    from nexus.cli.approve import approve_finding

    result = _stage(tmp_path, monkeypatch, audit_ids=[_REAL_AUDIT_ID])
    case_dir = Path(result["case_dir"])
    findings_path = case_dir / "findings.json"
    entries = json.loads(findings_path.read_text(encoding="utf-8"))
    fid = entries[0]["id"]
    # Simulate a post-staging edit.
    entries[0]["observation"] = "quietly rewritten"
    findings_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")

    out = approve_finding(case_dir, fid, analyst="examiner", password="irrelevant-no-key")
    assert "error" in out
    assert "seal" in out["error"].lower()


def test_report_flags_a_broken_seal(tmp_path, monkeypatch):
    from nexus.integration.dfir_report import build_dfir_markdown

    result = _stage(tmp_path, monkeypatch, audit_ids=[_REAL_AUDIT_ID])
    case_dir = Path(result["case_dir"])
    findings = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    findings[0]["observation"] = "edited after the seal"

    md = build_dfir_markdown(
        case_id=case_dir.name,
        case_name="Integrity Case",
        findings=findings,
        evidence=[],
        case_dir=case_dir,
    )
    assert "## Submission integrity" in md
