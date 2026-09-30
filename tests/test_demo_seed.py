"""WO-U10 (WP 14.10): the demo seeder stages through the real paths.

The demo's Approval Desk must show what a real case shows: findings sealed at
staging, L1 verdicts computed by the real verifier, approvals signed through
the real approval service (PROVEN only, no override needed), a rejection
through the real reject path, and a deliberately UNSUPPORTED finding left
DRAFT as the override example. Pipeline state files (lane gate, index state,
coverage audit) agree with what the cockpit banners read.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture()
def demo_case(tmp_path, monkeypatch) -> Path:
    """Seed the demo case into an isolated store and return its directory."""
    from nexus.config import settings

    monkeypatch.setattr(settings, "cases_root", tmp_path)
    monkeypatch.setenv("NEXUS_EXAMINER", "analyst_purple")
    monkeypatch.setenv("NEXUS_ACTIVE_CASE", "CASE-DEMO-001")

    from nexus.case.seed import seed_demo_case

    result = seed_demo_case(activate=False)
    assert result["ok"] is True
    return tmp_path / "CASE-DEMO-001"


def test_findings_staged_through_the_real_path(demo_case: Path):
    """Every seeded finding was staged, sealed and state-stamped by
    record_finding — not written into findings.json by the seeder."""
    findings = json.loads((demo_case / "findings.json").read_text(encoding="utf-8"))
    assert len(findings) >= 5
    for f in findings:
        # a real staging path seals the DRAFT (WP 10.4)
        assert f.get("seal"), f"{f['id']} has no submission seal"
        assert f.get("staged") is True
        assert f.get("audit_ids"), f"{f['id']} cites no audit_id"


def test_l1_verdicts_as_designed(demo_case: Path):
    """Four PROVEN claims and one deliberately UNSUPPORTED override example;
    the UNSUPPORTED one names an executable absent from every row. The
    verdicts come from the real verifier replaying the demo's own rows
    (verify_case's indexed_text hook — the same rows the index would answer
    from), so the expectation holds with or without a reachable ES."""
    from nexus.analysis.claim_verification import verify_case

    extractions = demo_case / "extractions"
    indexed_text = "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in sorted(extractions.rglob("*.csv"))
    )
    ledger = verify_case(demo_case, use_index=False, indexed_text=indexed_text)

    findings = json.loads((demo_case / "findings.json").read_text(encoding="utf-8"))
    titles = {f["id"]: f["title"] for f in findings}
    by_title = {}
    for row in ledger.get("claims") or []:
        fid = str(row.get("id") or "")
        by_title[titles[fid]] = row["verdict"]

    override = [v for t, v in by_title.items() if "override example" in t]
    assert override == ["UNSUPPORTED"]
    proven = [t for t, v in by_title.items() if v == "PROVEN"]
    assert len(proven) >= 4
    assert not [t for t, v in by_title.items() if v == "CONTRADICTED"]


def test_status_is_consistent(demo_case: Path):
    """The approved findings carry PROVEN at approval; the rejected one went
    through the real reject path; the store mirrors the flat file."""
    findings = json.loads((demo_case / "findings.json").read_text(encoding="utf-8"))
    statuses = [f["status"] for f in findings]
    assert statuses.count("APPROVED") == 2
    assert statuses.count("REJECTED") == 1
    for f in findings:
        if f["status"] == "APPROVED":
            assert f.get("l1_verdict_at_approval") == "PROVEN"
            assert f.get("seal_state") == "verified"
            assert f.get("approved_by")
        if f["status"] == "REJECTED":
            assert f.get("rejection_reason")
            assert f.get("rejected_by")

    from nexus.analysis.integrity import load_known_audit_ids

    known = load_known_audit_ids(demo_case)
    assert known, "the demo audit log holds no entries"
    for f in findings:
        assert set(f.get("audit_ids") or []) <= known


def test_approval_of_a_proven_demo_finding_needs_no_reason(demo_case: Path):
    """Approving a PROVEN demo DRAFT through the real approval service
    succeeds without an override reason and records the verdict."""
    from nexus.cli.approve import approve_finding

    findings = json.loads((demo_case / "findings.json").read_text(encoding="utf-8"))
    # the seeder only signs PROVEN drafts, so any remaining DRAFT that is
    # neither the override example nor rejected is PROVEN by construction;
    # verify against the demo rows the same way the seeder did.
    from nexus.analysis.claim_verification import verify_case

    extractions = demo_case / "extractions"
    indexed_text = "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in sorted(extractions.rglob("*.csv"))
    )
    ledger = verify_case(demo_case, use_index=False, indexed_text=indexed_text)
    verdicts = {
        str(row.get("id") or ""): str(row.get("verdict") or "")
        for row in ledger.get("claims") or []
    }
    proven = [
        f for f in drafts if verdicts.get(f["id"]) == "PROVEN"
    ] if (drafts := [f for f in findings if f["status"] == "DRAFT"]) else []
    assert proven, "no PROVEN demo draft to approve"

    result = approve_finding(
        demo_case, proven[0]["id"], "analyst_purple",
        "nexus-demo-fixture-approval", note="wo-u10 test",
        # the real caller (nexus approve) computes and passes the verdict
        l1_verdict="PROVEN",
    )
    assert result.get("status") == "APPROVED", result

    after = json.loads((demo_case / "findings.json").read_text(encoding="utf-8"))
    entry = next(f for f in after if f["id"] == proven[0]["id"])
    assert entry["status"] == "APPROVED"
    assert entry["l1_verdict_at_approval"] == "PROVEN"
    assert "override_reason" not in entry


def test_pipeline_state_files_are_coherent(demo_case: Path):
    """Lane gate clear (nothing unprocessed), index state and coverage audit
    written — the stage indicators and the gate banner read the same truth."""
    analysis = demo_case / "analysis"
    gate = json.loads((analysis / "lane_gate.json").read_text(encoding="utf-8"))
    assert gate.get("unprocessed") == []
    state = json.loads((analysis / "index_state.json").read_text(encoding="utf-8"))
    assert state.get("docs", 0) > 0
    assert (analysis / "coverage_audit.json").is_file()

    # every cited audit id exists in the real, chain-hashed audit log
    audit_files = list((demo_case / "audit").glob("*.jsonl"))
    assert audit_files
    entries = [
        json.loads(line)
        for line in audit_files[0].read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert all("audit_id" in e and "sha256" in e for e in entries)
