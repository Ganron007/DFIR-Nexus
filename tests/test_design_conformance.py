"""Phase 4f L2 — design-conformance tests (decision -> executable assertion).

Each committed design decision and spine invariant is pinned here, so the
plan cannot silently drift from the code. When a design changes (e.g. after
Phase 6), the matching assertion changes in one place.

Pinned decisions:
- D1 evidence system of record (SQLite; no legacy registry reads)
- D2 explicit per-request case scoping (X-Nexus-Case; no cross-case leakage)
- D3 dashboard/cockpit split (routes + legacy redirect)
- D4 case lifecycle gating (legal transitions only; SEALED never downgraded)
- D5 pipeline run durability (write-through + manifest reconciliation)
- D6 create/seed do not activate unless asked
- D7 every cockpit page re-fetches on case change
- Invariants: DRAFT-only, FD-001 audit-trail rejection, immutable runs,
  no-auto-approve, single password store, unsupported tools skip with reason
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

REPO = Path(__file__).resolve().parent.parent
FRONTEND_PAGES = REPO / "frontend" / "src" / "pages"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)

    from nexus.dashboard.app import create_dashboard

    return TestClient(Starlette(routes=create_dashboard()))


def _create(client, name: str, **extra) -> str:
    r = client.post("/portal/api/case/create", json={"name": name, **extra})
    assert r.status_code == 200, r.text
    return r.json()["case_id"]


def _stage_finding(case_id: str, title: str) -> str:
    from nexus.case import CaseManager
    from nexus.config import settings

    mgr = CaseManager(settings.cases_root / "cases.db")
    try:
        finding = mgr.add_finding(
            case_id,
            title=title,
            description="design conformance fixture",
            created_by="conformance",
        )
        assert finding is not None
        return finding.id
    finally:
        mgr.close()


# ---------------------------------------------------------------------------
# D1 — evidence system of record
# ---------------------------------------------------------------------------


def test_d1_portal_does_not_read_legacy_evidence_registry():
    app_text = (REPO / "src" / "nexus" / "dashboard" / "app.py").read_text(encoding="utf-8")
    assert "evidence_registry.json" not in app_text, (
        "the portal must read the SQLite evidence registry via evidence_service; "
        "the legacy evidence_registry.json read was the 4e split-brain bug"
    )
    # Password store is single-sourced from nexus.auth (the seal path reads it too).
    assert "_PASSWORDS_DIR" not in app_text


def test_d1_register_list_verify_agree(client, tmp_path):
    case_id = _create(client, "D1 Case")
    headers = {"X-Nexus-Case": case_id}
    ev = tmp_path / "evidence.bin"
    ev.write_bytes(b"design-conformance")

    r = client.post("/portal/api/evidence", json={"path": str(ev), "case_id": case_id})
    assert r.status_code == 200, r.text
    digest = r.json()["sha256"]

    listed = client.get("/portal/api/evidence", headers=headers).json()
    assert [item["path"] for item in listed["evidence"]] == [str(ev)]
    assert listed["evidence"][0]["sha256"] == digest

    summary = client.get("/portal/api/summary", headers=headers).json()
    assert summary["evidence"] == 1

    verify = client.post("/portal/api/evidence/verify", headers=headers).json()
    assert verify["ok"] is True
    assert all(item["valid"] for item in verify["results"])

    # mirror is generated for legacy consumers
    from nexus.config import settings

    mirror = json.loads((settings.cases_root / case_id / "evidence.json").read_text(encoding="utf-8"))
    assert mirror and mirror[0]["sha256"] == digest


# ---------------------------------------------------------------------------
# D2 — explicit case scoping; no cross-case leakage
# ---------------------------------------------------------------------------


def test_d2_case_scoping_no_cross_case_leakage(client, tmp_path):
    a = _create(client, "D2 Alpha")
    b = _create(client, "D2 Bravo")
    finding_a = _stage_finding(a, "ALPHA-FINDING")
    finding_b = _stage_finding(b, "BRAVO-FINDING")

    ev_a = tmp_path / "alpha.txt"
    ev_a.write_text("alpha", encoding="utf-8")
    ev_b = tmp_path / "bravo.txt"
    ev_b.write_text("bravo", encoding="utf-8")
    assert client.post("/portal/api/evidence", json={"path": str(ev_a), "case_id": a}).status_code == 200
    assert client.post("/portal/api/evidence", json={"path": str(ev_b), "case_id": b}).status_code == 200

    ha = {"X-Nexus-Case": a}
    hb = {"X-Nexus-Case": b}

    a_evidence = client.get("/portal/api/evidence", headers=ha).json()
    b_evidence = client.get("/portal/api/evidence", headers=hb).json()
    assert [i["path"] for i in a_evidence["evidence"]] == [str(ev_a)]
    assert [i["path"] for i in b_evidence["evidence"]] == [str(ev_b)]

    a_findings = client.get("/portal/api/findings", headers=ha).json()
    b_findings = client.get("/portal/api/findings", headers=hb).json()
    assert [f["id"] for f in a_findings["findings"]] == [finding_a]
    assert [f["id"] for f in b_findings["findings"]] == [finding_b]

    # No other case-scoped reader may leak the other case's identifiers.
    for path in (
        "/portal/api/timeline",
        "/portal/api/summary",
        "/portal/api/iocs",
        "/portal/api/todos",
        "/portal/api/workbench",
        "/portal/api/pipeline/ledger",
        "/portal/api/case/mode",
    ):
        payload = client.get(path, headers=ha)
        assert payload.status_code == 200, (path, payload.text)
        assert finding_b not in payload.text, path
        assert str(ev_b) not in payload.text, path

    # Invalid case id: falls back to the (empty) pointer, never a 500 or a leak.
    bad = client.get("/portal/api/evidence", headers={"X-Nexus-Case": "../evil"})
    assert bad.status_code == 200
    assert bad.json()["total"] == 0


def test_d2_invalid_case_ids_rejected(client):
    """Traversal-ish case ids must be rejected, never resolved or stored."""
    r = client.post("/portal/api/case/activate", json={"case_id": "../evil"})
    assert r.status_code == 400
    r = client.post("/portal/api/pipeline/run", json={"mode": "tools", "case_id": "../evil"})
    assert r.status_code == 400
    r = client.get("/portal/api/case/details?case_id=../evil")
    assert r.status_code == 404
    r = client.post("/portal/api/case/mode", json={"mode": "1", "case_id": "../evil"})
    assert r.status_code == 404


def test_d2_active_case_pointer_is_env_aware():
    """No module may hardcode the home active-case pointer.

    A hardcoded pointer means MCP/CLI/audit code stomps the real
    ``~/.nexus/active_case`` even when the process runs with an isolated
    ``NEXUS_ACTIVE_CASE_FILE`` — e2e/test runs leaked into the real pointer
    and silently dropped case audits (found 2026-09-10).
    """
    offenders: list[str] = []
    for path in sorted((REPO / "src" / "nexus").rglob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "_ACTIVE_CASE_FILE" in text and "NEXUS_ACTIVE_CASE_FILE" not in text:
            offenders.append(str(path.relative_to(REPO)))
    assert not offenders, f"hardcoded active-case pointer in: {offenders}"


# ---------------------------------------------------------------------------
# D3 — dashboard/cockpit split
# ---------------------------------------------------------------------------


def test_d3_routes_and_legacy_dashboard_redirect(client):
    from nexus.dashboard.app import create_dashboard

    paths = {getattr(route, "path", "") for route in create_dashboard()}
    assert "/portal/api/case/deactivate" in paths
    assert "/portal/api/case/{case_id}/details" in paths
    assert "/portal/api/case/create" in paths
    assert "/portal/api/case/activate" in paths

    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"] == "/portal/app/"


# ---------------------------------------------------------------------------
# D4 — lifecycle gating
# ---------------------------------------------------------------------------


def test_d4_lifecycle_transitions_are_gated(client):
    from nexus.case import CaseManager
    from nexus.case.schemas import CaseStatus
    from nexus.config import settings
    from nexus.dashboard.app import _transition_case_status

    case_id = _create(client, "D4 Case")
    mgr = CaseManager(settings.cases_root / "cases.db")
    try:
        case = mgr.get_case(case_id)
        assert case is not None and case.status == CaseStatus.CREATED
        # Not allowed from CREATED -> unchanged
        _transition_case_status(case_id, "processing", allowed_from={"intake"})
        case = mgr.get_case(case_id)
        assert case is not None and case.status == CaseStatus.CREATED
        # Allowed transition applies
        _transition_case_status(case_id, "intake")
        case = mgr.get_case(case_id)
        assert case is not None and case.status == CaseStatus.INTAKE
        # SEALED is terminal — no downgrade
        mgr.update_status(case_id, CaseStatus.SEALED)
        _transition_case_status(case_id, "intake")
        case = mgr.get_case(case_id)
        assert case is not None and case.status == CaseStatus.SEALED
    finally:
        mgr.close()


# ---------------------------------------------------------------------------
# D5 — pipeline run durability
# ---------------------------------------------------------------------------


def test_d5_pipeline_status_survives_memory_loss(client):
    from nexus.config import settings
    from nexus.dashboard import app as app_mod

    case_id = _create(client, "D5 Case")
    headers = {"X-Nexus-Case": case_id}
    case_dir = settings.cases_root / case_id

    record = {
        "run_id": "deadbeef",
        "case_id": case_id,
        "mode": "tools",
        "status": "complete",
        "started_at": "",
        "completed_at": "",
        "error": "",
        "stages": [],
    }
    app_mod._persist_pipeline_run(case_dir, record)
    app_mod._pipeline_runs.clear()

    r = client.get("/portal/api/pipeline/status?run_id=deadbeef", headers=headers)
    assert r.status_code == 200
    assert r.json()["status"] == "complete"


def test_d5_running_record_reconciles_with_run_manifest(client):
    from nexus.config import settings
    from nexus.dashboard import app as app_mod
    from nexus.langgraph import pipeline_runs

    case_id = _create(client, "D5 Reconcile")
    headers = {"X-Nexus-Case": case_id}
    case_dir = settings.cases_root / case_id

    run = pipeline_runs.create_run(case_dir, "tools", [])
    pipeline_runs.finalize_run(run, "completed")
    app_mod._persist_pipeline_run(case_dir, {
        "run_id": "reconcile1",
        "case_id": case_id,
        "mode": "tools",
        "status": "running",
        "started_at": "",
        "completed_at": "",
        "error": "",
        "stages": [],
    })
    app_mod._pipeline_runs.clear()

    r = client.get("/portal/api/pipeline/status?run_id=reconcile1", headers=headers)
    assert r.status_code == 200
    assert r.json()["status"] == "complete"


# ---------------------------------------------------------------------------
# D6 — create/seed never activate unless asked
# ---------------------------------------------------------------------------


def test_d6_create_and_seed_do_not_activate(client, tmp_path):
    body = client.post("/portal/api/case/create", json={"name": "D6 Case"}).json()
    assert body["active"] == ""

    seeded = client.post("/portal/api/case/seed-demo", json={})
    assert seeded.status_code == 200, seeded.text
    assert seeded.json()["active"] == ""
    pointer = tmp_path / "active_case"
    assert (not pointer.exists()) or pointer.read_text(encoding="utf-8").strip() == ""


# ---------------------------------------------------------------------------
# D7 — every cockpit page re-fetches on case change (static)
# ---------------------------------------------------------------------------


def test_d7_cockpit_pages_depend_on_active_case():
    pages = [
        "Explore", "Timeline", "Findings", "SteerChat", "Workbench",
        "Approve", "Report", "Entities", "Evidence", "Iocs", "Todos",
        "Transparency",
    ]
    pattern = re.compile(r"\[[^\]]*activeCase[^\]]*\]", re.DOTALL)
    for page in pages:
        source = (FRONTEND_PAGES / f"{page}.tsx").read_text(encoding="utf-8")
        assert "activeCase" in source, f"{page}: does not use activeCase"
        assert pattern.search(source), (
            f"{page}: no useEffect dependency array includes activeCase — "
            "the page will show the previous case after a switch"
        )


# ---------------------------------------------------------------------------
# Spine invariants
# ---------------------------------------------------------------------------


def test_invariant_draft_only_cannot_create_approved(client):
    from nexus.case import CaseManager
    from nexus.case.schemas import ApprovalState
    from nexus.config import settings

    case_id = _create(client, "Invariant Case")
    mgr = CaseManager(settings.cases_root / "cases.db")
    try:
        finding = mgr.add_finding(
            case_id, title="forced approved", initial_state=ApprovalState.APPROVED
        )
        assert finding is not None
        assert finding.approval_state == ApprovalState.DRAFT
        assert finding.metadata.get("auto_approve_blocked") is True
    finally:
        mgr.close()


def test_invariant_fd001_rejects_finding_without_audit_trail(client):
    from nexus.config import settings
    from nexus.langgraph.mode1 import save_draft_finding

    case_id = _create(client, "FD001 Case")
    case_dir = settings.cases_root / case_id
    draft = {
        "title": "No audit trail",
        "observation": "observed",
        "interpretation": "interpreted",
        "confidence": "LOW",
        "confidence_justification": "test",
        "type": "finding",
        "audit_ids": [],
        "evidence": [{"source": "evtxecmd/x.csv", "detail": "row"}],
    }
    result = save_draft_finding(case_dir, draft)
    assert result.get("status") == "REJECTED", result
    assert result.get("missing_audit_ids") is not None or "evidence trail" in str(result.get("error"))


def test_invariant_runs_are_immutable(client):
    from nexus.config import settings
    from nexus.langgraph import pipeline_runs

    case_id = _create(client, "Immutable Case")
    case_dir = settings.cases_root / case_id

    first = pipeline_runs.create_run(case_dir, "tools", [])
    before = {
        p: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in first.path.rglob("*")
        if p.is_file()
    }
    second = pipeline_runs.create_run(case_dir, "tools", [])

    after = {
        p: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in first.path.rglob("*")
        if p.is_file()
    }
    assert before == after, "a later run modified an earlier immutable run"
    pointers = json.loads((case_dir / "active_runs.json").read_text(encoding="utf-8"))
    assert pointers["tools"] == second.run_id


def test_invariant_no_auto_approve(client):
    case_id = _create(client, "NoAutoApprove")
    headers = {"X-Nexus-Case": case_id}
    finding_id = _stage_finding(case_id, "Gate me")

    # Without a challenge the API must refuse outright.
    r = client.post("/portal/api/commit", headers=headers, json={"finding_ids": [finding_id]})
    assert r.status_code == 400

    findings = client.get("/portal/api/findings", headers=headers).json()["findings"]
    assert next(f for f in findings if f["id"] == finding_id)["status"] == "DRAFT"


def test_invariant_unsupported_tool_skips_with_reason():
    lane_src = (REPO / "src" / "nexus" / "langgraph" / "tool_lane.py").read_text(encoding="utf-8")
    assert "csv-timeline" not in lane_src, "Suzaku 2.x has no csv-timeline subcommand"
    assert "Suzaku 2.x is cloud-log only" in lane_src
