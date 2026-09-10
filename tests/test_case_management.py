"""Tests for case management segregation (Phase 4e).

Covers:
- create/seed do not activate unless explicitly requested
- activate/deactivate write/clear the active-case pointer
- status lifecycle (created -> intake -> processing -> active -> sealed)
- case details by id (/case/{id}/details) with no active case
- X-Nexus-Case header scoping (evidence registered to the explicit case)
- evidence list comes from the SQLite system of record (regression for the
  evidence_registry.json split-brain where registered evidence never showed)
"""
import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from nexus.dashboard.app import create_dashboard


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    dashboard = create_dashboard()
    app = Starlette(routes=dashboard)
    return TestClient(app)


def _create(client, name="Case A", **extra):
    r = client.post("/portal/api/case/create", json={"name": name, **extra})
    assert r.status_code == 200, r.text
    return r.json()


def _pointer(tmp_path):
    p = tmp_path / "active_case"
    return p.read_text(encoding="utf-8").strip() if p.exists() else ""


def test_create_does_not_activate(client, tmp_path):
    body = _create(client)
    assert body["active"] == ""
    assert _pointer(tmp_path) == ""


def test_create_activate_true(client, tmp_path):
    body = _create(client, activate=True)
    assert body["active"] == body["case_id"]
    assert _pointer(tmp_path) == body["case_id"]


def test_activate_and_deactivate(client, tmp_path):
    case_id = _create(client)["case_id"]
    r = client.post("/portal/api/case/activate", json={"case_id": case_id})
    assert r.status_code == 200
    assert _pointer(tmp_path) == case_id

    r = client.post("/portal/api/case/deactivate")
    assert r.status_code == 200
    assert r.json()["active"] == ""
    assert _pointer(tmp_path) == ""


def test_seed_without_activate_leaves_pointer(client, tmp_path):
    r = client.post("/portal/api/case/seed-demo", json={"name": "Demo"})
    assert r.status_code == 200
    assert _pointer(tmp_path) == ""

    # The demo is flagged synthetic in both dashboard and detail payloads.
    seeded_id = r.json()["case_id"]
    cases = client.get("/portal/api/cases").json()
    assert cases["details"][seeded_id]["synthetic"] is True
    details = client.get(f"/portal/api/case/{seeded_id}/details").json()
    assert details["synthetic"] is True

    # Explicit activate still switches the pointer (legacy flow)
    r = client.post("/portal/api/case/seed-demo", json={"name": "Demo", "activate": True})
    assert r.status_code == 200
    assert _pointer(tmp_path) == r.json()["case_id"]


def test_status_lifecycle(client, tmp_path):
    from nexus.case import CaseManager
    from nexus.case.schemas import CaseStatus
    from nexus.config import settings

    case_id = _create(client)["case_id"]
    mgr = CaseManager(settings.cases_root / "cases.db")
    try:
        case = mgr.get_case(case_id)
        assert case is not None and case.status == CaseStatus.CREATED

        # Evidence registration advances CREATED -> INTAKE
        ev = tmp_path / "evidence.txt"
        ev.write_text("hello", encoding="utf-8")
        r = client.post(
            "/portal/api/evidence",
            json={"path": str(ev), "case_id": case_id},
        )
        assert r.status_code == 200, r.text
        case = mgr.get_case(case_id)
        assert case is not None and case.status == CaseStatus.INTAKE

        mgr.update_status(case_id, CaseStatus.PROCESSING)
        mgr.update_status(case_id, CaseStatus.ACTIVE)
        mgr.update_status(case_id, CaseStatus.SEALED)
        case = mgr.get_case(case_id)
        assert case is not None and case.status == CaseStatus.SEALED
    finally:
        mgr.close()


def test_case_details_by_id_without_active_case(client):
    case_id = _create(client, name="Details Case")["case_id"]

    r = client.get(f"/portal/api/case/{case_id}/details")
    assert r.status_code == 200
    body = r.json()
    assert body["case_id"] == case_id
    assert body["status"] == "created"

    # legacy shortcut still works with ?case_id=
    r = client.get(f"/portal/api/case/details?case_id={case_id}")
    assert r.status_code == 200

    # without any case it 404s
    r = client.get("/portal/api/case/details")
    assert r.status_code == 404


def test_evidence_register_and_list_via_case_header(client, tmp_path):
    """Regression: portal-registered evidence must appear in the evidence list."""
    case_id = _create(client, name="Evidence Case")["case_id"]
    ev = tmp_path / "sample.txt"
    ev.write_text("evidence-bytes", encoding="utf-8")

    r = client.post("/portal/api/evidence", json={"path": str(ev), "case_id": case_id})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True
    assert body["sha256"]

    headers = {"X-Nexus-Case": case_id}
    r = client.get("/portal/api/evidence", headers=headers)
    assert r.status_code == 200
    items = r.json()["evidence"]
    assert len(items) == 1
    assert items[0]["path"] == str(ev)
    assert items[0]["sha256"] == body["sha256"]

    # summary count matches the list (single source of record)
    r = client.get("/portal/api/summary", headers=headers)
    assert r.status_code == 200
    assert r.json()["evidence"] == 1

    # details count matches too
    r = client.get(f"/portal/api/case/{case_id}/details")
    assert r.json()["evidence_count"] == 1


def test_evidence_header_scopes_to_case_not_pointer(client, tmp_path):
    """Case A's evidence must not leak into case B (explicit header scoping)."""
    a = _create(client, name="Case A")["case_id"]
    b = _create(client, name="Case B")["case_id"]

    ev_a = tmp_path / "a.txt"
    ev_a.write_text("aaa", encoding="utf-8")
    ev_b = tmp_path / "b.txt"
    ev_b.write_text("bbb", encoding="utf-8")

    assert client.post(
        "/portal/api/evidence", json={"path": str(ev_a), "case_id": a}
    ).status_code == 200
    assert client.post(
        "/portal/api/evidence", json={"path": str(ev_b), "case_id": b}
    ).status_code == 200

    a_items = client.get("/portal/api/evidence", headers={"X-Nexus-Case": a}).json()["evidence"]
    b_items = client.get("/portal/api/evidence", headers={"X-Nexus-Case": b}).json()["evidence"]
    assert [i["path"] for i in a_items] == [str(ev_a)]
    assert [i["path"] for i in b_items] == [str(ev_b)]


def test_cases_endpoint_exposes_status_and_details(client):
    case_id = _create(client, name="Status Case")["case_id"]
    r = client.get("/portal/api/cases")
    assert r.status_code == 200
    body = r.json()
    assert case_id in body["cases"]
    assert body["details"][case_id]["status"] == "created"
    assert body["details"][case_id]["name"] == "Status Case"


def test_evidence_hash_parity_with_legacy_mcp(tmp_path):
    """The unified service and the legacy MCP hasher must agree on digests."""
    from nexus.case.evidence_service import hash_evidence_path as unified_hash
    from nexus.case_manager import _hash_evidence_path as legacy_hash

    tree = tmp_path / "tree"
    (tree / "sub").mkdir(parents=True)
    (tree / "a.txt").write_text("alpha", encoding="utf-8")
    (tree / "sub" / "b.bin").write_bytes(b"\x00\x01\x02")
    assert unified_hash(tree) == legacy_hash(tree)

    single = tmp_path / "single.txt"
    single.write_text("single", encoding="utf-8")
    assert unified_hash(single) == legacy_hash(single)
