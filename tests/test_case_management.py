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


def test_sealed_case_locks_actions_until_reopened(client, tmp_path):
    """Sealed = completed: mutations are rejected (409) until reopen."""
    from nexus.case import CaseManager
    from nexus.case.schemas import CaseStatus
    from nexus.config import settings

    case_id = _create(client, "Sealed Case")["case_id"]
    ev = tmp_path / "first.txt"
    ev.write_text("first", encoding="utf-8")
    assert client.post(
        "/portal/api/evidence", json={"path": str(ev), "case_id": case_id}
    ).status_code == 200

    mgr = CaseManager(settings.cases_root / "cases.db")
    try:
        mgr.update_status(case_id, CaseStatus.SEALED)
    finally:
        mgr.close()

    ev2 = tmp_path / "second.txt"
    ev2.write_text("second", encoding="utf-8")
    assert client.post(
        "/portal/api/evidence", json={"path": str(ev2), "case_id": case_id}
    ).status_code == 409
    assert client.post(
        "/portal/api/pipeline/run", json={"mode": "tools", "case_id": case_id}
    ).status_code == 409
    assert client.post(
        "/portal/api/case/mode", json={"mode": "2", "case_id": case_id}
    ).status_code == 409

    hdr = {"X-Nexus-Case": case_id}
    assert client.post(
        "/portal/api/mode1/ask", json={"question": "sdelete?"}, headers=hdr
    ).status_code == 409
    assert client.post(
        "/portal/api/workbench/add",
        json={"hit": {"file": "x.csv", "text": "t"}},
        headers=hdr,
    ).status_code == 409
    assert client.post(
        "/portal/api/chat/clear", json={}, headers=hdr
    ).status_code == 409
    assert client.post(
        "/portal/api/report/generate", json={"llm": False}, headers=hdr
    ).status_code == 409
    assert client.post(
        "/portal/api/report/steer", json={"instruction": "dig"}, headers=hdr
    ).status_code == 409
    assert client.post(
        "/portal/api/query-rerun", json={"needles": "sdelete"}, headers=hdr
    ).status_code == 409

    r = client.post("/portal/api/case/reopen", json={"case_id": case_id})
    assert r.status_code == 200
    assert r.json()["status"] == "active"
    assert r.json()["reopened_from"] == "sealed"

    # Actions flow again after the explicit reopen.
    assert client.post(
        "/portal/api/evidence", json={"path": str(ev2), "case_id": case_id}
    ).status_code == 200
    details = client.get(f"/portal/api/case/{case_id}/details").json()
    assert details["status"] == "active"


def test_case_seal_route_is_canonical_lifecycle_endpoint(client):
    """/case/seal is the general close action (mode-agnostic); /mode3/seal is
    an alias. Both enforce the same challenge-response contract."""
    case_id = _create(client, "Seal Route Case")["case_id"]
    hdr = {"X-Nexus-Case": case_id}

    for path in ("/portal/api/case/seal",):
        # Missing challenge fields → 400 (not 404 — the route exists).
        r = client.post(path, json={}, headers=hdr)
        assert r.status_code == 400, (path, r.text)
        # Bogus challenge → 401.
        r = client.post(
            path, json={"challenge_id": "nope", "response": "00"}, headers=hdr
        )
        assert r.status_code == 401, (path, r.text)


def _seed_extraction_csv(case_id, tmp_path, rows):
    """Write a CSV under extractions/ so the N4 CSV backend has rows."""
    from nexus.config import settings
    ext = settings.cases_root / case_id / "extractions" / "hayabusa"
    ext.mkdir(parents=True, exist_ok=True)
    (ext / "timeline.csv").write_text(
        "time,host,event\n" + rows, encoding="utf-8"
    )


def test_entities_empty_request_scans_all_and_needles_filter(client, tmp_path):
    """4j.5n: the Entities page posts {needles} — it must reach the query,
    and an empty request must match-all (WP 4b.9: page populates on mount)."""
    case_id = _create(client, "Entities Case")["case_id"]
    hdr = {"X-Nexus-Case": case_id}
    _seed_extraction_csv(
        case_id, tmp_path,
        "2026-08-10T15:00:00Z,WS01,sdelete.exe ran\n"
        "2026-08-10T15:01:00Z,WS01,beacon to https://evil-c2.example.com/x\n",
    )

    r = client.post("/portal/api/entities", json={}, headers=hdr)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["total"] >= 2, body
    assert "sdelete.exe" in body["entities"]["processes"]

    # needles= is a real filter, not a dead parameter.
    r = client.post("/portal/api/entities", json={"needles": "evil-c2"}, headers=hdr)
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 1


def test_iocs_unified_store_and_extended_extraction(client, tmp_path):
    """4j.5n: /iocs reads the unified store (iocs.json incl. legacy dict
    shape) — finding auto-extract now covers URLs/domains/emails."""
    import json as _json

    from nexus.case_manager import CaseManager as FlatCM
    from nexus.config import settings

    case_id = _create(client, "IOC Case")["case_id"]
    hdr = {"X-Nexus-Case": case_id}
    case_dir = settings.cases_root / case_id

    # Audit log so provenance passes (FD-001) — audit_ids must exist.
    audit_dir = case_dir / "audit"
    audit_dir.mkdir(exist_ok=True)
    aid1, aid2 = "hayabusa-examiner-20260913-001", "evtxecmd-examiner-20260913-002"
    (audit_dir / "tool.jsonl").write_text(
        _json.dumps({"audit_id": aid1, "source": "mcp", "tool": "test"}) + "\n"
        + _json.dumps({"audit_id": aid2, "source": "mcp", "tool": "test"}) + "\n"
    )

    # Legacy dict-shaped iocs.json (SQLite mirror schema) must still read.
    (case_dir / "iocs.json").write_text(_json.dumps({
        "ip": [], "host": [],
        "hash": [{"value": "ab" * 32, "source_findings": [], "source": "evidence"}],
    }))

    result = FlatCM().record_finding(
        {
            "title": "C2 callback to hotelesms.com",
            "observation": "mshta.exe fetched https://hotelesms.com/payload.hta "
                           "from 45.9.1.10; dropped payload.zip locally",
            "interpretation": "operator admin@evil-c2.net staged it",
            "confidence": "LOW",
            "confidence_justification": "test justification",
            "evidence": [
                {"audit_id": aid1, "source": "hayabusa/x", "path": "/x"},
                {"audit_id": aid2, "source": "evtxecmd/y", "path": "/y"},
            ],
            "audit_ids": [aid1, aid2],
        },
        case_dir=case_dir,
    )
    assert result["status"] == "STAGED", result

    r = client.get("/portal/api/iocs", headers=hdr)
    assert r.status_code == 200, r.text
    iocs = r.json()["iocs"]
    values = {str(i.get("value", "")).lower() for i in iocs}
    assert "hotelesms.com" in values            # domain — was never extracted before
    assert any(v.startswith("https://hotelesms.com") for v in values)  # url
    assert "45.9.1.10" in values                # ipv4
    assert "admin@evil-c2.net" in values        # email
    assert "ab" * 32 in values                  # legacy dict-shape evidence IOC
    # payload.zip is a filename, not a domain indicator.
    assert "payload.zip" not in values
    # Finding linkage survives on auto-extracted IOCs.
    c2 = next(i for i in iocs if i.get("value") == "hotelesms.com")
    assert "C2 callback" in c2.get("finding_title", "")
    assert c2.get("finding_status") == "DRAFT"


def test_todos_portal_add_update_and_sealed_guard(client, tmp_path):
    """4j.5n: TODOs are examiner follow-ups — add/complete via the portal,
    sealed cases lock them like every other mutator."""
    from nexus.case import CaseManager
    from nexus.case.schemas import CaseStatus
    from nexus.config import settings

    case_id = _create(client, "TODO Case")["case_id"]
    hdr = {"X-Nexus-Case": case_id}

    r = client.post(
        "/portal/api/todos",
        json={"description": "verify lateral movement to HOST2", "priority": "high"},
        headers=hdr,
    )
    assert r.status_code == 200, r.text
    todo_id = r.json()["todo_id"]
    assert todo_id.startswith("TODO-")

    body = client.get("/portal/api/todos", headers=hdr).json()
    assert body["total"] == 1
    assert body["todos"][0]["status"] == "open"

    r = client.post(
        "/portal/api/todos/update",
        json={"todo_id": todo_id, "status": "completed"},
        headers=hdr,
    )
    assert r.status_code == 200, r.text
    body = client.get("/portal/api/todos?status=completed", headers=hdr).json()
    assert body["total"] == 1
    assert body["todos"][0].get("completed_at")

    # Unknown id -> 404; empty update -> 400.
    assert client.post(
        "/portal/api/todos/update", json={"todo_id": "TODO-x-999", "status": "open"},
        headers=hdr,
    ).status_code == 404
    assert client.post(
        "/portal/api/todos/update", json={"todo_id": todo_id}, headers=hdr,
    ).status_code == 400

    # Sealed case locks todo mutations (409) — same as every other mutator.
    mgr = CaseManager(settings.cases_root / "cases.db")
    try:
        mgr.update_status(case_id, CaseStatus.SEALED)
    finally:
        mgr.close()
    assert client.post(
        "/portal/api/todos", json={"description": "x"}, headers=hdr,
    ).status_code == 409
    assert client.post(
        "/portal/api/todos/update",
        json={"todo_id": todo_id, "status": "open"},
        headers=hdr,
    ).status_code == 409


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
