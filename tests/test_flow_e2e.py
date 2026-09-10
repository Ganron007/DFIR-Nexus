"""Phase 4f L1 — full-loop flow test (design vs actual behavior).

Runs one real investigation through the Portal API on a Stage-0-shaped
evidence pack (two real EVTX files under ``wevtutil/``), exercising the real
N2 tool lane (Chainsaw / EvtxECmd), N4 search, workbench promotion, HMAC
approval, official report generation, and the mode-3 case seal.

This is deliberately an integration test: it takes minutes because it starts
the real MCP server and Windows parsers. It requires the local evidence
fixture (``Evidence-files/01-windows/evtx/504-win10``) and the Windows tool
binaries (gitignored ``Tools/windows``); otherwise it skips with a reason.

Run alone:      pytest tests/test_flow_e2e.py -q -s
Skip the slow:  pytest -q -k "not flow_e2e"
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import shutil
import time
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

REPO = Path(__file__).resolve().parent.parent
EVTX_SRC = REPO / "Evidence-files" / "01-windows" / "evtx" / "504-win10"
EXAMINER = "flow-e2e"
PIPELINE_TIMEOUT_SECONDS = 900


def _write_password_entry(tmp_path: Path) -> str:
    """Fabricate an examiner password entry (challenge-response auth material).

    The server authenticates by HMAC over the *stored* hash, so the test needs
    only a deterministic 32-byte hash — no PBKDF2 round trip required.
    """
    stored_hash = hashlib.sha256(b"flow-e2e-stored-hash").hexdigest()
    passwords = tmp_path / "passwords"
    passwords.mkdir(exist_ok=True)
    (passwords / f"{EXAMINER}.json").write_text(
        json.dumps({"hash": stored_hash, "salt": "flow-e2e-salt"}),
        encoding="utf-8",
    )
    return stored_hash


def _respond(client: TestClient, headers: dict[str, str], stored_hash: str) -> tuple[str, str]:
    challenge = client.get("/portal/api/commit/challenge", headers=headers).json()
    response = hmac_mod.new(
        bytes.fromhex(stored_hash),
        challenge["nonce"].encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return challenge["challenge_id"], response


def _build_stage0_pack(tmp_path: Path) -> Path:
    """A Stage-0-shaped pack: ``<pack>/wevtutil/*.evtx`` (real EVTX samples)."""
    if not EVTX_SRC.is_dir():
        pytest.skip(f"EVTX fixture missing: {EVTX_SRC}")
    pack = tmp_path / "pack"
    (pack / "wevtutil").mkdir(parents=True)
    copied = 0
    for name in ("Application.evtx", "HardwareEvents.evtx"):
        src = EVTX_SRC / name
        if src.is_file():
            shutil.copy2(src, pack / "wevtutil" / name)
            copied += 1
    if not copied:
        pytest.skip("no usable EVTX sample in the fixture directory")
    return pack


@pytest.fixture()
def flow_env(tmp_path, monkeypatch):
    """Isolated store + env for the flow (mirrors the conftest isolation)."""
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    monkeypatch.setenv("NEXUS_SIFT_SYNC", "0")
    monkeypatch.setenv("NEXUS_N4_BACKEND", "csv")
    monkeypatch.setenv("NEXUS_ES_AUTOINDEX", "0")
    monkeypatch.setenv("NEXUS_RAG_PRELOAD", "0")
    monkeypatch.setenv("NEXUS_REPO_EXPORT", "0")
    monkeypatch.setenv("NEXUS_EXAMINER", EXAMINER)
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)

    import nexus.dashboard.app as app_mod

    monkeypatch.setattr(app_mod, "_LOCKOUT_FILE", tmp_path / ".commit_lockout")
    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", tmp_path / "passwords")

    from nexus.dashboard.app import create_dashboard

    return {
        "tmp_path": tmp_path,
        "client": TestClient(Starlette(routes=create_dashboard())),
    }


def test_full_loop_design_flow(flow_env, monkeypatch):
    tmp_path: Path = flow_env["tmp_path"]
    client: TestClient = flow_env["client"]
    stored_hash = _write_password_entry(tmp_path)

    # 1. Create — must NOT activate (D3/D6)
    r = client.post("/portal/api/case/create", json={"name": "Flow E2E", "examiner": EXAMINER})
    assert r.status_code == 200, r.text
    body = r.json()
    case_id = body["case_id"]
    assert body["active"] == ""
    pointer = tmp_path / "active_case"
    assert (not pointer.exists()) or pointer.read_text(encoding="utf-8").strip() == ""
    headers = {"X-Nexus-Case": case_id}
    assert client.get(f"/portal/api/case/{case_id}/details").json()["status"] == "created"

    # 2. Register a Stage-0 pack (explicit case id) — visible everywhere immediately (D1)
    pack = _build_stage0_pack(tmp_path)
    r = client.post("/portal/api/evidence", json={"path": str(pack), "case_id": case_id})
    assert r.status_code == 200, r.text
    assert r.json()["sha256"]

    evidence = client.get("/portal/api/evidence", headers=headers).json()
    assert evidence["total"] == 1, evidence
    assert evidence["evidence"][0]["path"] == str(pack)
    summary = client.get("/portal/api/summary", headers=headers).json()
    assert summary["evidence"] == 1
    details = client.get(f"/portal/api/case/{case_id}/details").json()
    assert details["evidence_count"] == 1
    assert details["status"] == "intake"

    # 3. Mode
    r = client.post("/portal/api/case/mode", json={"mode": "1", "case_id": case_id})
    assert r.status_code == 200, r.text

    # 4. Real N2 tool lane via the API (background thread -> real MCP + parsers)
    r = client.post("/portal/api/pipeline/run", json={"mode": "tools", "case_id": case_id})
    assert r.status_code == 200, r.text
    run_id = r.json()["run_id"]

    deadline = time.time() + PIPELINE_TIMEOUT_SECONDS
    status = ""
    while time.time() < deadline:
        status = client.get(f"/portal/api/pipeline/status?run_id={run_id}", headers=headers).json().get("status", "")
        if status in ("complete", "error"):
            break
        time.sleep(5)
    assert status == "complete", f"N2 lane did not complete: {status}"

    from nexus.case import CaseManager
    from nexus.case.schemas import CaseStatus
    from nexus.config import settings
    from nexus.langgraph.pipeline_runs import resolve_run

    mgr = CaseManager(settings.cases_root / "cases.db")
    try:
        case = mgr.get_case(case_id)
        assert case is not None and case.status == CaseStatus.ACTIVE
    finally:
        mgr.close()

    case_dir = settings.cases_root / case_id
    run = resolve_run(case_dir, "tools")
    ledger = json.loads((run.extractions / "_tool_lane_ledger.json").read_text(encoding="utf-8"))
    assert any(row.get("status") == "OK" for row in ledger), ledger
    parse_csvs = [p for p in run.extractions.rglob("*.csv") if p.stat().st_size > 0]
    assert parse_csvs, "lane completed but produced no parser CSV"

    # 5. N4 search through the real route
    r = client.post("/portal/api/explore/search", headers=headers, json={"needles": "Application"})
    assert r.status_code == 200, r.text
    search = r.json()
    assert search["count"] > 0, search
    hit = search["hits"][0]

    # 6. Bookmark -> promote -> DRAFT with lane audit ids (heuristic scribe, no network)
    r = client.post("/portal/api/workbench/add", headers=headers, json={"hit": hit, "note": "flow e2e"})
    assert r.status_code == 200, r.text
    bookmark_id = r.json()["bookmark_id"]

    import nexus.langgraph.llm_pipeline as lp

    def _no_model(*_args, **_kwargs):
        raise RuntimeError("LLM disabled in the flow test — heuristic scribe path")

    monkeypatch.setattr(lp, "get_model", _no_model)
    r = client.post(
        "/portal/api/workbench/promote",
        headers=headers,
        json={
            "bookmark_ids": [bookmark_id],
            "title": "Flow E2E — Application channel activity",
            "scribe": True,
        },
    )
    assert r.status_code == 200, r.text
    promoted = r.json()
    assert promoted.get("finding_id"), promoted
    finding_id = promoted["finding_id"]

    findings = client.get("/portal/api/findings", headers=headers).json()["findings"]
    staged = next(f for f in findings if f["id"] == finding_id)
    assert staged["status"] == "DRAFT"
    assert staged["audit_ids"], "promote must carry lane audit ids (FD-001)"

    # 7. HMAC approval — challenge-response only, no auto-approve
    r = client.post("/portal/api/commit", headers=headers, json={"finding_ids": [finding_id]})
    assert r.status_code == 400  # missing challenge
    challenge_id, response = _respond(client, headers, stored_hash)
    r = client.post(
        "/portal/api/commit",
        headers=headers,
        json={"finding_ids": [finding_id], "challenge_id": challenge_id, "response": "00" * 32},
    )
    assert r.status_code == 401  # wrong password material
    challenge_id, response = _respond(client, headers, stored_hash)
    r = client.post(
        "/portal/api/commit",
        headers=headers,
        json={"finding_ids": [finding_id], "challenge_id": challenge_id, "response": response},
    )
    assert r.status_code == 200, r.text
    assert finding_id in r.json()["approved"]

    # 8. Official report (APPROVED only)
    r = client.post("/portal/api/report/generate", headers=headers, json={})
    assert r.status_code == 200, r.text
    assert r.json()["findings_count"] >= 1
    view = client.get("/portal/api/report/view", headers=headers).json()
    assert view.get("ok") is True
    assert "Flow E2E" in view.get("markdown", "")

    # 9. Case-file seal via the same challenge-response (lifecycle -> SEALED)
    challenge_id, response = _respond(client, headers, stored_hash)
    r = client.post(
        "/portal/api/mode3/seal",
        headers=headers,
        json={"challenge_id": challenge_id, "response": response},
    )
    assert r.status_code == 200, r.text
    mgr = CaseManager(settings.cases_root / "cases.db")
    try:
        case = mgr.get_case(case_id)
        assert case is not None and case.status == CaseStatus.SEALED
    finally:
        mgr.close()
