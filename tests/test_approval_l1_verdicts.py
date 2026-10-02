"""WO-2 (pre-gate): the L1 verdict is shown at approval time and enforced.

Real path: findings are staged through ``save_draft_finding``, approval is
driven through the real challenge-response commit endpoint, the CLI twin runs
through ``CliRunner``, and the recorded fields are read back from the files
the product writes. The only stand-in is the Elasticsearch *boundary*
(``_es_searcher``): verdicts must be deterministic without a live cluster. No
save/read function of the case store is mocked.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
from pathlib import Path

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient
from typer.testing import CliRunner

from nexus.case.records import save_findings

EXAMINER = "l1-verdict-examiner"
AUDIT_ID = "mftecmd-l1verdict-20260929-0001"
GOOD = "cmd.exe executed from a temporary directory"
BAD = "Beacon to ghosthost.example.com observed"
BAD_ROWS = [
    {
        "source": "evtx",
        "detail": "DNS query for ghosthost.example.com from the endpoint",
        "loc": "row 10",
    }
]


class _FakeSearcher:
    """Deterministic stand-in for the index boundary (an external system)."""

    def __init__(self, present: set[str]):
        self.present = {p.lower() for p in present}
        self.calls = 0

    def __call__(self, term: str) -> int:
        self.calls += 1
        return 5 if str(term).lower() in self.present else 0

    def family_count(self, family: str) -> int:  # pragma: no cover - no count claims
        self.calls += 1
        return 0


def _write_audit(case_dir: Path) -> None:
    audit = case_dir / "audit"
    audit.mkdir(parents=True, exist_ok=True)
    (audit / "nexus.jsonl").write_text(
        json.dumps(
            {"audit_id": AUDIT_ID, "tool": "mftecmd", "ts": "2026-09-29T09:00:00+00:00"}
        )
        + "\n",
        encoding="utf-8",
    )


def _stage(case_dir: Path, title: str, evidence: list[dict] | None = None) -> str:
    """Stage a DRAFT through the real staging function; return its finding id."""
    from nexus.modes.llm_desk import save_draft_finding

    draft = {
        "title": title,
        "observation": title,
        "interpretation": "Staged by the WO-2 regression test.",
        "confidence": "LOW",
        "confidence_justification": "Single parser family; awaiting corroboration.",
        "audit_ids": [AUDIT_ID],
        "artifacts": [{"type": "parser", "audit_id": AUDIT_ID}],
    }
    if evidence:
        draft["evidence"] = evidence
    result = save_draft_finding(case_dir, draft)
    entries = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    staged = [f for f in entries if f.get("title") == title]
    assert staged, f"staging did not persist a finding titled {title!r}: {result}"
    return str(staged[-1]["id"])


def _make_case(client: TestClient, tmp: Path) -> tuple[str, Path]:
    r = client.post(
        "/portal/api/case/create", json={"name": "L1 Verdict Case", "examiner": EXAMINER}
    )
    assert r.status_code == 200, r.text
    case_id = r.json()["case_id"]
    case_dir = tmp / "cases" / case_id
    _write_audit(case_dir)
    return case_id, case_dir


def _write_portal_password(tmp: Path) -> str:
    """The challenge-response needs only a deterministic stored hash."""
    stored_hash = hashlib.sha256(b"l1-verdict-stored-hash").hexdigest()
    passwords = tmp / "passwords"
    passwords.mkdir(exist_ok=True)
    (passwords / f"{EXAMINER}.json").write_text(
        json.dumps({"hash": stored_hash, "salt": "l1-verdict-salt"}),
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


def _verification_rows(tmp: Path) -> list[dict]:
    rows: list[dict] = []
    for path in (tmp / "verification").glob("*.jsonl"):
        rows.extend(
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        )
    return rows


@pytest.fixture()
def l1_env(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv("NEXUS_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(tmp_path / "active_case"))
    monkeypatch.setenv("NEXUS_SIFT_SYNC", "0")
    monkeypatch.setenv("NEXUS_RAG_PRELOAD", "0")
    monkeypatch.setenv("NEXUS_ES_AUTOINDEX", "0")
    monkeypatch.setenv("NEXUS_EXAMINER", EXAMINER)
    (tmp_path / "cases").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr("nexus.auth._PASSWORDS_DIR", tmp_path / "passwords")
    monkeypatch.setattr("nexus.auth.VERIFICATION_DIR", tmp_path / "verification")

    import nexus.analysis.claim_verification as cv

    fake = _FakeSearcher({"cmd.exe"})
    monkeypatch.setattr(cv, "_es_searcher", lambda case_dir: fake)
    cv._DRAFT_CACHE.clear()

    import nexus.dashboard.app as app_mod

    monkeypatch.setattr(app_mod, "_LOCKOUT_FILE", tmp_path / ".commit_lockout")

    from nexus.dashboard.app import create_dashboard

    return {
        "tmp": tmp_path,
        "client": TestClient(Starlette(routes=create_dashboard())),
        "fake": fake,
    }


def test_verify_drafts_proven_unsupported_and_cache(l1_env):
    tmp: Path = l1_env["tmp"]
    client: TestClient = l1_env["client"]
    fake: _FakeSearcher = l1_env["fake"]
    _, case_dir = _make_case(client, tmp)
    good = _stage(case_dir, GOOD)
    bad = _stage(case_dir, BAD, evidence=BAD_ROWS)

    from nexus.analysis.claim_verification import verify_drafts

    rows = verify_drafts(case_dir)
    assert rows[good]["verdict"] == "PROVEN", rows[good]
    assert rows[bad]["verdict"] == "UNSUPPORTED", rows[bad]
    assert [k for k, v in rows[bad]["checks"].items() if v["status"] == "fail"] == ["L1.3"]

    calls = fake.calls
    again = verify_drafts(case_dir)
    assert again[good]["verdict"] == "PROVEN"
    assert again[bad]["verdict"] == "UNSUPPORTED"
    assert fake.calls == calls, "cached verdicts must not re-query the index"


def test_portal_commit_enforces_override_reason(l1_env):
    tmp: Path = l1_env["tmp"]
    client: TestClient = l1_env["client"]
    stored = _write_portal_password(tmp)
    case_id, case_dir = _make_case(client, tmp)
    good = _stage(case_dir, GOOD)
    bad = _stage(case_dir, BAD, evidence=BAD_ROWS)
    headers = {"X-Nexus-Case": case_id}

    # The approval-desk payload carries the verdict before the examiner signs.
    payload = client.get("/portal/api/findings?status=DRAFT", headers=headers).json()
    by_id = {f["id"]: f for f in payload["findings"]}
    assert by_id[good]["l1"]["verdict"] == "PROVEN"
    assert by_id[bad]["l1"]["verdict"] == "UNSUPPORTED"
    assert by_id[bad]["l1"]["failing_checks"][0]["id"] == "L1.3"

    # PROVEN approves without an override.
    ch, resp = _respond(client, headers, stored)
    r = client.post(
        "/portal/api/commit",
        headers=headers,
        json={"finding_ids": [good], "challenge_id": ch, "response": resp},
    )
    assert r.status_code == 200, r.text
    assert good in r.json()["approved"]

    # Not PROVEN refuses without a reason and names the finding.
    ch, resp = _respond(client, headers, stored)
    r = client.post(
        "/portal/api/commit",
        headers=headers,
        json={"finding_ids": [bad], "challenge_id": ch, "response": resp},
    )
    assert r.status_code == 400, r.text
    refused = r.json()
    assert bad in refused["error"]
    assert refused["findings"][bad]["verdict"] == "UNSUPPORTED"

    # ... and approves with one; the verdict + reason land in the case file
    # and the verification ledger, and the submission seal still verifies.
    ch, resp = _respond(client, headers, stored)
    r = client.post(
        "/portal/api/commit",
        headers=headers,
        json={
            "finding_ids": [bad],
            "challenge_id": ch,
            "response": resp,
            "override_reasons": {bad: "Examiner verified the beacon against raw rows"},
        },
    )
    assert r.status_code == 200, r.text
    assert bad in r.json()["approved"]

    entries = {
        f["id"]: f
        for f in json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    }
    assert entries[good]["l1_verdict_at_approval"] == "PROVEN"
    assert entries[bad]["l1_verdict_at_approval"] == "UNSUPPORTED"
    assert entries[bad]["override_reason"] == "Examiner verified the beacon against raw rows"

    from nexus.analysis.integrity import verify_seal

    ok, reason = verify_seal(entries[bad])
    assert ok, reason

    ledger = next(r for r in _verification_rows(tmp) if r.get("finding_id") == bad)
    assert ledger["l1_verdict_at_approval"] == "UNSUPPORTED"
    assert ledger["override_reason"] == "Examiner verified the beacon against raw rows"


def test_cli_approve_shows_verdict_and_requires_reason(l1_env, monkeypatch):
    tmp: Path = l1_env["tmp"]
    client: TestClient = l1_env["client"]
    case_id, case_dir = _make_case(client, tmp)
    bad = _stage(case_dir, BAD, evidence=BAD_ROWS)

    from nexus.case.outputs import set_active_case_id

    set_active_case_id(case_id)

    # The CLI verifies the real PBKDF2 entry, so create one for real.
    from nexus.auth import setup_password

    setup_password(EXAMINER, "l1-cli-pass")
    monkeypatch.setenv("NEXUS_APPROVAL_PASSWORD", "l1-cli-pass")

    from nexus.cli.main import app as cli_app

    runner = CliRunner()
    r = runner.invoke(cli_app, ["approve", bad, "--examiner", EXAMINER])
    assert r.exit_code == 1, r.output
    assert "L1 UNSUPPORTED" in r.output
    assert "Refused" in r.output
    drafts = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    assert [f for f in drafts if f["status"] == "DRAFT"], "refusal must not approve"

    r = runner.invoke(
        cli_app,
        ["approve", bad, "--examiner", EXAMINER, "--reason", "Examiner accepted the beacon"],
    )
    assert r.exit_code == 0, r.output
    assert "APPROVED" in r.output

    entries = {
        f["id"]: f
        for f in json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    }
    assert entries[bad]["status"] == "APPROVED"
    assert entries[bad]["l1_verdict_at_approval"] == "UNSUPPORTED"
    assert entries[bad]["override_reason"] == "Examiner accepted the beacon"

    ledger = next(r for r in _verification_rows(tmp) if r.get("finding_id") == bad)
    assert ledger["l1_verdict_at_approval"] == "UNSUPPORTED"
    assert ledger["override_reason"] == "Examiner accepted the beacon"
    # the fixture password store is real PBKDF2 material
    assert (tmp / "passwords").exists()


def test_portal_commit_verifier_raise_requires_reason(l1_env, monkeypatch):
    """WO-10: verification that raised must not approve unreasoned."""
    tmp: Path = l1_env["tmp"]
    client: TestClient = l1_env["client"]
    stored = _write_portal_password(tmp)
    case_id, case_dir = _make_case(client, tmp)
    fid = _stage(case_dir, GOOD)
    headers = {"X-Nexus-Case": case_id}

    import nexus.analysis.claim_verification as cv

    def _boom(case_dir):  # noqa: ANN001
        raise RuntimeError("verifier unavailable")

    monkeypatch.setattr(cv, "verify_drafts", _boom)

    # No reason -> refused, named, and labeled UNVERIFIABLE - not approved.
    ch, resp = _respond(client, headers, stored)
    r = client.post(
        "/portal/api/commit",
        headers=headers,
        json={"finding_ids": [fid], "challenge_id": ch, "response": resp},
    )
    assert r.status_code == 400, r.text
    assert r.json()["findings"][fid]["verdict"] == "UNVERIFIABLE"
    entries = {
        f["id"]: f
        for f in json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    }
    assert entries[fid]["status"] == "DRAFT", "refusal must not approve"

    # With a reason -> approved; the label and the reason are recorded.
    ch, resp = _respond(client, headers, stored)
    r = client.post(
        "/portal/api/commit",
        headers=headers,
        json={
            "finding_ids": [fid],
            "challenge_id": ch,
            "response": resp,
            "override_reasons": {fid: "Verifier down; examiner read the raw rows"},
        },
    )
    assert r.status_code == 200, r.text
    assert fid in r.json()["approved"]
    entries = {
        f["id"]: f
        for f in json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    }
    assert entries[fid]["l1_verdict_at_approval"] == "UNVERIFIABLE"
    assert entries[fid]["override_reason"] == "Verifier down; examiner read the raw rows"


def test_portal_commit_absent_from_verdict_map_requires_reason(l1_env, monkeypatch):
    """WO-10: a verifier run that omitted the id is the same class."""
    tmp: Path = l1_env["tmp"]
    client: TestClient = l1_env["client"]
    stored = _write_portal_password(tmp)
    case_id, case_dir = _make_case(client, tmp)
    fid = _stage(case_dir, GOOD)
    headers = {"X-Nexus-Case": case_id}

    import nexus.analysis.claim_verification as cv

    monkeypatch.setattr(cv, "verify_drafts", lambda case_dir: {})

    ch, resp = _respond(client, headers, stored)
    r = client.post(
        "/portal/api/commit",
        headers=headers,
        json={"finding_ids": [fid], "challenge_id": ch, "response": resp},
    )
    assert r.status_code == 400, r.text
    assert r.json()["findings"][fid]["verdict"] == "UNVERIFIABLE"

    ch, resp = _respond(client, headers, stored)
    r = client.post(
        "/portal/api/commit",
        headers=headers,
        json={
            "finding_ids": [fid],
            "challenge_id": ch,
            "response": resp,
            "override_reasons": {fid: "Verdict map omitted the id; examiner reviewed"},
        },
    )
    assert r.status_code == 200, r.text
    entries = {
        f["id"]: f
        for f in json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    }
    assert entries[fid]["l1_verdict_at_approval"] == "UNVERIFIABLE"


def test_portal_commit_refuses_a_broken_seal_even_with_override(l1_env):
    """WO-21: an edited-after-staging finding must not be approvable via the portal."""
    tmp: Path = l1_env["tmp"]
    client: TestClient = l1_env["client"]
    stored = _write_portal_password(tmp)
    case_id, case_dir = _make_case(client, tmp)
    fid = _stage(case_dir, GOOD)
    headers = {"X-Nexus-Case": case_id}

    rows = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    target = next(f for f in rows if f["id"] == fid)
    assert target.get("seal") or target.get("content_hash"), (
        "staging must seal the entry for this test to mean anything"
    )
    target["title"] = "edited after staging"
    # Edit through the case store, not the flat file: findings.json is a
    # generated mirror, so a mirror-only edit is refused as drift before the
    # seal is ever checked. Writing the store keeps the two in step and leaves
    # the stale seal, which is what this test is about.
    save_findings(case_dir, rows)

    # No override: the L1 gate refuses (the edit made the finding non-PROVEN).
    ch, resp = _respond(client, headers, stored)
    r = client.post(
        "/portal/api/commit",
        headers=headers,
        json={"finding_ids": [fid], "challenge_id": ch, "response": resp},
    )
    assert r.status_code == 400, r.text

    # With an override: the SEAL check still refuses, and nothing is signed.
    ch, resp = _respond(client, headers, stored)
    r = client.post(
        "/portal/api/commit",
        headers=headers,
        json={
            "finding_ids": [fid],
            "challenge_id": ch,
            "response": resp,
            "override_reasons": {fid: "examiner says it is fine"},
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["approved"] == [], body
    assert any("seal" in str(e.get("error", "")).lower() for e in body["errors"]), body
    entries = {
        f["id"]: f
        for f in json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    }
    assert entries[fid]["status"] == "DRAFT"
    assert not [row for row in _verification_rows(tmp) if row.get("finding_id") == fid]


def test_portal_commit_seal_less_draft_needs_a_reason(l1_env):
    """WO-23: a seal-less DRAFT is UNSEALED -> UNVERIFIABLE + override + record."""
    tmp: Path = l1_env["tmp"]
    client: TestClient = l1_env["client"]
    stored = _write_portal_password(tmp)
    case_id, case_dir = _make_case(client, tmp)
    fid = _stage(case_dir, GOOD)
    headers = {"X-Nexus-Case": case_id}

    rows = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    target = next(f for f in rows if f["id"] == fid)
    target.pop("seal", None)
    target.pop("content_hash", None)
    # Edit through the case store, not the flat file: findings.json is a
    # generated mirror, so a mirror-only edit is refused as drift before the
    # seal is ever checked. Writing the store keeps the two in step and leaves
    # the stale seal, which is what this test is about.
    save_findings(case_dir, rows)

    ch, resp = _respond(client, headers, stored)
    r = client.post(
        "/portal/api/commit",
        headers=headers,
        json={"finding_ids": [fid], "challenge_id": ch, "response": resp},
    )
    assert r.status_code == 400, r.text
    assert r.json()["findings"][fid]["verdict"] == "UNVERIFIABLE"

    ch, resp = _respond(client, headers, stored)
    r = client.post(
        "/portal/api/commit",
        headers=headers,
        json={
            "finding_ids": [fid],
            "challenge_id": ch,
            "response": resp,
            "override_reasons": {fid: "pre-10.4 draft; reviewed by examiner"},
        },
    )
    assert r.status_code == 200, r.text
    assert fid in r.json()["approved"]
    entries = {
        f["id"]: f
        for f in json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    }
    assert entries[fid]["seal_state"] == "absent"
    ledger = next(r for r in _verification_rows(tmp) if r.get("finding_id") == fid)
    assert ledger["seal_state"] == "absent"


def test_cli_approve_seal_less_draft_needs_a_reason(l1_env, monkeypatch):
    """WO-23 CLI twin: unsealed DRAFT -> reason required, seal_state recorded."""
    tmp: Path = l1_env["tmp"]
    client: TestClient = l1_env["client"]
    case_id, case_dir = _make_case(client, tmp)
    fid = _stage(case_dir, GOOD)

    rows = json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    target = next(f for f in rows if f["id"] == fid)
    target.pop("seal", None)
    target.pop("content_hash", None)
    # Edit through the case store, not the flat file: findings.json is a
    # generated mirror, so a mirror-only edit is refused as drift before the
    # seal is ever checked. Writing the store keeps the two in step and leaves
    # the stale seal, which is what this test is about.
    save_findings(case_dir, rows)

    from nexus.case.outputs import set_active_case_id

    set_active_case_id(case_id)

    from nexus.auth import setup_password

    setup_password(EXAMINER, "l1-cli-pass")
    monkeypatch.setenv("NEXUS_APPROVAL_PASSWORD", "l1-cli-pass")

    from nexus.cli.main import app as cli_app

    runner = CliRunner()
    r = runner.invoke(cli_app, ["approve", fid, "--examiner", EXAMINER])
    assert r.exit_code == 1, r.output
    assert "UNVERIFIABLE" in r.output

    r = runner.invoke(
        cli_app,
        ["approve", fid, "--examiner", EXAMINER, "--reason", "pre-10.4 draft; reviewed"],
    )
    assert r.exit_code == 0, r.output
    entries = {
        f["id"]: f
        for f in json.loads((case_dir / "findings.json").read_text(encoding="utf-8"))
    }
    assert entries[fid]["seal_state"] == "absent"
    ledger = next(r for r in _verification_rows(tmp) if r.get("finding_id") == fid)
    assert ledger["seal_state"] == "absent"