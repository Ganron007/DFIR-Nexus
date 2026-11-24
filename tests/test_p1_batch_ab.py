"""Regression tests for P1 Batch A and Batch B fixes (AUD-05, 06, 10, 11, 16, 17, CI)."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.messages import AIMessage
from starlette.applications import Starlette
from starlette.testclient import TestClient
from typer.testing import CliRunner

from nexus.audit import AuditWriter
from nexus.langgraph import context_loop, es_native
from tests.test_context_loop import _case, _fake_backbone
from tests.test_query_generation_contract import TYPES
from tests.test_tool_generation import SchemaRecordingModel

# ---------------------------------------------------------------------------
# P1-13 / AUD-17: Narrow grammar-rejection detection vs transport failures
# ---------------------------------------------------------------------------


def test_p1_13_provider_400_parameter_rejection_falls_back_cleanly(tmp_path: Path, monkeypatch):
    class BadRequestError(Exception):
        def __init__(self, message: str) -> None:
            super().__init__(message)
            self.status_code = 400

    class GrammarRejectingModel(SchemaRecordingModel):
        def _generate(self, messages, stop=None, run_manager=None, **kwargs):
            if kwargs.get("response_format") is not None:
                self.wire_options.append(dict(kwargs))
                raise BadRequestError("Error code: 400 - {'error': {'message': 'The model rejected the request parameters.'}}")
            return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

    case = _case(tmp_path)
    monkeypatch.setattr(es_native, "_field_types", lambda _: TYPES)
    calls: list = []
    _fake_backbone(monkeypatch, calls)
    model = GrammarRejectingModel(script=[AIMessage(content='{"tool_calls": [], "answer": "fallback ok"}')])
    result = context_loop.run_context_loop(
        case_dir=case,
        case_id=case.name,
        question="fallback control",
        model=model,
        audit=AuditWriter("nexus", audit_dir=case / "audit"),
        budget=context_loop.LoopBudget(rounds=2, calls=3, seconds=60),
    )
    assert result["finish_reason"] == "answer"
    assert result["reply"].startswith("fallback ok")
    # Call 1 had response_format; call 2 dropped response_format
    assert model.wire_options[0].get("response_format") is not None
    assert model.wire_options[1].get("response_format") is None


# ---------------------------------------------------------------------------
# P1-CI / AUD-CI: match_all / match_none collapsed condition (SIM102)
# ---------------------------------------------------------------------------


def test_p1_ci_es_native_match_all_and_match_none_validation():
    es_native.validate_query({"match_all": {}})
    es_native.validate_query({"match_none": {}})
    with pytest.raises(es_native.ESQueryError):
        es_native.validate_query({"match_all": {"boost": 1}})
    with pytest.raises(es_native.ESQueryError):
        es_native.validate_query({"match_none": "bad"})


# ---------------------------------------------------------------------------
# P1-1 / AUD-05: Unified atomic seal/commit lockout
# ---------------------------------------------------------------------------


def test_p1_1_seal_accounts_failures_and_shares_lockout_with_cli(tmp_path: Path, monkeypatch):
    from nexus import auth
    from nexus.case.approval_service import ApprovalLockedError, require_examiner
    from nexus.dashboard.app import create_dashboard

    monkeypatch.setenv("NEXUS_EXAMINER", "alice")
    auth.setup_password("alice", "valid-password-123")

    cases_root = tmp_path / "cases"
    case_dir = cases_root / "CASE-SEAL-1"
    (case_dir / "evidence").mkdir(parents=True)
    (case_dir / "evidence.json").write_text("[]", encoding="utf-8")
    (case_dir / "findings.json").write_text("[]", encoding="utf-8")
    (case_dir / "timeline.json").write_text("[]", encoding="utf-8")
    (case_dir / "iocs.json").write_text("[]", encoding="utf-8")
    (case_dir / "CASE.yaml").write_text("case_id: CASE-SEAL-1\nstatus: active\n", encoding="utf-8")

    app = Starlette(routes=create_dashboard())
    with (
        patch("nexus.dashboard.app._get_case_dir", return_value=case_dir),
        patch("nexus.dashboard.app._lane_gate_error", return_value=None),
    ):
        client = TestClient(app)

        # Spoofed body examiner cannot pick another bucket or impersonate
        ch0 = client.get("/portal/api/commit/challenge").json()
        spoof = client.post(
            "/portal/api/case/seal",
            json={"challenge_id": ch0["challenge_id"], "response": "deadbeef", "examiner": "other-bucket"},
        )
        assert spoof.status_code == 401

        # 3 bad HMAC attempts on /portal/api/case/seal lock out the examiner across both surfaces
        for idx in range(3):
            ch = client.get("/portal/api/commit/challenge")
            assert ch.status_code == 200
            bad = client.post(
                "/portal/api/case/seal",
                json={"challenge_id": ch.json()["challenge_id"], "response": f"bad{idx}"},
            )
            assert bad.status_code == 401

        locked_seal = client.post(
            "/portal/api/case/seal",
            json={"challenge_id": "any", "response": "any"},
        )
        assert locked_seal.status_code == 429
        assert client.get("/portal/api/commit/challenge").status_code == 429

        # CLI/service lockout sees the exact same shared lockout state
        with pytest.raises(ApprovalLockedError):
            require_examiner("alice", "valid-password-123")

        # After clearing lockout, valid challenge clears failure counter cleanly
        auth.clear_lockout("alice")
        ch_ok = client.get("/portal/api/commit/challenge").json()
        pw_hash = hashlib.pbkdf2_hmac(
            "sha256",
            b"valid-password-123",
            ch_ok["salt"].encode("utf-8"),
            600_000,
        )
        proof = hmac.new(pw_hash, ch_ok["nonce"].encode("utf-8"), hashlib.sha256).hexdigest()
        with patch("nexus.case.seal.seal_case", return_value={"status": "sealed"}):
            ok_resp = client.post(
                "/portal/api/case/seal",
                json={"challenge_id": ch_ok["challenge_id"], "response": proof},
            )
        assert ok_resp.status_code == 200
        assert auth.failure_count("alice") == 0


# ---------------------------------------------------------------------------
# P1-2 / AUD-06: SummaryGenerator binds egress_case + router scrubs external LLM
# ---------------------------------------------------------------------------


def test_p1_2_summary_and_router_anonymize_external_egress(tmp_path: Path, monkeypatch):
    from nexus.analysis.summary import SummaryGenerator
    from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity
    from nexus.llm.router import LLMRouter

    monkeypatch.setenv("NEXUS_LLM_EGRESS", "")
    case_dir = tmp_path / "cases" / "CASE-SUM-01"
    (case_dir / "analysis").mkdir(parents=True)

    seen_prompts: list[str] = []

    class FakeProvider:
        name = "fake-remote"
        base_url = "https://models.jarvislabs.net/v1"
        default_model = "glm-5.3-flash"

        async def chat(self, messages, **_kwargs):
            seen_prompts.extend(str(m.get("content") or "") for m in messages)
            # Echo back tokenized text so we can verify restore_text too
            payload = {
                "overview": f"Summary saw {seen_prompts[-1][:80]}",
                "key_findings": ["Check host"],
                "recommended_actions": ["Isolate"],
            }
            return {
                "choices": [{"message": {"content": json.dumps(payload), "tool_calls": []}, "finish_reason": "stop"}],
                "model": "glm-5.3-flash",
            }

    router = LLMRouter(default_provider="openai", openai_api_key="test")
    router._providers["openai"] = FakeProvider()  # type: ignore[assignment]

    art = Artifact(
        id="art-1",
        artifact_type=ArtifactType.AUTH,
        source=ArtifactSource.EVTX,
        timestamp=datetime(2026, 11, 1, 12, 0, tzinfo=UTC),
        host="victim-dc01.corp.local",
        user="victim_admin",
        source_ip="10.42.99.15",
        description="Logon from 10.42.99.15 on victim-dc01.corp.local",
        severity=Severity.HIGH,
        technique_ids=["T1078"],
    )
    gen = SummaryGenerator(llm_router=router)
    summary = gen.generate([art], case_id="CASE-SUM-01", case_dir=case_dir)
    assert summary.llm_generated is True
    combined_sent = "\n".join(seen_prompts)
    assert "10.42.99.15" not in combined_sent
    assert (case_dir / "analysis" / "egress_tokens.json").is_file()


# ---------------------------------------------------------------------------
# P1-6 / AUD-10: Strict SSH host-key checking & WinRM HTTPS support
# ---------------------------------------------------------------------------


def test_p1_6_ssh_strict_host_keys_and_winrm_https(tmp_path: Path, monkeypatch):
    from nexus.collect.transport import SshTransport, WinRmTransport
    from nexus.collect.types import AuthSpec, HostSpec

    monkeypatch.delenv("NEXUS_SSH_ACCEPT_NEW", raising=False)
    key = tmp_path / "id_ed25519"
    key.write_text("dummy", encoding="utf-8")
    known = tmp_path / "known_hosts"
    known.write_text("10.0.0.5 ssh-ed25519 AAAA\n", encoding="utf-8")
    monkeypatch.setenv("NEXUS_SSH_KNOWN_HOSTS", str(known))

    spec = HostSpec(
        os="linux",
        address="10.0.0.5",
        transport="ssh",
        auth=AuthSpec(user="analyst", identity=str(key)),
    )
    ssh = SshTransport(spec)
    argv_joined = " ".join(ssh._base_ssh())
    scp_joined = " ".join(ssh._scp_argv())
    assert "StrictHostKeyChecking=yes" in argv_joined
    assert "StrictHostKeyChecking=yes" in scp_joined
    assert "accept-new" not in argv_joined
    assert f"UserKnownHostsFile={known}" in argv_joined

    # Paramiko uses RejectPolicy unless explicitly opted in
    monkeypatch.setenv("NEXUS_COLLECT_PASSWORD", "pw")
    fake_client = MagicMock()
    reject_sentinel = object()
    auto_sentinel = object()
    fake_paramiko = SimpleNamespace(
        SSHClient=MagicMock(return_value=fake_client),
        RejectPolicy=MagicMock(return_value=reject_sentinel),
        AutoAddPolicy=MagicMock(return_value=auto_sentinel),
    )
    with patch.dict(sys.modules, {"paramiko": fake_paramiko}):
        SshTransport(spec)._paramiko_connect(10)
    fake_client.set_missing_host_key_policy.assert_called_once_with(reject_sentinel)

    # WinRM HTTPS over 5986 validates certificates
    win_spec = HostSpec(
        os="windows",
        address="10.0.0.8",
        transport="winrm",
        auth=AuthSpec(user="Administrator", port=5986),
    )
    fake_sess = MagicMock()
    fake_sess.run_ps.return_value = SimpleNamespace(status_code=0, std_out=b"ok", std_err=b"")
    fake_winrm = SimpleNamespace(Session=MagicMock(return_value=fake_sess))
    with patch.dict(sys.modules, {"winrm": fake_winrm}):
        res = WinRmTransport(win_spec)._pywinrm_run("hostname", 10)
    assert res.ok is True
    fake_sess.run_ps.assert_called_once_with("hostname")
    call_args, call_kwargs = fake_winrm.Session.call_args
    assert call_args[0] == "https://10.0.0.8:5986/wsman"
    assert call_kwargs["server_cert_validation"] == "validate"


# ---------------------------------------------------------------------------
# P1-7 / AUD-11: Fail-closed checksums & tag honoring
# ---------------------------------------------------------------------------


def test_p1_7_rag_and_triage_checksums_fail_closed_and_honor_tag(tmp_path: Path):
    from nexus.tools.rag import _verify_checksums as verify_rag_checksums
    from nexus.triage import download as triage_dl

    # 1. Missing checksum file fails closed
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    assert verify_rag_checksums(empty_dir) is False
    assert triage_dl._verify_checksums(empty_dir) is False

    # 2. Missing target asset or path traversal in checksum manifest fails closed
    bad_dir = tmp_path / "bad"
    bad_dir.mkdir()
    (bad_dir / "rag-checksums.sha256").write_text("deadbeef  ../evil.tar.zst\n", encoding="utf-8")
    assert verify_rag_checksums(bad_dir) is False

    (bad_dir / "checksums.sha256").write_text("deadbeef  known_good.db.zst\n", encoding="utf-8")
    assert triage_dl._verify_checksums(bad_dir) is False

    # 3. Valid checksums covering required assets pass
    good_dir = tmp_path / "good"
    good_dir.mkdir()
    rag_bytes = b"rag-bundle"
    (good_dir / "rag-index.tar.zst").write_bytes(rag_bytes)
    (good_dir / "rag-checksums.sha256").write_text(
        f"{hashlib.sha256(rag_bytes).hexdigest()}  rag-index.tar.zst\n",
        encoding="utf-8",
    )
    assert verify_rag_checksums(good_dir) is True

    # 4. download_databases honors explicit tag instead of silently picking release[0]
    requested_urls: list[str] = []

    class _FakeResp:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def read(self) -> bytes:
            return self._data

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    def _fake_urlopen(req, timeout=30):
        requested_urls.append(req.full_url)
        return _FakeResp(json.dumps({"tag_name": "triage-db-pinned", "assets": []}).encode())

    with patch("urllib.request.urlopen", side_effect=_fake_urlopen):
        ok = triage_dl.download_databases(tmp_path / "db", tag="triage-db-pinned")
    assert ok is False  # no assets, but proves pinned tag endpoint was queried
    assert requested_urls[0].endswith("/releases/tags/triage-db-pinned")


# ---------------------------------------------------------------------------
# P1-12 / AUD-16: Backup restore fails closed & reconciles canonical DB
# ---------------------------------------------------------------------------


def test_p1_12_restore_fails_closed_on_db_error_and_reconciles_sqlite(tmp_path: Path, monkeypatch):
    from nexus.case.compat import get_sqlite_manager
    from nexus.cli.backup import app as backup_app

    archive = tmp_path / "case.zip"
    case_id = "CASE-RESTORE-SQL"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("_backup_manifest.json", json.dumps({"case_id": case_id}))
        zf.writestr(
            "_file_manifest.json",
            json.dumps({
                "CASE.yaml": hashlib.sha256(b"case_id: CASE-RESTORE-SQL\nname: Restored\nstatus: open\n").hexdigest(),
                "findings.json": hashlib.sha256(b'[{"id":"F-001","title":"Test finding","severity":"high","status":"DRAFT"}]').hexdigest(),
            }),
        )
        zf.writestr("CASE.yaml", b"case_id: CASE-RESTORE-SQL\nname: Restored\nstatus: open\n")
        zf.writestr("findings.json", b'[{"id":"F-001","title":"Test finding","severity":"high","status":"DRAFT"}]')

    runner = CliRunner()
    cases_root = tmp_path / "restored_cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    active_file = tmp_path / "active_case"
    active_file.write_text("CASE-ORIGINAL", encoding="utf-8")
    monkeypatch.setenv("NEXUS_ACTIVE_CASE_FILE", str(active_file))

    # 1. If canonical DB reconciliation fails, restore aborts non-zero and leaves active case untouched
    with patch("nexus.case.compat.LegacyJsonImporter.import_case", side_effect=RuntimeError("db locked")):
        fail_res = runner.invoke(
            backup_app,
            ["restore", str(archive), "--cases-root", str(cases_root), "--force"],
        )
    assert fail_res.exit_code != 0
    assert active_file.read_text(encoding="utf-8") == "CASE-ORIGINAL"

    # 2. Successful restore reconciles canonical SQLite tables in cases_root/cases.db
    ok_res = runner.invoke(
        backup_app,
        ["restore", str(archive), "--cases-root", str(cases_root), "--force"],
    )
    assert ok_res.exit_code == 0, ok_res.output
    sql_mgr = get_sqlite_manager(cases_root / "cases.db")
    try:
        assert sql_mgr.get_case(case_id) is not None
        assert len(sql_mgr.list_findings(case_id)) == 1
    finally:
        with contextlib.suppress(Exception):
            sql_mgr.close()
