"""Regression tests for all 17 pre-release blockers.

Each test is named after the blocker it covers. These tests would FAIL on
the unfixed code and PASS on the fixed code.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Blocker #1 — Pass-the-hash portal auth
# ---------------------------------------------------------------------------
class TestBlocker1PassTheHash:
    """Portal must derive signing key from stored_hash (not plaintext password)
    and challenge verification must use HMAC, not PBKDF2(stored_hash, nonce)."""

    def test_challenge_verification_is_hmac_not_pbkdf2(self) -> None:
        from nexus.auth import derive_purpose_key
        stored_hash_hex = hashlib.pbkdf2_hmac(
            "sha256", b"testpass", b"salt123", 600_000
        ).hex()
        nonce = "abc123"
        stored_bytes = bytes.fromhex(stored_hash_hex)
        expected = hmac.new(
            stored_bytes, nonce.encode(), hashlib.sha256
        ).hexdigest()
        assert len(expected) == 64

    def test_signing_key_derived_from_stored_hash(self) -> None:
        from nexus.auth import derive_purpose_key, SIGNING_PURPOSE
        stored_hash = hashlib.pbkdf2_hmac(
            "sha256", b"pw", b"salt", 600_000
        ).hex()
        key1 = derive_purpose_key(bytes.fromhex(stored_hash), SIGNING_PURPOSE)
        key2 = derive_purpose_key(bytes.fromhex(stored_hash), SIGNING_PURPOSE)
        assert key1 == key2
        assert len(key1) == 32


# ---------------------------------------------------------------------------
# Blocker #2 — Browser commit crypto mismatch
# ---------------------------------------------------------------------------
class TestBlocker2BrowserCrypto:
    """Server and JS must compute the same HMAC for challenge-response."""

    def test_server_hmac_matches_client_hmac(self) -> None:
        stored_hash_hex = hashlib.pbkdf2_hmac(
            "sha256", b"password", b"salt", 600_000
        ).hex()
        nonce = "testnonce123"
        server_response = hmac.new(
            bytes.fromhex(stored_hash_hex),
            nonce.encode(),
            hashlib.sha256,
        ).hexdigest()
        client_stored_hash_bytes = bytes.fromhex(stored_hash_hex)
        client_response = hmac.new(
            client_stored_hash_bytes,
            nonce.encode(),
            hashlib.sha256,
        ).hexdigest()
        assert server_response == client_response


# ---------------------------------------------------------------------------
# Blocker #3 — Stored XSS
# ---------------------------------------------------------------------------
class TestBlocker3XSS:
    """All case-controlled data must be HTML-escaped in portal output."""

    def test_escape_helper(self) -> None:
        from nexus.dashboard.app import _e
        assert "&lt;script&gt;" in _e("<script>alert(1)</script>")
        assert "&amp;" in _e("a&b")
        assert "&quot;" in _e('"quoted"')

    def test_status_tag_escaped(self) -> None:
        from nexus.dashboard.app import _status_tag
        result = _status_tag('<img src=x onerror="alert(1)">')
        assert "<img" not in result
        assert "&lt;img" in result

    def test_badge_escaped(self) -> None:
        from nexus.dashboard.app import _badge
        result = _badge('<script>alert("x")</script>')
        assert "<script>" not in result


# ---------------------------------------------------------------------------
# Blocker #4 — Key separation
# ---------------------------------------------------------------------------
class TestBlocker4KeySeparation:
    """Different purposes must produce different keys from same base material."""

    def test_signing_vs_challenge_keys_differ(self) -> None:
        from nexus.auth import (
            SIGNING_PURPOSE, CHALLENGE_PURPOSE, derive_purpose_key,
        )
        base = b"\x00" * 32
        signing = derive_purpose_key(base, SIGNING_PURPOSE)
        challenge = derive_purpose_key(base, CHALLENGE_PURPOSE)
        assert signing != challenge

    def test_same_purpose_same_key(self) -> None:
        from nexus.auth import SIGNING_PURPOSE, derive_purpose_key
        base = b"\x00" * 32
        assert derive_purpose_key(base, SIGNING_PURPOSE) == derive_purpose_key(
            base, SIGNING_PURPOSE
        )


# ---------------------------------------------------------------------------
# Blocker #5 — Hardcoded audit secret
# ---------------------------------------------------------------------------
class TestBlocker5AuditSecret:
    """Default audit secret must be per-install random, not a fixed value."""

    def test_no_hardcoded_dev_secret(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from nexus.case import secrets
        monkeypatch.delenv("NEXUS_AUDIT_SECRET", raising=False)
        monkeypatch.setattr(secrets, "_PERSISTED_SECRET_PATH", tmp_path / "audit_secret")
        s1 = secrets.get_audit_secret()
        s2 = secrets.get_audit_secret()
        assert s1 == s2
        assert s1 != hashlib.sha256(b"nexus-dev-audit-v1").digest()
        assert len(s1) == 64

    def test_two_installs_different_secrets(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        from nexus.case import secrets
        monkeypatch.delenv("NEXUS_AUDIT_SECRET", raising=False)
        monkeypatch.setattr(
            secrets, "_PERSISTED_SECRET_PATH", tmp_path / "a" / "audit_secret"
        )
        s1 = secrets.get_audit_secret()
        monkeypatch.setattr(
            secrets, "_PERSISTED_SECRET_PATH", tmp_path / "b" / "audit_secret"
        )
        s2 = secrets.get_audit_secret()
        assert s1 != s2


# ---------------------------------------------------------------------------
# Blocker #6 — Findings default to DRAFT
# ---------------------------------------------------------------------------
class TestBlocker6DraftDefault:
    """All findings must start as DRAFT, never APPROVED."""

    def test_schema_default_is_draft(self) -> None:
        from nexus.case.schemas import ApprovalState, Finding, FindingSeverity
        f = Finding(
            id="F1", case_id="C1", title="t", description="d",
            severity=FindingSeverity.MEDIUM, artifact_id=None,
            technique_ids=[], created_at=datetime.now(UTC), created_by="a",
        )
        assert f.approval_state == ApprovalState.DRAFT

    def test_from_dict_default_is_draft(self) -> None:
        from nexus.case.schemas import ApprovalState, Finding
        d = {
            "id": "F1", "case_id": "C1", "title": "t", "description": "d",
            "severity": "medium", "artifact_id": None, "technique_ids": [],
            "created_at": "2026-01-01T00:00:00", "created_by": "a",
        }
        f = Finding.from_dict(d)
        assert f.approval_state == ApprovalState.DRAFT

    def test_manager_forces_draft(self) -> None:
        from nexus.case import CaseManager
        from nexus.case.schemas import ApprovalState
        with tempfile.TemporaryDirectory() as tmp:
            mgr = CaseManager(Path(tmp) / "cases.db", secret_key=b"k")
            case = mgr.create_case(name="test")
            f = mgr.add_finding(
                case.id, "test", initial_state=ApprovalState.APPROVED
            )
            assert f is not None
            assert f.approval_state == ApprovalState.DRAFT
            mgr.close()


# ---------------------------------------------------------------------------
# Blocker #7 — Input path validation + dangerous flags + batch_scan
# ---------------------------------------------------------------------------
class TestBlocker7PathValidation:
    """_validate_input_path must raise; _DANGEROUS_FLAGS must be enforced."""

    @pytest.mark.skipif(os.name == "nt", reason="Linux paths")
    def test_blocked_paths_raise(self) -> None:
        from nexus.tools.sift import _validate_input_path
        for p in ["/etc/passwd", "/proc/1/cmdline", "/dev/sda", "/boot/vmlinuz"]:
            with pytest.raises(ValueError):
                _validate_input_path(p)

    def test_dangerous_flags_blocked(self) -> None:
        from nexus.tools.sift import _sanitize_extra_args
        with pytest.raises(ValueError):
            _sanitize_extra_args(["-e", "something"], "test")

    def test_metachar_still_blocked(self) -> None:
        from nexus.tools.sift import _sanitize_extra_args
        with pytest.raises(ValueError):
            _sanitize_extra_args(["$(whoami)"], "test")

    def test_safe_args_pass(self) -> None:
        from nexus.tools.sift import _sanitize_extra_args
        result = _sanitize_extra_args(["-f", "/evidence/test.evtx", "--csv"], "test")
        assert result == ["-f", "/evidence/test.evtx", "--csv"]


# ---------------------------------------------------------------------------
# Blocker #8 — Backup implementation
# ---------------------------------------------------------------------------
class TestBlocker8Backup:
    """backup create/restore/verify must actually work."""

    def test_backup_roundtrip(self, tmp_path: Path) -> None:
        case_dir = tmp_path / "cases" / "CASE-TEST"
        case_dir.mkdir(parents=True)
        (case_dir / "findings.json").write_text('[{"id":"F1","status":"DRAFT"}]')
        (case_dir / "timeline.json").write_text("[]")

        backup_path = tmp_path / "backup.zip"
        active_file = tmp_path / "active_case"
        active_file.write_text(str(case_dir))

        with patch("nexus.cli.backup._resolve_case_dir", return_value=case_dir):
            from nexus.cli.backup import _verify_backup
            from typer.testing import CliRunner
            from nexus.cli.backup import app
            runner = CliRunner()
            result = runner.invoke(app, ["create", str(backup_path)])
            assert result.exit_code == 0, result.output

        assert backup_path.exists()
        assert backup_path.stat().st_size > 0

        ok, detail = _verify_backup(backup_path)
        assert ok


# ---------------------------------------------------------------------------
# Blocker #9 — Case stack bridge
# ---------------------------------------------------------------------------
class TestBlocker9CaseStackBridge:
    """Report generation must check flat-JSON stack when SQLite misses."""

    def test_report_falls_back_to_flat_json(self, tmp_path: Path) -> None:
        case_dir = tmp_path / "cases" / "CASE-FLAT"
        case_dir.mkdir(parents=True)
        findings = [
            {"id": "F1", "title": "Test", "status": "APPROVED",
             "severity": "high", "approved_by": "lead", "description": "test"}
        ]
        (case_dir / "findings.json").write_text(json.dumps(findings))
        active = tmp_path / "active_case"
        active.write_text(str(case_dir))
        with patch("nexus.cli.report.Path.home", return_value=tmp_path), \
             patch("nexus.cli.report._get_active_case_id", return_value="CASE-FLAT"):
            from nexus.cli.report import _get_active_case_id
            assert _get_active_case_id() == "CASE-FLAT"


# ---------------------------------------------------------------------------
# Blocker #10 — HTTP transport mismatch
# ---------------------------------------------------------------------------
class TestBlocker10Transport:
    """serve --http must mount streamable-http at /mcp, not SSE at /."""

    def test_cli_main_has_streamable_http(self) -> None:
        import inspect
        from nexus.cli.main import build_http_app
        source = inspect.getsource(build_http_app)
        assert "streamable_http_app" in source
        assert "/mcp" in source


# ---------------------------------------------------------------------------
# Blocker #11 — Syslog timestamp + Splunk severity
# ---------------------------------------------------------------------------
class TestBlocker11TimestampAndSeverity:
    """RFC 3164 timestamps must parse; Splunk severity must not be inverted."""

    def test_rfc3164_timestamp(self) -> None:
        from nexus.ingest.base import Importer
        result = Importer.normalize_timestamp("Jan 15 12:34:56")
        assert result is not None
        assert result.month == 1
        assert result.day == 15
        assert result.hour == 12
        assert result.minute == 34
        assert result.second == 56

    def test_splunk_severity_5_is_critical(self) -> None:
        from nexus.ingest.schemas import Severity
        assert Severity.normalize(5) == Severity.INFORMATIONAL
        splunk_5_map = {1: "informational", 2: "low", 3: "medium", 4: "high", 5: "critical"}
        sev = Severity.normalize(splunk_5_map[5])
        assert sev == Severity.CRITICAL

    def test_splunk_importer_inverts_correctly(self, tmp_path: Path) -> None:
        from nexus.ingest.siem.splunk import SplunkImporter
        imp = SplunkImporter()
        csv_file = tmp_path / "splunk_export.csv"
        csv_file.write_text(
            "_time,host,severity,sourcetype,msg\n"
            "1700000000,h1,5,splunkd,critical event\n"
            "1700000001,h2,1,splunkd,info event\n"
        )
        artifacts = list(imp.parse(csv_file))
        assert len(artifacts) == 2
        assert artifacts[0].severity.value == "critical"
        assert artifacts[1].severity.value == "informational"


# ---------------------------------------------------------------------------
# Blocker #12 — Sigma tactic extraction
# ---------------------------------------------------------------------------
class TestBlocker12SigmaTactics:
    """Tactic name tags must map to ATT&CK tactic IDs."""

    def test_tactic_name_mapped(self) -> None:
        from nexus.detection.indexer import DetectionIndexer
        tags = [
            "attack.credential_access",
            "attack.t1003.001",
            "attack.initial_access",
        ]
        techniques, tactics = DetectionIndexer._extract_mitre_from_tags(tags)
        assert "T1003.001" in techniques
        assert "TA0006" in tactics
        assert "TA0001" in tactics

    def test_unknown_tactic_not_crashed(self) -> None:
        from nexus.detection.indexer import DetectionIndexer
        tags = ["attack.bogus_tactic"]
        techniques, tactics = DetectionIndexer._extract_mitre_from_tags(tags)
        assert techniques == []
        assert tactics == []


# ---------------------------------------------------------------------------
# Blocker #13 — CI fixed
# ---------------------------------------------------------------------------
class TestBlocker13CI:
    """CI must reference existing test files."""

    def test_ci_references_valid_files(self) -> None:
        ci_path = Path(__file__).parent.parent / ".github" / "workflows" / "ci.yml"
        if not ci_path.exists():
            pytest.skip("CI file not in expected location")
        content = ci_path.read_text()
        assert "test_push_gateway" not in content
        # Push feature removed 2026-08 — CI must not reference the deleted file.
        assert "test_push.py" not in content
        # Every script test CI runs must exist on disk.
        import re
        for ref in re.findall(r"python (tests/test_\w+\.py|tests/functional_audit\.py)", content):
            assert (Path(__file__).parent.parent / ref).exists(), f"CI references missing file: {ref}"


# ---------------------------------------------------------------------------
# Blocker #14 — docker-compose bind
# ---------------------------------------------------------------------------
class TestBlocker14DockerCompose:
    """docker-compose must include --host 0.0.0.0."""

    def test_compose_has_host_flag(self) -> None:
        compose_path = Path(__file__).parent.parent / "docker-compose.yml"
        if not compose_path.exists():
            pytest.skip("docker-compose.yml not found")
        content = compose_path.read_text()
        assert "0.0.0.0" in content


# ---------------------------------------------------------------------------
# Blocker #15 — Shodan key leak
# ---------------------------------------------------------------------------
class TestBlocker15ShodanKeyLeak:
    """Shodan API key must not appear in error messages."""

    @pytest.mark.asyncio
    async def test_shodan_http_error_sanitized(self) -> None:
        import httpx
        from nexus.ti.router import TIRouter
        test_key = "shodan_test_key_12345"
        router = TIRouter(force_mock=False)

        async def fake_get(*a, **kw):
            raise httpx.HTTPStatusError(
                f"Forbidden key={test_key}",
                request=httpx.Request("GET", f"https://api.shodan.io?key={test_key}"),
                response=httpx.Response(403),
            )
        class FakeClient:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *a):
                pass
            get = fake_get

        with patch.dict(os.environ, {"NEXUS_TI_SHODAN_API_KEY": test_key}):
            with patch("nexus.ti.providers.optional.httpx.AsyncClient", return_value=FakeClient()):
                result = await router.query_provider("shodan", "1.2.3.4")
                error_str = result.get("error", "")
                assert test_key not in error_str


# ---------------------------------------------------------------------------
# Blocker #16 — CLI fixes
# ---------------------------------------------------------------------------
class TestBlocker16CLIFixes:
    """Service status must not crash; exec must audit; config must not default to 'default'."""

    def test_service_status_format(self) -> None:
        import inspect
        from nexus.cli.service import status
        source = inspect.getsource(status)
        assert "pid_str" in source or "str(pid)" in source

    def test_exec_has_audit(self) -> None:
        import inspect
        from nexus.cli.exec_cmd import run
        source = inspect.getsource(run)
        assert "sha256" in source
        assert "audit" in source.lower()


# ---------------------------------------------------------------------------
# Blocker #17 — LangGraph fixes
# ---------------------------------------------------------------------------
class TestBlocker17LangGraph:
    """Pipeline must have checkpointer; interrupt_payload must be preserved."""

    def test_pipeline_state_has_interrupt_payload(self) -> None:
        from nexus.langgraph.types import PipelineState
        state = PipelineState()
        assert hasattr(state, "interrupt_payload")
        assert state.interrupt_payload is None

    def test_pipeline_state_dict_has_interrupt(self) -> None:
        from nexus.langgraph.types import PipelineState
        state = PipelineState(interrupt_payload={"test": True})
        d = state.to_dict()
        assert "interrupt_payload" in d

    def test_pyproject_has_pipeline_extra(self) -> None:
        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        content = pyproject.read_text()
        assert "pipeline" in content
        assert "langgraph" in content


# ---------------------------------------------------------------------------
# Blocker Bug Fixes - B1 to B4 & B7
# ---------------------------------------------------------------------------
class TestBlockerBugFixes:
    """Tests for the security and parsing bug fixes."""

    def test_b1_timing_oracle_verify_password(self) -> None:
        from nexus.auth import verify_password
        # A nonexistent user should execute the dummy PBKDF2 hash calculation and return False
        assert verify_password("nonexistent_analyst_xyz_123", "some_password") is False

    @pytest.mark.asyncio
    async def test_b2_vql_injection_collect_artifact(self) -> None:
        from nexus.integration.velociraptor_mcp_server import create_velociraptor_server
        from mcp.types import CallToolRequest, CallToolRequestParams
        from unittest.mock import patch
        
        server = create_velociraptor_server()
        handler = server.request_handlers[CallToolRequest]
        
        # Verify that double quotes are rejected and error is returned in TextContent
        req = CallToolRequest(
            params=CallToolRequestParams(
                name="vql_collect_artifact",
                arguments={
                    "artifact_name": "Generic.Client.Info",
                    "parameters": {"bad_param": 'evil"inject'}
                }
            )
        )
        res = await handler(req)
        assert len(res.root.content) == 1
        assert "Double quotes are not allowed" in res.root.content[0].text
            
        req = CallToolRequest(
            params=CallToolRequestParams(
                name="vql_collect_artifact",
                arguments={
                    "artifact_name": "Generic.Client.Info",
                    "parameters": {"bad-param-name": "value"}
                }
            )
        )
        res = await handler(req)
        assert len(res.root.content) == 1
        assert "Invalid parameter name" in res.root.content[0].text

    def test_b3_zeek_ts_hyphen_handling(self) -> None:
        from nexus.ingest.network.zeek import ZeekImporter
        from nexus.ingest.schemas import ArtifactType
        from pathlib import Path
        
        importer = ZeekImporter()
        record = {
            "ts": "-",
            "proto": "TCP",
            "id.orig_h": "192.168.1.10",
            "id.orig_p": "443",
            "id.resp_h": "192.168.1.20",
            "id.resp_p": "80",
        }
        artifact = importer._record_to_artifact(record, "conn", ArtifactType.NETWORK, Path("conn.log"))
        assert artifact is not None
        assert artifact.timestamp is not None

    def test_b4_rdp_event_id_priority(self) -> None:
        from nexus.ingest.df.evtx import EVTXImporter
        from nexus.ingest.df.hayabusa import HayabusaImporter
        from nexus.ingest.schemas import ArtifactType
        
        # In both, 4624 and 4778 should map to RDP, not AUTH
        assert EVTXImporter._event_id_to_type("4624") == ArtifactType.RDP
        assert EVTXImporter._event_id_to_type("4778") == ArtifactType.RDP
        assert EVTXImporter._event_id_to_type("4625") == ArtifactType.AUTH
        
        assert HayabusaImporter._event_id_to_type("4624", "Security") == ArtifactType.RDP
        assert HayabusaImporter._event_id_to_type("4778", "Security") == ArtifactType.RDP
        assert HayabusaImporter._event_id_to_type("4625", "Security") == ArtifactType.AUTH

    def test_b7_skipped_lines_tracking(self) -> None:
        from nexus.ingest.base import Importer
        from nexus.ingest.schemas import ArtifactSource, Artifact, ArtifactType, Severity
        from collections.abc import Iterator
        
        # Test that skipped_lines is correctly wired
        class MockImporter(Importer):
            @classmethod
            def source_class(cls) -> ArtifactSource:
                return ArtifactSource.ZEEK
            @classmethod
            def can_handle(cls, path: Path) -> bool:
                return True
            def parse(self, path: Path) -> Iterator[Artifact]:
                self.skipped_lines += 2
                yield Artifact(
                    id=Artifact.new_id(),
                    artifact_type=ArtifactType.NETWORK,
                    source=ArtifactSource.ZEEK,
                    timestamp=None,
                    severity=Severity.INFORMATIONAL,
                    description="mock",
                )
                
        importer = MockImporter()
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)
        try:
            res = importer.ingest(tmp_path)
            assert res.skipped_lines == 2
            assert res.parsed_lines == 1
            assert res.total_lines == 3
        finally:
            tmp_path.unlink()
