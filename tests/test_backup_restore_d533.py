"""Tests for backup/restore correctness and validation hardening (D533 / TC-4)."""

import hashlib
import json
import zipfile
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from nexus.cli.backup import _verify_backup, app


def test_backup_restore_roundtrip_configured_root(tmp_path: Path):
    """Test full backup and restore cycle respecting configured cases_root and ledger."""
    cases_root = tmp_path / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    case_dir = cases_root / "CASE-RESTORE-TEST"
    case_dir.mkdir()
    (case_dir / "findings.json").write_text('[{"id":"F1","title":"Suspicious execution"}]', encoding="utf-8")
    (case_dir / "timeline.json").write_text('[{"event_id":1}]', encoding="utf-8")
    (case_dir / "reports").mkdir()
    (case_dir / "reports" / "REPORT.md").write_text("# Test Report", encoding="utf-8")

    test_vdir = tmp_path / "verification"
    test_vdir.mkdir(parents=True, exist_ok=True)
    ledger_file = test_vdir / "CASE-RESTORE-TEST.jsonl"
    ledger_file.write_text('{"finding_id":"F1","hmac":"dummyhmac"}\n', encoding="utf-8")

    backup_zip = tmp_path / "case_backup.zip"
    runner = CliRunner()

    with patch("nexus.auth.VERIFICATION_DIR", test_vdir), \
         patch("nexus.cli.backup._resolve_case_dir", return_value=case_dir):
        res = runner.invoke(app, ["create", str(backup_zip)])
        assert res.exit_code == 0, res.output

    assert backup_zip.is_file()
    ok, msg = _verify_backup(backup_zip)
    assert ok, msg

    # Now restore into a fresh location
    new_cases_root = tmp_path / "restored_cases"
    new_cases_root.mkdir()

    with patch("nexus.auth.VERIFICATION_DIR", test_vdir):
        res_restore = runner.invoke(app, ["restore", str(backup_zip), "--cases-root", str(new_cases_root), "--no-activate"])
        assert res_restore.exit_code == 0, res_restore.output

    restored_case = new_cases_root / "CASE-RESTORE-TEST"
    assert restored_case.is_dir()
    assert (restored_case / "findings.json").read_text(encoding="utf-8") == '[{"id":"F1","title":"Suspicious execution"}]'
    assert (restored_case / "reports" / "REPORT.md").read_text(encoding="utf-8") == "# Test Report"


def test_restore_rejects_path_traversal(tmp_path: Path):
    """Restore must detect and reject zip archives attempting path traversal."""
    malicious_zip = tmp_path / "malicious.zip"
    manifest = {
        "case_id": "CASE-TRAVERSAL",
        "created_at": "2026-01-01T00:00:00Z",
    }
    with zipfile.ZipFile(malicious_zip, "w") as zf:
        zf.writestr("_backup_manifest.json", json.dumps(manifest))
        zf.writestr("_file_manifest.json", json.dumps({"../evil.txt": "dummy"}))
        zf.writestr("../evil.txt", "pwned")

    dest_root = tmp_path / "cases_safe"
    runner = CliRunner()
    res = runner.invoke(app, ["restore", str(malicious_zip), "--cases-root", str(dest_root), "--force"])
    assert res.exit_code != 0
    assert "Path traversal detected" in res.output or "Path escape detected" in res.output
    assert not (tmp_path / "evil.txt").exists()


def test_restore_rejects_tampered_archive_without_force(tmp_path: Path):
    """Restore must verify manifest hashes and reject tampered files unless --force is given."""
    tampered_zip = tmp_path / "tampered.zip"
    manifest = {
        "case_id": "CASE-TAMPERED",
        "created_at": "2026-01-01T00:00:00Z",
    }
    file_manifest = {
        "findings.json": hashlib.sha256(b"original").hexdigest(),
    }
    with zipfile.ZipFile(tampered_zip, "w") as zf:
        zf.writestr("_backup_manifest.json", json.dumps(manifest))
        zf.writestr("_file_manifest.json", json.dumps(file_manifest))
        zf.writestr("findings.json", "altered content")

    dest_root = tmp_path / "tampered_target"
    runner = CliRunner()
    res = runner.invoke(app, ["restore", str(tampered_zip), "--cases-root", str(dest_root)])
    assert res.exit_code != 0
    assert "Refusing restore: backup integrity verification failed" in res.output

    # With --force, it should proceed
    res_forced = runner.invoke(app, ["restore", str(tampered_zip), "--cases-root", str(dest_root), "--force", "--no-activate"])
    assert res_forced.exit_code == 0, res_forced.output
    assert (dest_root / "CASE-TAMPERED" / "findings.json").is_file()
