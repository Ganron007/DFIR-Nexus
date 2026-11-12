"""Unit tests for WP 10.36 report hardening (secret redaction, exposure brief, vector PDF)."""

from __future__ import annotations

from pathlib import Path

import pytest

from nexus.integration.report_hardening import (
    RedactionError,
    export_report_pdf,
    exposure_brief,
    find_pdf_engine,
    redact_report_secrets,
)


def test_redact_aws_and_private_keys():
    text = (
        "# Incident Report\n"
        "Compromised AWS key: AKIAIOSFODNN7EXAMPLE was used.\n"
        "Secret key was aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'.\n"
        "Exfiltrated certificate:\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y123456789abcdef...\n"
        "-----END RSA PRIVATE KEY-----\n"
    )

    redacted, records = redact_report_secrets(text)

    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED_AWS_ACCESS_KEY]" in redacted
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in redacted
    assert "[REDACTED_AWS_SECRET_KEY]" in redacted
    assert "MIIEowIBAAKCAQEA0Y123456789abcdef" not in redacted
    assert "[REDACTED_PRIVATE_KEY]" in redacted

    categories = [r["category"] for r in records]
    assert "AWS_ACCESS_KEY" in categories
    assert "AWS_SECRET_KEY" in categories
    assert "PRIVATE_KEY" in categories


def test_redact_passwords_tokens_and_hashes():
    text = (
        "Attacker ran: psexec.exe -u admin -p SecretPassword123 cmd.exe\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.tokenpayload123456789\n"
        "DB connection: postgresql://dbuser:P@ssw0rd!@10.0.0.5:5432/core\n"
        "Found hash: $6$rounds=5000$saltsalt$5B8vGUYMhttLEmg3UrYouhandlehashes...\n"
        "Found NTLM: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n"
    )

    redacted, records = redact_report_secrets(text)

    assert "SecretPassword123" not in redacted
    assert "[REDACTED_PASSWORD]" in redacted
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.tokenpayload123456789" not in redacted
    assert "[REDACTED_BEARER_TOKEN]" in redacted
    assert "P@ssw0rd!" not in redacted
    assert "$6$rounds=5000$saltsalt$5B8vGUYMhttLEmg3UrYouhandlehashes..." not in redacted
    assert "[REDACTED_PASSWORD_HASH]" in redacted
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in redacted
    assert "[REDACTED_NTLM_HASH]" in redacted

    assert len(records) >= 5


def test_exposure_brief_content():
    sample_records = [
        {"category": "AWS_ACCESS_KEY", "line_no": 12, "mask": "[REDACTED_AWS_ACCESS_KEY]"},
        {"category": "PRIVATE_KEY", "line_no": 45, "mask": "[REDACTED_PRIVATE_KEY]"},
    ]

    brief = exposure_brief(sample_records)
    assert "## Sensitive Data Exposure Brief (Redacted)" in brief
    assert "`AWS_ACCESS_KEY`" in brief
    assert "`PRIVATE_KEY`" in brief
    assert "Rotate private keys immediately" in brief


def test_redaction_fail_closed_on_invalid_input():
    with pytest.raises(RedactionError):
        redact_report_secrets(None)  # type: ignore[arg-type]


def test_find_pdf_engine():
    engine = find_pdf_engine()
    # On Windows test host, Edge should be found
    assert engine is not None
    assert Path(engine).is_file()


def test_export_report_pdf_generation(tmp_path: Path):
    markdown_content = (
        "# Executive Incident Report\n\n"
        "## Summary\n"
        "Investigation of compromised endpoint identified persistence mechanisms.\n\n"
        "## Findings\n"
        "| ID | Severity | Title |\n"
        "|---|---|---|\n"
        "| F-01 | CRITICAL | Malicious Service Installed |\n"
        "| F-02 | HIGH | Scheduled Task Persistence |\n\n"
        "> Observed command: `schtasks /create /sc daily /tn Updater /tr C:\\evil.exe`\n"
    )

    pdf_out = tmp_path / "test_report.pdf"
    result_path = export_report_pdf(markdown_content, pdf_out, title="CASE-TEST-123 Report")

    assert result_path == pdf_out
    assert pdf_out.is_file()
    assert pdf_out.stat().st_size > 1000

    # Validate PDF signature
    with open(pdf_out, "rb") as f:
        header = f.read(5)
        assert header.startswith(b"%PDF-")


def test_export_report_pdf_with_redaction(tmp_path: Path):
    markdown_content = (
        "# Report with Secret\n\n"
        "Exfiltrated API key: api_key=secret_token_123456789abcdef\n"
    )

    pdf_out = tmp_path / "test_redacted.pdf"
    result_path = export_report_pdf(markdown_content, pdf_out, title="Redacted Case Report", redact=True)

    assert result_path.is_file()
    assert result_path.stat().st_size > 1000


def test_cli_report_generate_pdf_and_redact(tmp_path: Path):
    import json

    from typer.testing import CliRunner

    from nexus.cli.report import app

    case_dir = tmp_path / "CASE-CLI-REPORT"
    case_dir.mkdir(parents=True)
    findings = [{
        "id": "F-01",
        "title": "Compromised Access Key",
        "status": "APPROVED",
        "severity": "critical",
        "description": "Found key AKIAIOSFODNN7EXAMPLE used with password -p Secret123",
        "created_at": "2026-11-12T00:00:00Z",
        "created_by": "examiner",
    }]
    (case_dir / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    (case_dir / "case.json").write_text(json.dumps({"id": "CASE-CLI-REPORT", "name": "CLI Test Case"}), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(app, ["--case", str(case_dir), "--pdf", "--redact"])
    assert result.exit_code == 0
    assert "Redacted" in result.stdout
    assert "Exported PDF" in result.stdout
    pdf_file = case_dir / "reports" / "REPORT.pdf"
    assert pdf_file.is_file()
    assert pdf_file.stat().st_size > 0

