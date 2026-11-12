"""WP 10.36 — Report hardening: secret redaction and vector PDF export.

Provides fail-closed secret redaction of report text and dedicated sensitive
data exposure briefs for credential/secret findings.
Renders printable, high-fidelity vector PDF reports via headless browser
(Microsoft Edge / Chromium).
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class RedactionError(Exception):
    """Raised when secret redaction fails or encounters an unrecoverable state."""


class PDFExportError(Exception):
    """Raised when PDF generation fails."""


# Secret detection patterns with category tags
_REDACTION_RULES: list[tuple[str, re.Pattern[str], str]] = [
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----",
            re.MULTILINE,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
        "[REDACTED_AWS_ACCESS_KEY]",
    ),
    (
        "AWS_SECRET_KEY",
        re.compile(
            r"(?i)\b(?:aws_secret_access_key|aws_secret_key|secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        "aws_secret_access_key=[REDACTED_AWS_SECRET_KEY]",
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9_\-\.]{20,})\b"),
        "Bearer [REDACTED_BEARER_TOKEN]",
    ),
    (
        "BASIC_AUTH",
        re.compile(r"(?i)\bBasic\s+([A-Za-z0-9+/=]{16,})\b"),
        "Basic [REDACTED_BASIC_AUTH]",
    ),
    (
        "URL_CREDENTIALS",
        re.compile(r"(?i)\b([a-zA-Z][a-zA-Z0-9+.-]*://[A-Za-z0-9_.-]+):([^/\s]+)@([A-Za-z0-9_.-]+)"),
        r"\1:[REDACTED_PASSWORD]@\3",
    ),
    (
        "CLI_PASSWORD",
        re.compile(r"(?i)(?<!\S)(?:-[pP]\s+|/[pP]:|--password\s+)(['\"]?[^\s\"';&|]{3,}['\"]?)"),
        "-p [REDACTED_PASSWORD]",
    ),
    (
        "CONFIG_PASSWORD",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s\"';&|]{4,})['\"]?"
        ),
        "password=[REDACTED_PASSWORD]",
    ),
    (
        "API_KEY",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,})['\"]?"
        ),
        "api_key=[REDACTED_API_KEY]",
    ),
    (
        "UNIX_SHADOW_HASH",
        re.compile(r"\$(?:1|2a|2b|5|6)\$(?:rounds=\d+\$)?[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{16,86}"),
        "[REDACTED_PASSWORD_HASH]",
    ),
    (
        "NTLM_HASH",
        re.compile(r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b"),
        "[REDACTED_NTLM_HASH]",
    ),
]


def redact_report_secrets(text: str) -> tuple[str, list[dict[str, Any]]]:
    """Redact sensitive credentials, keys, and tokens from report text.

    Enforces a strict fail-closed policy: raises RedactionError if redaction
    encounters malformed inputs or regex processing errors. Never returns
    partially redacted text on failure.

    Args:
        text: Raw report markdown or text content.

    Returns:
        A tuple of (redacted_text, redaction_records).
        Each record contains:
            - category: Type of secret detected.
            - line_no: Approximate line number.
            - mask: The replacement mask applied.
    """
    if not isinstance(text, str):
        raise RedactionError("Input text must be a string")

    if not text:
        return "", []

    redacted = text
    records: list[dict[str, Any]] = []

    try:
        for category, pattern, replacement in _REDACTION_RULES:
            matches = list(pattern.finditer(redacted))
            if not matches:
                continue

            for match in matches:
                # Calculate approximate line number from original text offset
                start_pos = match.start()
                line_no = redacted.count("\n", 0, start_pos) + 1
                records.append({
                    "category": category,
                    "line_no": line_no,
                    "mask": replacement if not replacement.startswith(r"\1") else "[REDACTED_CREDENTIAL]",
                })

            redacted = pattern.sub(replacement, redacted)

        # Fail-closed check: verify no unredacted private key headers remain
        if "-----BEGIN" in redacted and "PRIVATE KEY-----" in redacted:
            raise RedactionError("Private key fragment persisted after redaction pass")

    except RedactionError:
        raise
    except Exception as exc:
        log.error("Redaction error: %s", exc)
        raise RedactionError(f"Secret redaction failed: {exc}") from exc

    return redacted, records


def exposure_brief(redactions: list[dict[str, Any]]) -> str:
    """Generate a dedicated Sensitive Data Exposure Brief section.

    Summarizes redacted credentials and potential credential exposure findings
    without disclosing the actual sensitive material.
    """
    if not redactions:
        return (
            "## Sensitive Data Exposure Brief\n\n"
            "_No sensitive credentials, keys, or passwords were detected in report findings._\n"
        )

    counts: dict[str, int] = {}
    lines_by_cat: dict[str, list[int]] = {}
    for r in redactions:
        cat = r["category"]
        counts[cat] = counts.get(cat, 0) + 1
        lines_by_cat.setdefault(cat, []).append(r["line_no"])

    remediations: dict[str, str] = {
        "PRIVATE_KEY": "Rotate private keys immediately; revoke compromised certificates.",
        "AWS_ACCESS_KEY": "Deactivate compromised IAM access keys in AWS IAM console.",
        "AWS_SECRET_KEY": "Rotate associated AWS access keys and review CloudTrail logs.",
        "BEARER_TOKEN": "Revoke OAuth/session tokens and inspect active sessions.",
        "BASIC_AUTH": "Rotate credentials and enforce multi-factor authentication.",
        "URL_CREDENTIALS": "Change user passwords and review service access logs.",
        "CLI_PASSWORD": "Change local/domain user account passwords.",
        "CONFIG_PASSWORD": "Reset passwords and restrict access to configuration files.",
        "API_KEY": "Regenerate API keys and review API telemetry for misuse.",
        "UNIX_SHADOW_HASH": "Force password change for affected UNIX/Linux accounts.",
        "NTLM_HASH": "Reset account password; evaluate Pass-the-Hash exposure.",
    }

    lines = [
        "## Sensitive Data Exposure Brief (Redacted)",
        "",
        "> [!WARNING]",
        "> **Operational Security Notice:** The following sensitive credentials, keys, or hashes",
        "> were identified in investigation evidence/findings and automatically redacted.",
        "",
        "| Secret Category | Occurrences | Cited Lines | Recommended Remediation |",
        "|:---|:---:|:---|:---|",
    ]

    for cat in sorted(counts.keys()):
        count = counts[cat]
        line_refs = ", ".join(f"L{num}" for num in sorted(set(lines_by_cat[cat]))[:5])
        if len(set(lines_by_cat[cat])) > 5:
            line_refs += "..."
        rem = remediations.get(cat, "Rotate credentials and investigate potential compromise.")
        lines.append(f"| `{cat}` | {count} | {line_refs} | {rem} |")

    lines.append("")
    return "\n".join(lines)


def find_pdf_engine() -> str | None:
    """Find a local browser executable capable of headless vector PDF rendering.

    Checks Microsoft Edge (default on Windows), Google Chrome, and chromium on PATH.
    """
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]

    for c in candidates:
        if Path(c).is_file():
            return c

    for name in ("msedge", "msedge.exe", "chrome", "chrome.exe", "chromium", "chromium-browser"):
        found = shutil.which(name)
        if found and Path(found).is_file():
            return found

    return None


def _markdown_to_printable_html(report_markdown: str, title: str = "DFIR-Nexus Incident Report") -> str:
    """Convert report markdown to styled printable HTML."""
    try:
        import markdown
        html_body = markdown.markdown(
            report_markdown,
            extensions=["tables", "fenced_code", "nl2br"],
        )
    except Exception:
        # Fallback basic conversion if markdown module throws
        html_body = f"<pre>{report_markdown}</pre>"

    css = """
    @page {
        size: A4;
        margin: 20mm 15mm 20mm 15mm;
        @bottom-right {
            content: "Page " counter(page) " of " counter(pages);
            font-size: 8pt;
            color: #64748b;
        }
    }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        font-size: 10pt;
        line-height: 1.5;
        color: #1e293b;
        margin: 0;
        padding: 0;
    }
    h1 {
        font-size: 18pt;
        color: #0f172a;
        border-bottom: 2pt solid #2563eb;
        padding-bottom: 4pt;
        margin-top: 0;
        page-break-after: avoid;
    }
    h2 {
        font-size: 13pt;
        color: #1e40af;
        border-bottom: 1pt solid #cbd5e1;
        padding-bottom: 2pt;
        margin-top: 14pt;
        page-break-after: avoid;
    }
    h3 {
        font-size: 11pt;
        color: #334155;
        margin-top: 10pt;
        page-break-after: avoid;
    }
    p, li {
        font-size: 9.5pt;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 10pt 0;
        page-break-inside: avoid;
    }
    th, td {
        border: 0.5pt solid #cbd5e1;
        padding: 4pt 6pt;
        text-align: left;
        font-size: 8.5pt;
    }
    th {
        background-color: #f1f5f9;
        font-weight: 600;
        color: #0f172a;
    }
    code {
        font-family: Consolas, "Courier New", monospace;
        font-size: 8.5pt;
        background-color: #f8fafc;
        border: 0.5pt solid #e2e8f0;
        padding: 1pt 3pt;
        border-radius: 2pt;
    }
    pre {
        background-color: #f8fafc;
        border: 0.5pt solid #cbd5e1;
        padding: 6pt;
        border-radius: 3pt;
        overflow-x: auto;
        font-size: 8pt;
        page-break-inside: avoid;
    }
    blockquote {
        margin: 8pt 0;
        padding: 4pt 10pt;
        border-left: 3pt solid #3b82f6;
        background-color: #eff6ff;
        color: #1e3a8a;
        page-break-inside: avoid;
    }
    .header-box {
        background: #f8fafc;
        border: 1pt solid #e2e8f0;
        border-radius: 4pt;
        padding: 10pt;
        margin-bottom: 16pt;
    }
    """

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
{css}
</style>
</head>
<body>
<div class="header-box">
  <div style="font-size: 8pt; color: #64748b; text-transform: uppercase; font-weight: 700; letter-spacing: 0.5pt;">DFIR-Nexus Forensics & Incident Response</div>
  <div style="font-size: 16pt; font-weight: 700; color: #0f172a; margin-top: 4pt;">{title}</div>
</div>
{html_body}
</body>
</html>
"""


def export_report_pdf(
    report_markdown: str,
    output_path: Path | str,
    title: str = "DFIR-Nexus Incident Report",
    *,
    redact: bool = False,
) -> Path:
    """Render a vector PDF report from markdown text using a headless browser.

    Args:
        report_markdown: Report markdown text.
        output_path: Destination path for the generated PDF.
        title: Document title.
        redact: Whether to redact secrets before generating PDF.

    Returns:
        The Path to the generated PDF.

    Raises:
        PDFExportError: If browser is not found or rendering fails.
        RedactionError: If redaction fails.
    """
    out_p = Path(output_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)

    text_to_render = report_markdown
    if redact:
        redacted_text, redactions = redact_report_secrets(text_to_render)
        brief = exposure_brief(redactions)
        text_to_render = f"{redacted_text}\n\n{brief}"

    html_content = _markdown_to_printable_html(text_to_render, title=title)

    engine = find_pdf_engine()
    if not engine:
        raise PDFExportError(
            "No headless PDF engine found. Microsoft Edge or Google Chrome is required for PDF export."
        )

    # Use a temporary HTML file for the headless browser print
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as tmp:
        tmp.write(html_content)
        tmp_path = Path(tmp.name)

    try:
        cmd = [
            engine,
            "--headless",
            "--disable-gpu",
            "--run-all-compositor-stages-before-draw",
            f"--print-to-pdf={out_p}",
            str(tmp_path),
        ]
        log.info("Generating PDF: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise PDFExportError(
                f"PDF engine failed with exit code {result.returncode}: {result.stderr.strip()}"
            )

        if not out_p.is_file() or out_p.stat().st_size == 0:
            raise PDFExportError(f"PDF generation failed: output file {out_p} was not created or is empty")

        log.info("PDF exported successfully: %s (%d bytes)", out_p, out_p.stat().st_size)
        return out_p

    except subprocess.TimeoutExpired as exc:
        raise PDFExportError("PDF generation timed out after 60s") from exc
    except PDFExportError:
        raise
    except Exception as exc:
        raise PDFExportError(f"Failed to generate PDF: {exc}") from exc
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
