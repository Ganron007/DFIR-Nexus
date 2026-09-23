"""F2: report per-stage ITM coverage + registry facts (id-validated)."""

from __future__ import annotations


def test_itm_coverage_lines_validated_and_grouped():
    from nexus.integration.dfir_report import _itm_coverage_lines

    findings = [
        {
            "id": "F-1",
            "title": "RDP configuration change",
            "interpretation": (
                "Insider Threat Matrix (Preparation): AR3/PR026. "
                "Also AR3/PR999 (invented, must be dropped)."
            ),
        },
        {
            "id": "F-2",
            "title": "Shadow copies deleted",
            "interpretation": "Insider Threat Matrix (Anti-Forensics): AR5/AF020.",
        },
        {"id": "F-3", "title": "No mapping", "interpretation": "plain finding"},
    ]
    lines = _itm_coverage_lines(findings)
    text = "\n".join(lines)

    assert "### Stage coverage" in text
    # Preparation evidenced once, Anti-Forensics once; invented id dropped.
    assert "| Preparation | 1 |" in text
    assert "| Anti-Forensics | 1 |" in text
    assert "`AR3/PR026`" in text and "Remote Desktop" in text
    assert "`AR5/AF020`" in text
    assert "PR999" not in text

    # Registry facts carry the three frameworks.
    assert "Insider Threat Matrix**:" in text
    assert "MITRE ATLAS** (AI/ML)" in text
    assert "MITRE MBC** (malware)" in text
    assert "capa-YARA rules" in text


def test_itm_coverage_without_ids_is_negative_evidence_wording():
    from nexus.integration.dfir_report import _itm_coverage_lines

    text = "\n".join(_itm_coverage_lines([{"id": "F-9", "title": "x"}]))
    assert "absence of evidence, not absence" in text
    assert "| Motive | 0 |" in text
