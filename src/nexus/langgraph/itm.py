"""Insider Threat Matrix prompt block (local copy of the public taxonomy)."""

from __future__ import annotations

from pathlib import Path

_ITM_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "knowledge"
    / "discipline"
    / "framework"
    / "insider_threat_matrix.md"
)

ITM_URL = "https://insiderthreatmatrix.org/"


def itm_prompt_block() -> str:
    text = ""
    if _ITM_PATH.is_file():
        text = _ITM_PATH.read_text(encoding="utf-8")
    return (
        "INSIDER THREAT MATRIX (required mapping):\n"
        f"Look up and apply {ITM_URL}. Local taxonomy follows — map every "
        "finding to itm_stage (Motive|Means|Preparation|Infringement|"
        "Anti-Forensics) and itm_objects (names from the taxonomy). "
        "Call forensic_rag_search for insider-threat / data-staging / "
        "cloud-exfil methodology before emitting JSON.\n\n"
        f"{text}\n"
    )
