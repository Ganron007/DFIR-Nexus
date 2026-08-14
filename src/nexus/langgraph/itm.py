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
        "HYPOTHESIS LENSES (both apply; evidence chooses which fits):\n"
        "A) External compromise / intrusion — MITRE ATT&CK when justified "
        "(initial access, execution, persistence, C2, credential access). "
        "Do not invent an APT name or campaign.\n"
        "B) Insider misuse — Insider Threat Matrix "
        f"({ITM_URL}): itm_stage (Motive|Means|Preparation|Infringement|"
        "Anti-Forensics) and itm_objects when the facts support an authorized "
        "user abusing access. Omit ITM fields when the evidence is only "
        "external-intrusion or is benign.\n"
        "Call forensic_rag_search only for QUERY PACK hit families "
        "(how to read those artifacts). Do not dump unrelated methodology.\n\n"
        f"{text}\n"
    )
