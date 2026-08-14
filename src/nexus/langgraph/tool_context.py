"""Deterministic case-context overlay for tools mode (no LLM).

Maps examiner intake / playbook keywords onto ledger rows so a human (and
later coverage) can see *which parsed families matter for this case*. This is
not a finding and does not change which parsers run.
"""

from __future__ import annotations

from typing import Any

from nexus.langgraph.case_intake import extra_playbook_names

# Playbook ID → ledger tool keys (and purpose substrings) to highlight.
_PLAYBOOK_TOOLS: dict[str, tuple[str, ...]] = {
    "usb_activity": (
        "sbecmd", "lecmd", "jlecmd", "recmd", "setupapi", "pecmd", "hayabusa",
        "evtxecmd",
    ),
    "data_staging": (
        "srumecmd", "rbcmd", "bitsparser", "bmc-tools", "sqlecmd", "mftecmd",
        "hayabusa",
    ),
    "external_compromise": (
        "hayabusa", "evtxecmd", "pecmd", "amcacheparser", "vol",
        "bitsparser", "recmd", "srumecmd", "mftecmd",
    ),
}

_KEYWORD_TOOLS: tuple[tuple[tuple[str, ...], tuple[str, ...]], ...] = (
    (("usb", "removable", "thumb drive"),
     ("sbecmd", "lecmd", "setupapi", "recmd")),
    (("rdp", "remote desktop", "bitmap"),
     ("bmc-tools", "hayabusa", "evtxecmd")),
    (("bits", "qmgr", "download job"),
     ("bitsparser",)),
    (("memory", "volatility", "process list"),
     ("vol",)),
    (("external", "compromise", "intrusion", "malware", "c2", "phishing"),
     ("hayabusa", "evtxecmd", "pecmd", "amcacheparser", "vol", "recmd")),
)


def _blob(ctx: dict[str, Any] | None) -> str:
    ctx = ctx or {}
    return " ".join(
        str(ctx.get(k) or "")
        for k in ("hypothesis", "description", "question", "notes", "playbooks")
    ).lower()


def relevant_tool_keys(ctx: dict[str, Any] | None) -> list[str]:
    """Tool keys an examiner should read first, given intake. Empty = no bias."""
    keys: list[str] = []
    for pb in extra_playbook_names(ctx):
        keys.extend(_PLAYBOOK_TOOLS.get(pb, ()))
    blob = _blob(ctx)
    if blob.strip():
        for needles, tools in _KEYWORD_TOOLS:
            if any(n in blob for n in needles):
                keys.extend(tools)
    return list(dict.fromkeys(keys))


def build_tool_context_markdown(
    ctx: dict[str, Any] | None,
    ledger: list[dict[str, Any]] | None = None,
) -> str:
    """Plain-text overlay for TOOL-RUN.md. No narrative findings."""
    ctx = ctx or {}
    ledger = ledger or []
    lines = [
        "## Case-context overlay (deterministic, not LLM)",
        "",
    ]
    filled = {
        k: str(ctx.get(k) or "").strip()
        for k in (
            "hypothesis", "question", "description", "window",
            "subjects", "known_good", "playbooks", "host",
        )
        if str(ctx.get(k) or "").strip()
    }
    if not filled:
        lines.extend([
            "No examiner category / hypothesis / question was provided.",
            "The lane still parsed every present artifact. Later coverage/design "
            "interpretation without intake will be generic host-triage only — "
            "do not treat that as a reliable case narrative.",
            "",
        ])
        return "\n".join(lines)

    lines.append("Intake used as a **read-order hint** (does not change parsers):")
    for key, val in filled.items():
        lines.append(f"- **{key}:** {val}")
    lines.append("")

    want = set(relevant_tool_keys(ctx))
    if not want:
        lines.append("No playbook/keyword mapping matched. Read the full ledger.")
        lines.append("")
        return "\n".join(lines)

    lines.append("Ledger rows that match this intake (OK first):")
    matched = [
        r for r in ledger
        if str(r.get("tool") or "").lower() in want
    ]
    if not matched:
        lines.append("- (no matching rows in this run — artifact may be absent)")
    else:
        for row in matched:
            lines.append(
                f"- **{row.get('status')}** `{row.get('host')}/{row.get('tool')}` "
                f"— {row.get('purpose') or ''}"
            )
    lines.extend([
        "",
        "This is not a finding. Coverage/design may interpret these rows under "
        "the hypothesis; evidence still wins.",
        "",
    ])
    return "\n".join(lines)
