"""D1 — draft Sigma / KQL / Suricata from APPROVED findings for the SIEM team.

Not an N5 input. Do not deploy. Detection RAG must not be treated as host facts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_EXE = re.compile(r"\b[\w.-]+\.exe\b", re.I)
_PATH = re.compile(r"[A-Za-z]:\\[^\s\"']+", re.I)
_JUNK_NEEDLE = (
    "_stdout.txt",
    "_stderr.txt",
    ".nexus\\cases",
    ".nexus/cases",
    "\\extractions\\",
    "/extractions/",
)


def _keep_needle(token: str) -> bool:
    low = token.replace("/", "\\").lower()
    if any(j.replace("/", "\\") in low for j in _JUNK_NEEDLE):
        return False
    if "\\.nexus\\" in low:
        return False
    return True


def _needles(findings: list[dict[str, Any]]) -> list[str]:
    blob = " ".join(
        str(f.get(k) or "")
        for f in findings
        for k in ("title", "observation", "description", "interpretation")
    )
    found = [m.group(0) for m in _EXE.finditer(blob)]
    found.extend(m.group(0) for m in _PATH.finditer(blob))
    # Keep distinctive tokens from titles
    for f in findings:
        title = str(f.get("title") or "")
        for tok in ("sdelete", "pst", "drivefs", "mimikatz", "rubeus"):
            if tok in title.lower():
                found.append(tok)
    seen: set[str] = set()
    out: list[str] = []
    for t in found:
        if not _keep_needle(t):
            continue
        key = t.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(t)
    return out[:20]


def draft_sigma(needles: list[str], case_id: str) -> str:
    sels = "\n".join(f"            - '*{n}*'" for n in needles) or "            - '*placeholder*'"
    return (
        f"title: DFIR-Nexus draft from {case_id}\n"
        "status: experimental\n"
        "description: Drafted from APPROVED host findings. Hand to SIEM — do not auto-deploy.\n"
        "logsource:\n"
        "    category: process_creation\n"
        "    product: windows\n"
        "detection:\n"
        "    selection:\n"
        "        CommandLine|contains:\n"
        f"{sels}\n"
        "    condition: selection\n"
        "falsepositives:\n"
        "    - Unknown\n"
        "level: medium\n"
    )


def draft_kql(needles: list[str]) -> str:
    if not needles:
        return "// INSUFFICIENT — no process/path needles on APPROVED findings\n"
    ors = " or ".join(f"ProcessCommandLine has \"{n.replace(chr(34), '')}\"" for n in needles)
    return (
        "// Draft KQL from APPROVED findings — SIEM team owns search/deploy\n"
        "DeviceProcessEvents\n"
        f"| where {ors}\n"
        "| project Timestamp, DeviceName, FileName, ProcessCommandLine\n"
    )


def draft_suricata(needles: list[str]) -> str:
    lines = ["# Draft Suricata — file for SIEM/NSM, not loaded into N5"]
    sid = 1100001
    for n in needles:
        if n.lower().endswith(".exe") or n.lower() in {"sdelete", "mimikatz"}:
            content = n.replace(";", "")
            lines.append(
                f'alert http any any -> any any (msg:"NEXUS-DRAFT {content}"; '
                f'content:"{content}"; nocase; sid:{sid}; rev:1;)'
            )
            sid += 1
    if len(lines) == 1:
        lines.append("# INSUFFICIENT — no network-exportable needles")
    return "\n".join(lines) + "\n"


def draft_from_approved(
    case_dir: Path,
    findings: list[dict[str, Any]] | None = None,
    finding_ids: list[str] | None = None,
) -> dict[str, Any]:
    case_dir = Path(case_dir)
    if findings is None:
        fp = case_dir / "findings.json"
        findings = json.loads(fp.read_text(encoding="utf-8")) if fp.is_file() else []
    if finding_ids:
        want = set(finding_ids)
        findings = [f for f in findings if f.get("id") in want]
    approved = [
        f for f in findings
        if str(f.get("status") or f.get("approval_state") or "").upper() == "APPROVED"
    ]
    dest = case_dir / "analysis" / "detections"
    dest.mkdir(parents=True, exist_ok=True)
    needles = _needles(approved)
    (dest / "draft.sigma.yml").write_text(draft_sigma(needles, case_dir.name), encoding="utf-8")
    (dest / "draft.kql").write_text(draft_kql(needles), encoding="utf-8")
    (dest / "draft.suricata.rules").write_text(draft_suricata(needles), encoding="utf-8")
    readme = (
        "D1 drafts from APPROVED findings only.\n"
        "Hand these files to the SIEM team. DFIR-Nexus does not deploy them.\n"
        "Do not treat this folder as host evidence or N5 facts.\n"
    )
    (dest / "README.md").write_text(readme, encoding="utf-8")
    return {
        "approved": len(approved),
        "needles": needles,
        "dir": str(dest),
    }
