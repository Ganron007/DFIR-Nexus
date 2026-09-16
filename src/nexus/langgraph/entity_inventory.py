"""Deterministic entity inventory — Mode 2 broad-interpretation input.

Censuses every item of interest from the case's indexed evidence rows:
processes, file paths, users, hosts, network IOCs, hashes, command-line
hints. The Mode 2 interpret agent must address every item; the gap list
(``compute_coverage_gaps``) marks anything its findings did not mention.

The inventory is investigation scaffolding — findings still cite evidence
rows' audit_ids (FD-001).
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_EXE_RE = re.compile(r"[A-Za-z0-9_\-.]+\.exe\b", re.IGNORECASE)
_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\",;'<>|]{3,160}")
_USER_RE = re.compile(
    r"(?:SrcUser|TgtUser|TargetUser|SourceUser|UserName|AccountName|user|account)"
    r"\s*[:=]\s*([A-Za-z0-9_.\\$-]{2,64})",
    re.IGNORECASE,
)
_CMD_HINTS = (
    "powershell", "cmd.exe", "wmic", "rundll32", "regsvr32", "mshta",
    "certutil", "bitsadmin", "curl", "wget", "nltest", "net.exe",
    "vssadmin", "wbadmin", "schtasks", "wevtutil", "icacls",
)
_CAP = 40


def _add(counts: dict[str, int], value: str) -> None:
    v = (value or "").strip().strip(".,;:()[]\"'")
    if not v or v.lower() in ("n/a", "na", "null", "none", "-", "unknown"):
        return
    if "|" in v or v.endswith(":"):
        return  # regex artifacts like "SourceUser:  | TargetUser"
    counts[v] = counts.get(v, 0) + 1


def _add_path(counts: dict[str, int], value: str) -> None:
    """Host paths only — the case rung/evidence source paths are not artifacts."""
    v = (value or "").strip().strip(".,;:()[]\"'")
    if len(v) < 12 or v.endswith("\\"):
        return
    low = v.lower()
    if "\\cases\\" in low or "evidence-files" in low or "\\runs\\" in low:
        return
    counts[v[:160]] = counts.get(v[:160], 0) + 1


def _top(counts: dict[str, int], cap: int = _CAP) -> list[dict[str, Any]]:
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))
    return [{"value": v, "count": c} for v, c in ranked[:cap]]


def build_entity_inventory(case_id: str, *, cap: int = _CAP) -> dict[str, Any]:
    """Census entities from the case's indexed evidence rows (no LLM)."""
    from nexus.tools.evidence_index import do_n4_query

    result = do_n4_query(case_id=case_id, dsl="", limit=400, match_all=True)
    hits = [h for h in (result.get("hits") or []) if isinstance(h, dict)]

    procs: dict[str, int] = {}
    paths: dict[str, int] = {}
    users: dict[str, int] = {}
    hosts: dict[str, int] = {}
    commands: dict[str, int] = {}
    for h in hits:
        text = str(h.get("text") or "")
        host = str(h.get("host") or "")
        if host:
            _add(hosts, host)
        fields = h.get("fields") or {}
        if isinstance(fields, dict):
            for key, value in fields.items():
                key_low = str(key).lower()
                str_value = str(value or "")
                if key_low in ("computer", "host", "hostname"):
                    _add(hosts, str_value)
                elif "user" in key_low or "account" in key_low:
                    for u in _USER_RE.findall(str_value) or [str_value]:
                        _add(users, u)
                text += " " + str_value
        for m in _EXE_RE.findall(text):
            _add(procs, m.lower())
        for m in _PATH_RE.findall(text):
            _add_path(paths, m)
        low = text.lower()
        for hint in _CMD_HINTS:
            if hint in low:
                _add(commands, hint)

    from nexus.langgraph.ti_context import extract_iocs

    network = extract_iocs([str(h.get("text") or "") for h in hits], cap=cap)

    inventory = {
        "hits_scanned": len(hits),
        "error": result.get("error"),
        "processes": _top(procs, cap),
        "paths": _top(paths, cap),
        "users": _top(users, cap),
        "hosts": _top(hosts, cap),
        "commands": _top(commands, cap),
        "network": {
            "ipv4": network.get("ipv4", []),
            "domain": network.get("domain", []),
            "url": network.get("url", []),
        },
        "hashes": {
            "sha256": network.get("sha256", []),
            "sha1": network.get("sha1", []),
            "md5": network.get("md5", []),
        },
    }
    return inventory


def render_inventory_markdown(inv: dict[str, Any], *, per_kind: int = 20) -> str:
    """Compact prompt/markdown block for the interpret agent."""
    lines = [
        "# Entity inventory (deterministic census — address EVERY item)",
        "",
        f"Scanned {inv.get('hits_scanned', 0)} indexed row(s).",
    ]

    def _line(label: str, items: list[Any]) -> None:
        if not items:
            return
        rendered = []
        for item in items[:per_kind]:
            if isinstance(item, dict):
                rendered.append(f"{item.get('value')} ({item.get('count')})")
            else:
                rendered.append(str(item))
        lines.append(f"- {label}: " + ", ".join(rendered))

    _line("Processes/executables", list(inv.get("processes") or []))
    _line("Hosts", list(inv.get("hosts") or []))
    _line("Users/accounts", list(inv.get("users") or []))
    _line("Paths", list(inv.get("paths") or []))
    _line("Command hints", list(inv.get("commands") or []))
    net = inv.get("network") or {}
    for kind in ("ipv4", "domain", "url"):
        _line(f"Network/{kind}", list(net.get(kind) or []))
    hashes = inv.get("hashes") or {}
    for kind in ("sha256", "sha1", "md5"):
        _line(f"Hashes/{kind}", list(hashes.get(kind) or []))
    lines.append("")
    lines.append(
        "For EVERY item above: cite the evidence row(s) that show it and "
        "classify it (known-good / likely-benign / suspicious / unknown). "
        "Items with no further signal must still appear — state the assessment."
    )
    return "\n".join(lines) + "\n"


def write_entity_inventory(case_dir: Path, inv: dict[str, Any]) -> Path | None:
    """Persist the inventory to analysis/entity_inventory.json."""
    try:
        analysis = Path(case_dir) / "analysis"
        analysis.mkdir(parents=True, exist_ok=True)
        path = analysis / "entity_inventory.json"
        path.write_text(json.dumps(inv, indent=2, default=str), encoding="utf-8")
        return path
    except OSError as exc:
        log.warning("entity inventory write failed: %s", exc)
        return None


def _iter_significant(inv: dict[str, Any]) -> list[tuple[str, str]]:
    """(kind, value) pairs worth coverage-checking, most significant first."""
    out: list[tuple[str, str]] = []
    for item in (inv.get("processes") or [])[:15]:
        out.append(("process", str(item.get("value") or "")))
    for item in (inv.get("hosts") or [])[:6]:
        out.append(("host", str(item.get("value") or "")))
    for item in (inv.get("users") or [])[:6]:
        out.append(("user", str(item.get("value") or "")))
    net = inv.get("network") or {}
    for kind in ("ipv4", "domain", "url"):
        for value in (net.get(kind) or [])[:8]:
            out.append((kind, str(value)))
    hashes = inv.get("hashes") or {}
    for kind in ("sha256", "sha1", "md5"):
        for value in (hashes.get(kind) or [])[:4]:
            out.append((kind, str(value)))
    return [(k, v) for k, v in out if v]


def compute_coverage_gaps(inv: dict[str, Any], findings: list[dict[str, Any]],
                          *, cap: int = 25) -> list[dict[str, str]]:
    """Items in the inventory never mentioned by any staged finding."""
    blob = " ".join(
        " ".join(str(f.get(k) or "") for k in
                 ("title", "observation", "interpretation", "evidence"))
        for f in findings or []
        if isinstance(f, dict)
    ).lower()
    gaps: list[dict[str, str]] = []
    for kind, value in _iter_significant(inv):
        if value.lower() not in blob:
            gaps.append({"kind": kind, "value": value})
        if len(gaps) >= cap:
            break
    return gaps
