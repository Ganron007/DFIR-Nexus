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
from collections.abc import Iterable
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_EXE_RE = re.compile(r"[A-Za-z0-9_\-.]+\.exe\b", re.IGNORECASE)
_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\",;'<>|]{3,}")
_USER_RE = re.compile(
    r"(?:SrcUser|TgtUser|TargetUser|SourceUser|UserName|AccountName|user|account)"
    r"\s*[:=]\s*([A-Za-z0-9_.\\$-]{2,})",
    re.IGNORECASE,
)
_CMD_HINTS = (
    "powershell", "cmd.exe", "wmic", "rundll32", "regsvr32", "mshta",
    "certutil", "bitsadmin", "curl", "wget", "nltest", "net.exe",
    "vssadmin", "wbadmin", "schtasks", "wevtutil", "icacls",
)
def _looks_like_path(value: str) -> bool:
    """True when a value is a filesystem path (or a path fragment).

    ``C:\\STUDY\\Github\\...`` and every ``dir\\leaf`` piece of it match the
    generic DOMAIN\\user shape — reject path context, not accounts.
    """
    v = str(value or "").strip()
    if not v:
        return False
    if v.startswith(("\\\\", "/")) or re.match(r"^[A-Za-z]:[\\/]", v):
        return True
    return v.count("\\") >= 2


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
    counts[v] = counts.get(v, 0) + 1


def _top(counts: dict[str, int]) -> list[dict[str, Any]]:
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0].lower()))
    return [{"value": v, "count": c} for v, c in ranked]


class EntityAccumulator:
    """Entity counters and raw-text network census without retaining hits."""

    def __init__(self) -> None:
        from nexus.langgraph.ti_context import IOCAccumulator

        self.hits_scanned = 0
        self.procs: dict[str, int] = {}
        self.paths: dict[str, int] = {}
        self.users: dict[str, int] = {}
        self.hosts: dict[str, int] = {}
        self.commands: dict[str, int] = {}
        self.network = IOCAccumulator()

    def add_hit(self, h: dict[str, Any]) -> None:
        if not isinstance(h, dict):
            return
        self.hits_scanned += 1
        text = str(h.get("text") or "")
        self.network.add_text(text)
        host = str(h.get("host") or "")
        if host:
            _add(self.hosts, host)
        fields = h.get("fields") or {}
        if isinstance(fields, dict):
            for key, value in fields.items():
                key_low = str(key).lower()
                str_value = str(value or "")
                if key_low in ("computer", "host", "hostname"):
                    _add(self.hosts, str_value)
                elif "user" in key_low or "account" in key_low:
                    found = _USER_RE.findall(str_value)
                    for u in found or [str_value]:
                        if _looks_like_path(str(u)):
                            continue  # C:\STUDY\Github\... is a directory, not an account
                        _add(self.users, u)
                text += " " + str_value
        for m in _EXE_RE.findall(text):
            _add(self.procs, m.lower())
        for m in _PATH_RE.findall(text):
            _add_path(self.paths, m)
        low = text.lower()
        for hint in _CMD_HINTS:
            if hint in low:
                _add(self.commands, hint)


    def result(self) -> dict[str, Any]:
        network = self.network.result()
        inventory = {
            "hits_scanned": self.hits_scanned,
            "hits_capped": False,
            "error": "",
            "processes": _top(self.procs),
            "paths": _top(self.paths),
            "users": _top(self.users),
            "hosts": _top(self.hosts),
            "commands": _top(self.commands),
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


def build_entity_inventory(
    case_id: str,
    *,
    hits: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the existing complete inventory by folding its input stream."""
    if hits is None:
        from nexus.langgraph.case_census import iter_case_hits

        hits = iter_case_hits(case_id)
    accumulator = EntityAccumulator()
    for hit in hits:
        accumulator.add_hit(hit)
    return accumulator.result()


def render_inventory_markdown(inv: dict[str, Any]) -> str:
    """Compact prompt/markdown block for the interpret agent."""
    lines = [
        "# Entity inventory (deterministic census — address EVERY item)",
        "",
        f"Scanned {inv.get('hits_scanned', 0)} indexed row(s)."
        + (
            " WARNING: capped sample — coverage may be incomplete."
            if inv.get("hits_capped")
            else ""
        ),
    ]

    def _line(label: str, items: list[Any]) -> None:
        if not items:
            return
        rendered = []
        for item in items:
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
    for item in (inv.get("processes") or []):
        out.append(("process", str(item.get("value") or "")))
    for item in (inv.get("hosts") or []):
        out.append(("host", str(item.get("value") or "")))
    for item in (inv.get("users") or []):
        out.append(("user", str(item.get("value") or "")))
    for item in (inv.get("paths") or []):
        out.append(("path", str(item.get("value") or "")))
    for item in (inv.get("commands") or []):
        out.append(("command", str(item.get("value") or "")))
    net = inv.get("network") or {}
    for kind in ("ipv4", "domain", "url"):
        for value in (net.get(kind) or []):
            out.append((kind, str(value)))
    hashes = inv.get("hashes") or {}
    for kind in ("sha256", "sha1", "md5"):
        for value in (hashes.get(kind) or []):
            out.append((kind, str(value)))
    return [(k, v) for k, v in out if v]


def compute_coverage_gaps(inv: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, str]]:
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
    return gaps
