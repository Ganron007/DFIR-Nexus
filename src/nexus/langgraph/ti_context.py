"""Deterministic IOC sweep + TI enrichment — Mode 2 interpretation & steering.

Extracts hashes / IPs / domains / URLs from the case's indexed evidence rows,
runs the TI router (local-capable; external only when providers are
configured), and renders a compact context block for the LLM.

TI results are INVESTIGATION CONTEXT — never case evidence (FD-001).
Findings must still cite the evidence rows' audit_ids.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# A domain is a whole dotted name: not the head of a longer one (`System.Net` in
# `System.Net.WebClient`) and not its tail (D202).
_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|top|xyz|info|biz|online|site|club|live|"
    r"support|link|click|onion|dev|app|cloud|pro|cc|tk|gg)(?![\w-]|\.[A-Za-z0-9])",
    re.IGNORECASE,
)


def _is_code_name(name: str) -> bool:
    """A dotted name written as code: a .NET type or namespace, not a host.

    Evidence writes host names in lower or upper case; code writes `PowerShell`, `GeneratedTypes`,
    `System.Net`. CASE-C5B04D31's census sent `system.net` (from `System.Net.WebClient`, the
    commonest PowerShell download idiom) and a `...Cmdletization.GeneratedTypes.Net` namespace to the
    threat-intel providers as domains (D202).
    """
    labels = name.split(".")
    return any(re.search(r"[a-z][A-Z]", label) for label in labels) or all(
        re.fullmatch(r"[A-Z][a-z0-9]+", label) for label in labels)
_URL_RE = re.compile(r"https?://[^\s\"'<>|)]{6,}", re.IGNORECASE)

_SYSTEM_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com",
    "schemas.microsoft.com", "w3.org", "verisign.com", "digicert.com",
    "globalsign.com", "sectigo.com", "local", "localhost",
}
_NOISE_URL_PARTS = ("schemas.", "w3.org", "xmlns", "schemas.microsoft.com")

def _is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved


_VERSION_LABEL_RE = re.compile(r"(?:version|revision)[^\d\n]{0,24}$", re.IGNORECASE)


def _address_quads(text: str) -> list[str]:
    """The dotted quads in ``text`` that stand as network addresses.

    Windows also writes versions as dotted quads: a registry key or folder named for a version
    (``...\\InprocServer32\\1.0.0.0``, ``...\\Modules\\LocalAccounts\\1.0.0.0``), a ``Version`` or
    ``Revision`` value, or the first four parts of a longer version. CASE-C5B04D31's entity census
    (2026-10-14) listed 1.0.0.0 and 3.0.0.0 as IPv4 indicators from 2,659 and 1,318 such rows. A quad
    is a path component when separators come straight after a name; a UNC host
    (``\\\\10.1.2.3\\share``) and a URL host stay addresses.
    """
    quads: list[str] = []
    for match in _IPV4_RE.finditer(text):
        start, end = match.span()
        if text[end:end + 1] == "." and text[end + 1:end + 2].isdigit():
            continue  # the start of a longer dotted number
        before = text[max(0, start - 64):start]
        name = before.rstrip("\\/")
        if len(name) < len(before) and name and (name[-1].isalnum() or name[-1] in "_$-.~}])"):
            continue  # a path component under a named key or folder
        if _VERSION_LABEL_RE.search(before):
            continue
        quads.append(match.group(0))
    return quads


class IOCAccumulator:
    """One IOC rule owner; retain unique indicators, never input rows or texts."""

    def __init__(self) -> None:
        self.found: dict[str, set[str]] = {
            "sha256": set(), "sha1": set(), "md5": set(),
            "ipv4": set(), "domain": set(), "url": set(),
        }

    def add_text(self, text: str) -> None:
        if not text:
            return
        for m in _SHA256_RE.findall(text):
            self.found["sha256"].add(m.lower())
        for m in _SHA1_RE.findall(text):
            self.found["sha1"].add(m.lower())
        for m in _MD5_RE.findall(text):
            self.found["md5"].add(m.lower())
        for m in _address_quads(text):
            if not _is_private_ip(m):
                self.found["ipv4"].add(m)
        for m in _DOMAIN_RE.findall(text):
            if _is_code_name(m):
                continue
            d = m.lower().strip(".")
            if d in _SYSTEM_DOMAINS:
                continue
            # Skip pure hex-ish tokens that happen to look like domains
            if re.fullmatch(r"[a-f0-9]{8,}", d.split(".")[0]):
                continue
            self.found["domain"].add(d)
        for m in _URL_RE.findall(text):
            u = m.rstrip(".,;:)")
            if any(part in u.lower() for part in _NOISE_URL_PARTS):
                continue
            self.found["url"].add(u)

    def result(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for kind, values in self.found.items():
            # hashes first by kind priority; drop hashes that are substrings of
            # longer hashes seen (md5 inside sha1/sha256 hex strings is common)
            out[kind] = sorted(values)
        sha256_set = set(out["sha256"])
        all_hex = " ".join(sha256_set)
        out["sha1"] = [h for h in out["sha1"] if h not in all_hex]
        sha1_joined = " ".join(out["sha1"])
        out["md5"] = [h for h in out["md5"]
                      if h not in all_hex and h not in sha1_joined]
        return out


def extract_iocs(texts: Iterable[str]) -> dict[str, list[str]]:
    """Deterministic IOC census with global hash-substring exclusion."""
    accumulator = IOCAccumulator()
    for text in texts:
        accumulator.add_text(text)
    return accumulator.result()


def _ordered_iocs(iocs: dict[str, list[str]]) -> list[str]:
    ordered: list[str] = []
    for kind in ("sha256", "sha1", "md5", "ipv4", "domain", "url"):
        for value in iocs.get(kind, []):
            if value not in ordered:
                ordered.append(value)
    return ordered


class IOCSweep:
    """TI's text-plus-fields census, incrementally folded over indexed hits."""

    def __init__(self) -> None:
        self.hits_scanned = 0
        self.iocs = IOCAccumulator()

    def add_hit(self, hit: dict[str, Any]) -> None:
        if not isinstance(hit, dict):
            return
        self.hits_scanned += 1
        self.iocs.add_text(str(hit.get("text") or ""))
        fields = hit.get("fields") or {}
        if isinstance(fields, dict):
            for value in fields.values():
                if value:
                    self.iocs.add_text(str(value))

    def result(self) -> dict[str, Any]:
        return {"hits_scanned": self.hits_scanned, "hits_capped": False,
                "iocs": self.iocs.result(), "error": ""}


def sweep_case_iocs(
    case_id: str = "",
    *,
    hits: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Census the complete hit stream without retaining rows or text lists."""
    if hits is None:
        from nexus.langgraph.case_census import iter_case_hits

        hits = iter_case_hits(case_id)
    accumulator = IOCSweep()
    for hit in hits:
        accumulator.add_hit(hit)
    return accumulator.result()


def enrich_iocs(iocs: list[str]) -> list[dict[str, Any]]:
    """Enrich every ordered IOC in one bounded asynchronous batch."""
    from nexus.ti import create_default_router
    from nexus.ti.enrich import _run_async

    router = create_default_router()
    return _run_async(router.lookup_many(iocs))


def _result_line(res: dict[str, Any]) -> str:
    value = str(res.get("value") or res.get("ioc") or "")
    ioc_type = str(res.get("ioc_type") or "")
    malicious = int(res.get("malicious_count") or 0)
    also = [p.get("provider") for p in (res.get("results") or [])
            if isinstance(p, dict) and p.get("malicious") is True]
    verdict = "MALICIOUS" if malicious else (
        "clean/unknown" if all(
            isinstance(p, dict) and p.get("status") == "ok"
            for p in (res.get("results") or [])
        ) and res.get("results") else "n/a"
    )
    tags: list[str] = []
    for p in res.get("results") or []:
        if not isinstance(p, dict):
            continue
        name = str(p.get("provider") or "")
        p_status = str(p.get("status") or "")
        p_verdict = (
            "MALICIOUS" if p.get("malicious") is True
            else "clean" if p_status == "ok"
            else p_status or "n/a"
        )
        summary = re.sub(r"\s+", " ", str(p.get("summary") or ""))
        piece = f"{name}:{p_verdict}"
        if p_status == "error" and p.get("error"):
            reason = re.sub(r"\s+", " ", str(p["error"]))
            piece += f" ({reason})"
        if summary and p.get("malicious") is True:
            piece += f" ({summary})"
        history = (p.get("raw") or {}).get("nexus_attempt_failures") or []
        if history:
            reasons = [str(item.get("reason") or "") for item in history if isinstance(item, dict)]
            piece += "; attempts: " + " | ".join(reasons)
        tags.append(piece)
    line = f"- {value} [{ioc_type}] → {verdict} (malicious_count={malicious})"
    if also:
        line += f" — flagged by: {', '.join(str(a) for a in also)}"
    if tags:
        line += f"; {'; '.join(tags)}"
    return line


def render_ti_markdown(sweep: dict[str, Any], results: list[dict[str, Any]]) -> str:
    """Compact markdown block: the IOC census + provider verdicts."""
    iocs: dict[str, list[str]] = sweep.get("iocs") or {}
    lines = [
        "# Threat-intel context (context, never evidence — FD-001)",
        "",
        f"Scanned {sweep.get('hits_scanned', 0)} indexed evidence row(s)."
        + (
            " WARNING: capped sample — this is a LOWER BOUND, not a complete census."
            if sweep.get("hits_capped")
            else ""
        ),
    ]
    census = ", ".join(
        f"{kind}={len(iocs.get(kind) or [])}" for kind in
        ("sha256", "sha1", "md5", "ipv4", "domain", "url")
    )
    lines.append(f"IOC census: {census}")
    if results:
        lines.append("")
        lines.append("## Provider verdicts")
        lines.extend(_result_line(r) for r in results)
    else:
        lines.append("")
        lines.append("No TI lookups run (no IOCs found, or providers unavailable).")
    return "\n".join(lines) + "\n"


def build_case_ti_context(
    case_id: str,
    *,
    hits: Iterable[dict[str, Any]] | None = None,
    sweep: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Sweep the case's evidence for IOCs and enrich every extracted IOC."""
    if sweep is not None and hits is not None:
        raise ValueError("supply the census or hits, not both")
    if sweep is None:
        sweep = sweep_case_iocs(case_id, hits=hits)
    ordered = _ordered_iocs(sweep.get("iocs") or {})
    results = enrich_iocs(ordered)
    return {
        "sweep": sweep,
        "iocs": ordered,
        "results": results,
        "markdown": render_ti_markdown(sweep, results),
    }


def write_ti_context(case_dir: Path, context: dict[str, Any]) -> Path | None:
    """Write analysis/ti_context.md so the briefing/portal can surface it."""
    try:
        analysis = Path(case_dir) / "analysis"
        analysis.mkdir(parents=True, exist_ok=True)
        path = analysis / "ti_context.md"
        path.write_text(str(context.get("markdown") or ""), encoding="utf-8")
        return path
    except OSError as exc:
        log.warning("ti_context write failed: %s", exc)
        return None
