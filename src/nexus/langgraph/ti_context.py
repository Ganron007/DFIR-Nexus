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
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|top|xyz|info|biz|online|site|club|live|"
    r"support|link|click|onion|dev|app|cloud|pro|cc|tk|gg)\b",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s\"'<>|)]{6,200}", re.IGNORECASE)

_SYSTEM_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com",
    "schemas.microsoft.com", "w3.org", "verisign.com", "digicert.com",
    "globalsign.com", "sectigo.com", "local", "localhost",
}
_NOISE_URL_PARTS = ("schemas.", "w3.org", "xmlns", "schemas.microsoft.com")

_MAX_PER_KIND = 6


def _is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return True
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved


def extract_iocs(texts: list[str], *, cap: int = 12) -> dict[str, list[str]]:
    """Deterministic IOC census over evidence text (hashes > IPs > domains > URLs)."""
    found: dict[str, set[str]] = {"sha256": set(), "sha1": set(), "md5": set(),
                                  "ipv4": set(), "domain": set(), "url": set()}
    for text in texts:
        if not text:
            continue
        for m in _SHA256_RE.findall(text):
            found["sha256"].add(m.lower())
        for m in _SHA1_RE.findall(text):
            found["sha1"].add(m.lower())
        for m in _MD5_RE.findall(text):
            found["md5"].add(m.lower())
        for m in _IPV4_RE.findall(text):
            if not _is_private_ip(m):
                found["ipv4"].add(m)
        for m in _DOMAIN_RE.findall(text):
            d = m.lower().strip(".")
            if d in _SYSTEM_DOMAINS:
                continue
            # Skip pure hex-ish tokens that happen to look like domains
            if re.fullmatch(r"[a-f0-9]{8,}", d.split(".")[0]):
                continue
            found["domain"].add(d)
        for m in _URL_RE.findall(text):
            u = m.rstrip(".,;:)")
            if any(part in u.lower() for part in _NOISE_URL_PARTS):
                continue
            found["url"].add(u[:200])
    out: dict[str, list[str]] = {}
    for kind, values in found.items():
        # hashes first by kind priority; drop hashes that are substrings of
        # longer hashes seen (md5 inside sha1/sha256 hex strings is common)
        out[kind] = sorted(values)[:cap]
    sha256_set = set(out["sha256"])
    all_hex = " ".join(sha256_set)
    out["sha1"] = [h for h in out["sha1"] if h not in all_hex][:_MAX_PER_KIND]
    sha1_joined = " ".join(out["sha1"])
    out["md5"] = [h for h in out["md5"]
                  if h not in all_hex and h not in sha1_joined][:_MAX_PER_KIND]
    return out


def _ordered_iocs(iocs: dict[str, list[str]], cap: int) -> list[str]:
    ordered: list[str] = []
    for kind in ("sha256", "sha1", "md5", "ipv4", "domain", "url"):
        for value in iocs.get(kind, []):
            if value not in ordered:
                ordered.append(value)
            if len(ordered) >= cap:
                return ordered
    return ordered


def sweep_case_iocs(case_id: str = "", *, cap: int = 12) -> dict[str, Any]:
    """Extract IOCs from the case's indexed evidence rows (deterministic, no LLM)."""
    from nexus.tools.evidence_index import do_n4_query

    result = do_n4_query(case_id=case_id, dsl="", limit=400, match_all=True)
    hits = result.get("hits") or []
    texts: list[str] = []
    for h in hits:
        if not isinstance(h, dict):
            continue
        texts.append(str(h.get("text") or ""))
        fields = h.get("fields") or {}
        if isinstance(fields, dict):
            texts.extend(str(v) for v in fields.values() if v)
    iocs = extract_iocs(texts, cap=cap)
    return {"hits_scanned": len(hits), "iocs": iocs, "error": result.get("error")}


def enrich_iocs(iocs: list[str], *, max_iocs: int = 6) -> list[dict[str, Any]]:
    """Run the TI router for each IOC (mock/local by default; external w/ keys)."""
    from nexus.ti import create_default_router
    from nexus.ti.enrich import _run_async

    router = create_default_router()
    results: list[dict[str, Any]] = []
    for ioc in iocs[:max_iocs]:
        try:
            res = _run_async(router.lookup(ioc))
            if isinstance(res, dict):
                results.append(res)
        except Exception as exc:  # noqa: BLE001 — enrichment is best-effort
            log.warning("TI lookup failed for %s: %s", ioc, exc)
    return results


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
    for p in (res.get("results") or [])[:5]:
        if not isinstance(p, dict):
            continue
        name = str(p.get("provider") or "")
        p_status = str(p.get("status") or "")
        p_verdict = (
            "MALICIOUS" if p.get("malicious") is True
            else "clean" if p_status == "ok"
            else p_status or "n/a"
        )
        summary = re.sub(r"\s+", " ", str(p.get("summary") or ""))[:80]
        piece = f"{name}:{p_verdict}"
        if summary and p.get("malicious") is True:
            piece += f" ({summary})"
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
        f"Scanned {sweep.get('hits_scanned', 0)} indexed evidence row(s).",
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


def build_case_ti_context(case_id: str, *, max_iocs: int = 6) -> dict[str, Any]:
    """Sweep the case's evidence for IOCs and enrich the top ones."""
    sweep = sweep_case_iocs(case_id)
    ordered = _ordered_iocs(sweep.get("iocs") or {}, max_iocs)
    results = enrich_iocs(ordered, max_iocs=max_iocs)
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
