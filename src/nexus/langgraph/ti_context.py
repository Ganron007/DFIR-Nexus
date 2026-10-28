"""Lead observables + TI enrichment — Mode 1 interpretation & steering.

Takes hashes / public IPs / domains / URLs from the typed (ECS) fields of the
evidence rows the case's leads cite (D455), checks hashes against the local
known-good baseline, runs the TI router on the rest (local-capable; external
only when providers are configured), and renders a compact context block for
the LLM. ``extract_iocs`` types values in examiner-written text, which has no
fields.

TI results are INVESTIGATION CONTEXT — never case evidence (FD-001).
Findings must still cite the evidence rows' audit_ids.
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from nexus.langgraph.typed_entities import (
    OBSERVABLE_KINDS,
    is_private_ip,
    iter_sources,
    observables_from_ecs,
)

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
            if not is_private_ip(m):
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


def lead_references(leads: Iterable[dict[str, Any]]) -> tuple[dict[str, list[str]], dict[tuple[str, str], list[str]]]:
    """Every evidence row the leads cite, by document id and by (file, line) -> the subjects citing it."""
    from nexus.analysis.leads import lead_row_refs

    by_id: dict[str, list[str]] = {}
    by_loc: dict[tuple[str, str], list[str]] = {}
    for lead in leads:
        subject = str(lead.get("subject") or "")
        doc_ids, locs = lead_row_refs(lead)
        for key, table in [(d, by_id) for d in doc_ids] + [(loc, by_loc) for loc in locs]:
            subjects = table.setdefault(key, [])
            if subject and subject not in subjects:
                subjects.append(subject)
    return by_id, by_loc


def select_lead_observables(case_id: str, leads: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """The observables in the index rows the case's leads cite (D455, operator 2026-10-28)."""
    from nexus.analysis.leads import lead_rows_query

    leads = list(leads)
    by_id, by_loc = lead_references(leads)
    found: dict[str, set[str]] = {kind: set() for kind in OBSERVABLE_KINDS}
    sources: dict[str, list[str]] = {}
    rows_found = 0
    ids, locs = sorted(by_id), sorted(by_loc)
    for start in range(0, max(len(ids), len(locs)), 200):
        query = lead_rows_query(ids[start:start + 200], locs[start:start + 200])
        if query is None:
            continue
        for doc in iter_sources(case_id, query, ["file", "line", "ecs"]):
            rows_found += 1
            subjects = (by_id.get(str(doc.get("_id") or ""))
                        or by_loc.get((str(doc.get("file") or ""), str(doc.get("line") or ""))) or [])
            for kind, values in observables_from_ecs(doc.get("ecs")).items():
                found[kind] |= values
                for value in values:
                    listed = sources.setdefault(value, [])
                    listed.extend(s for s in subjects if s not in listed)
    return {"leads": len(leads), "lead_rows": len(by_id) + len(by_loc), "rows_found": rows_found,
            "iocs": {kind: sorted(found[kind]) for kind in OBSERVABLE_KINDS}, "sources": sources}


def known_good_hashes(values: Iterable[str]) -> dict[str, list[str]]:
    """Hashes the local known-good baseline holds -> its file paths. Never leaves the machine."""
    hashes = [v for v in values if len(v) in (32, 40, 64) and all(c in "0123456789abcdef" for c in v)]
    if not hashes:
        return {}
    from nexus.config import settings
    from nexus.triage.db import KnownGoodDB

    path = settings.data_root / "triage" / "known_good.db"
    if not path.exists():
        return {}
    db = KnownGoodDB(path, read_only=True)
    db.connect()
    try:
        out: dict[str, list[str]] = {}
        for value in hashes:
            rows = db.lookup_hash(value)
            if rows:
                out[value] = sorted({str(r.get("path_normalized") or "") for r in rows})
        return out
    finally:
        db.close()


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


def render_ti_markdown(selection: dict[str, Any], known_good: dict[str, list[str]],
                       results: list[dict[str, Any]]) -> str:
    """Compact markdown block: the lead observables, the local known-good ones, provider verdicts."""
    iocs: dict[str, list[str]] = selection.get("iocs") or {}
    sources: dict[str, list[str]] = selection.get("sources") or {}
    lines = [
        "# Threat-intel context (context, never evidence — FD-001)",
        "",
        "Observables by field meaning (hash, public address, DNS name, domain and URL fields) in the "
        f"{selection.get('lead_rows', 0)} evidence row(s) cited by {selection.get('leads', 0)} lead(s); "
        f"{selection.get('rows_found', 0)} of those rows are in the index. "
        "Any other value is looked up on demand with ti_lookup.",
        "Observables: " + ", ".join(f"{kind}={len(iocs.get(kind) or [])}" for kind in OBSERVABLE_KINDS)
        + f"; in the local known-good baseline (not sent out): {len(known_good)}.",
    ]

    def _leads(value: str) -> str:
        subjects = sources.get(value) or []
        return f" — leads: {'; '.join(subjects[:3])}" if subjects else ""

    if results:
        lines.append("")
        lines.append("## Provider verdicts")
        lines.extend(_result_line(r) + _leads(str(r.get("value") or "")) for r in results)
    else:
        lines.append("")
        lines.append("No provider lookups run (no lead observable outside the known-good baseline).")
    if known_good:
        lines.append("")
        lines.append("## Known-good (local baseline)")
        lines.extend(f"- {value} → {', '.join(paths[:2])}{_leads(value)}"
                     for value, paths in sorted(known_good.items()))
    return "\n".join(lines) + "\n"


def build_case_ti_context(selection: dict[str, Any]) -> dict[str, Any]:
    """Enrich the selected lead observables the local known-good baseline does not hold."""
    ordered = _ordered_iocs(selection.get("iocs") or {})
    known_good = known_good_hashes(ordered)
    lookups = [value for value in ordered if value not in known_good]
    results = enrich_iocs(lookups) if lookups else []
    return {
        "selection": selection,
        "known_good": known_good,
        "iocs": lookups,
        "results": results,
        "markdown": render_ti_markdown(selection, known_good, results),
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
