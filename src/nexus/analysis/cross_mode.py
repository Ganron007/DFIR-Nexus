"""WP 10.0b - cross-mode consistency check.

The same evidence run through Mode 1 (LLM), Mode 2 (multi-role) and Mode 3
(multi-agent) can reach different conclusions. Nothing tests for it, and a
contradiction is a defect rather than a nuance: if one mode asserts a process
executed and another asserts the same process did not, an examiner reading the
report cannot tell which is grounded.

This check projects every mode's output into the one claim vocabulary the
multi-agent board already uses - the dispute key
``(entity_type, entity_value, claim_kind)`` - so an intra-Mode-3 dispute and a
cross-mode contradiction are the same object, and the same code decides both.

Three surfaces are compared:

* **shared** - two or more modes asserting the same key with the same polarity.
  Reported, because agreement is evidence, and because it is the baseline a
  contradiction is measured against.
* **contradictions** - two or more modes asserting the same key with opposite
  polarity, or a mode asserting something another mode's own artifacts deny.
  Every contradiction carries both citations.
* **row contradictions** - a claim that survives FD-001..007 but whose cited
  audit ids resolve to a row that does not contain the entity. This is the
  "what the rows deny" half, and it needs the index, so it is opt-in.

A missing mode is ``unknown``, never ``consistent``. Silence is not agreement.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

__all__ = [
    "MODES",
    "collect_mode_claims",
    "check_cross_mode",
    "check_cross_mode_group",
    "sibling_cases",
    "render_consistency_markdown",
    "write_consistency",
]

# Canonical product mode -> the labels a case may record.
MODES: dict[str, str] = {"1": "Mode 1 (LLM)", "2": "Mode 2 (multi-role)", "3": "Mode 3 (multi-agent)"}

# Polarity vocabulary, aligned with the multi-agent board.
_AFFIRM = {"affirm", "true", "present", "executed", "occurred", "yes", "support", "supports"}
_DENY = {"deny", "false", "absent", "not_executed", "did_not_occur", "no", "refute", "refutes", "contradicts"}

_FILE_EXTENSIONS = frozenset({
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf",
    "evtx", "log", "csv", "json", "jsonl", "txt", "xml", "yaml", "yml",
    "db", "dat", "sqlite", "edb", "bin", "pf", "lnk", "etl", "reg", "hve",
    "doc", "docx", "xls", "xlsx", "pdf", "png", "jpg", "gif", "zip", "7z",
    "bak", "tmp", "ini", "cfg", "conf", "htm", "html", "md", "py", "pl",
})

# Private-lab / internal TLDs that are not public suffixes. The CADRE lab runs
# `.cadre.local`, `.range.local`, `.corp.local` and friends, and an FQDN like
# `ws01.cadre.local` is a host the index holds. Without these labels every
# lab hostname was dropped as "not a domain" and the entity check silently
# skipped it. Merged into the public-suffix-ish list below.
_PRIVATE_TLDS = frozenset({
    "local", "localdomain", "lan", "intranet", "internal", "corp", "home",
    "cadre", "range", "ad", "test", "lab", "domain",
})

# A Windows path segment may contain spaces (`C:\Program Files\...`). The old
# `[^\s,;"']+` pattern stopped at the first space and truncated
# `C:\Program Files\Asset Management\tool.exe` to `c:\program`, which then
# never matched the row's full path and produced a phantom "unsupported
# entity" on the real case's evidence.
#
# Two alternatives, in order:
#   1. a path whose final component carries an extension — directory segments
#      may contain spaces, the final component may not, so the path cannot
#      swallow the prose that follows it;
#   2. a contiguous path with no whitespace at all (a bare directory such as
#      `C:\Windows\Temp`, or any single-token path).
_WIN_PATH = re.compile(
    r"\b([A-Za-z]:\\(?:[^\\\r\n<>|*?\":]+\\)*[^\\\s]*\.[A-Za-z0-9]{1,8})"
    r"|(\b[A-Za-z]:\\[^\s,;\"'<>|*?]+)"
    r"|(\\\\[^\s,;\"'<>|*?]+\\[^\s,;\"'<>|*?]+)"
)
_ENTITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("process", re.compile(r"\b([A-Za-z0-9_.\-]{3,}\.exe)\b", re.I)),
    ("domain", re.compile(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b", re.I)),
    ("ipv4", re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")),
    ("sha256", re.compile(r"\b([0-9a-f]{64})\b", re.I)),
    ("sha1", re.compile(r"\b([0-9a-f]{40})\b", re.I)),
    ("registry_key", re.compile(r"\b((?:HKEY_[A-Z_]+|HKLM|HKCU|HKU|Software)\\[^\s,;\"']{3,})", re.I)),
    ("user", re.compile(r"\b([A-Za-z0-9._\-]{2,}\\Users\\[A-Za-z0-9._\-]+)\b", re.I)),
    ("file", _WIN_PATH),
    ("url", re.compile(r"\b(https?://[^\s,;\"'<>]{6,})", re.I)),
)

# A dotted word is not automatically a domain. `security.evtx`, `zone.identifier`
# and `lsass.exe` are filenames, and calling them domains sent L1.3 hunting for
# DNS records that do not exist - so a value whose last label is a known file
# extension is not a domain. Filtered in code rather than in the pattern, which
# stays readable and keeps the extension list in one place.
_NOT_A_DOMAIN = frozenset(_FILE_EXTENSIONS) | {"identifier", "microsoft", "windows"}

# Public-suffix-ish list. A real host's last label is a TLD; `lsass.exe` ends in
# a filename extension and `zone.identifier` in a data-stream name. Keeping the
# two lists apart means the check asks the index about hosts and nothing else.
_TLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name",
    "pro", "coop", "museum", "aero", "jobs", "mobi", "travel", "cat", "tel",
    "asia", "post", "xxx", "arpa", "dev", "app", "ai", "cloud", "online",
    "site", "store", "shop", "tech", "xyz", "io", "co", "uk", "de", "fr",
    "nl", "be", "ch", "at", "it", "es", "se", "no", "fi", "dk", "pl", "cz",
    "sk", "hu", "ro", "bg", "gr", "pt", "ie", "ru", "ua", "by", "kz", "uz",
    "tr", "il", "ae", "sa", "eg", "za", "ng", "ke", "gh", "tz", "ug", "zw",
    "zm", "cm", "ci", "sn", "ml", "ma", "dz", "tn", "ly", "us", "ca", "mx",
    "br", "ar", "cl", "pe", "ve", "cr", "pa", "cu", "do", "gt", "hn", "sv",
    "ni", "bo", "py", "uy", "ec", "jm", "tt", "in", "cn", "jp", "kr", "tw",
    "hk", "sg", "my", "th", "vn", "ph", "id", "bn", "lk", "np", "mm", "kh",
    "la", "mn", "ge", "am", "az",
}) | _PRIVATE_TLDS

# Claim kinds, matching the multi-agent board's vocabulary.
_CLAIM_KINDS = {"observation", "interpretation", "temporal", "network", "persistence", "attribution"}


def _norm(v: Any) -> str:
    return str(v or "").strip()


def _polarity(v: Any, *, default_affirm: bool = True) -> str:
    s = _norm(v).lower()
    if s in _DENY:
        return "deny"
    if s in _AFFIRM:
        return "affirm"
    if re.search(r"\b(?:did\s+not|does\s+not|was\s+not|were\s+not|never|no\s+evidence|not\s+observed|could\s+not\s+be\s+found)\b", s, re.I):
        return "deny"
    if re.search(r"\b(?:executed|ran|occurred|present|detected|found|observed|created|modified|connected)\b", s, re.I):
        return "affirm"
    return "affirm" if default_affirm else "deny"


def _entities(text: str) -> list[tuple[str, str]]:
    """(entity_type, entity_value) pairs named in the text.

    A value gets its most specific type only: `lsass.exe` is a process, and
    emitting it again as a domain produced a phantom DNS lookup in every check
    that consumes entities. The first matching pattern in ``_ENTITY_PATTERNS``
    is the most specific one, so the first type to claim a value keeps it.
    """
    out: list[tuple[str, str]] = []
    claimed: set[str] = set()
    for etype, pat in _ENTITY_PATTERNS:
        for m in pat.finditer(text or ""):
            val = next((g for g in m.groups() if g), None)
            if val is None:
                continue
            val = val.strip().strip('".,;')
            if len(val) < 3:
                continue
            key = val.lower()
            if key in claimed:
                continue
            if etype == "domain":
                last = key.rsplit(".", 1)[-1]
                if last in _NOT_A_DOMAIN:
                    continue
                # A bare filename with a known extension is a file, not a host.
                if "." in key[:-len(last) - 1] and last not in _TLDS:
                    continue
            claimed.add(key)
            out.append((etype, key))
    return out


def _entity_in_blob(entity: str, blob: str) -> bool:
    """True when ``blob`` (the finding's own evidence rows, lowercased) names
    ``entity`` — including the FQDN / short-name pair.

    WO-R2F item 7 (D47): "an FQDN matches its short name when the index holds
    both forms." A finding written as ``ws01.cadre.local`` against rows that
    say ``ws01`` (and the reverse) was flagged as unsupported, which is a false
    positive on the exact lab data this product runs against. The equivalence
    is deliberately narrow: only the left-most label of a multi-label domain
    participates, and only in this direction, so a check that previously failed
    on a genuinely absent host still fails.
    """
    if not entity or not blob:
        return False
    if entity in blob:
        return True
    if "." not in entity:
        # Short name written in the finding, FQDN in the rows.
        return re.search(rf"\b{re.escape(entity)}\.[A-Za-z]{{2,}}\b", blob) is not None
    # FQDN written in the finding, short name in the rows. `ws01.cadre.local`
    # matches rows naming `ws01`; `a.b.corp.local` matches rows naming `a`.
    short = entity.split(".", 1)[0]
    if short and len(short) >= 3:
        return re.search(rf"\b{re.escape(short)}\b", blob) is not None
    return False


def _audit_ids(claim: dict[str, Any]) -> list[str]:
    raw = claim.get("audit_ids") or claim.get("audit_id") or []
    if isinstance(raw, str):
        raw = [raw]
    out = [str(x).strip() for x in raw if str(x).strip()]
    for art in claim.get("artifacts") or ():
        if isinstance(art, dict):
            v = _norm(art.get("audit_id"))
            if v:
                out.append(v)
        elif isinstance(art, str) and art.strip():
            out.append(art.strip())
    seen: set[str] = set()
    uniq = []
    for a in out:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return uniq


def _kind_for(claim: dict[str, Any]) -> str:
    k = _norm(claim.get("claim_kind")).lower()
    if k in _CLAIM_KINDS:
        return k
    text = f"{_norm(claim.get('title'))} {_norm(claim.get('text'))}".lower()
    if re.search(r"\b(?:persist|service|schtask|run\s*key|startup|autorun)", text):
        return "persistence"
    if re.search(r"\b(?:connect|domain|dns|http|url|beacon|c2|ip\b)", text):
        return "network"
    if re.search(r"\b(?:before|after|during|timeline|sequence|then|later)\b", text):
        return "temporal"
    if re.search(r"\b(?:because|indicat|suggests|likely|conclusion|impact)\b", text):
        return "interpretation"
    return "observation"


def _claim_from_finding(mode: str, f: dict[str, Any]) -> list[dict[str, Any]]:
    """Project one finding into claim rows (one per named entity)."""
    text = " ".join(
        _norm(f.get(k)) for k in ("title", "description", "rationale", "interpretation", "claim")
    )
    entities = _entities(text)
    if not entities:
        # A finding that names no entity still asserts something; key it on the
        # title so two modes can still be compared on it.
        t = _norm(f.get("title"))
        if t:
            entities = [("finding", t.lower()[:80])]
    pol = _polarity(f.get("polarity") or f.get("status_reason") or text)
    ids = _audit_ids(f)
    kind = _kind_for(f)
    return [
        {
            "mode": mode,
            "source": f"finding:{_norm(f.get('id')) or '?'}",
            "key": [etype, evalue, kind],
            "polarity": pol,
            "audit_ids": ids,
            "title": _norm(f.get("title"))[:160],
            "confidence": f.get("confidence"),
        }
        for etype, evalue in entities
    ]


def _claims_from_run(mode: str, record: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cand in record.get("candidates") or ():
        if not isinstance(cand, dict):
            continue
        rows.extend(_claim_from_finding(mode, cand))
    for v in record.get("verdicts") or ():
        if not isinstance(v, dict):
            continue
        rows.extend(_claim_from_finding(mode, {**v, "polarity": v.get("verdict")}))
    return rows


def _stored_mode(case_dir: Path) -> str:
    """The case's canonical product mode ("1"/"2"/"3"), legacy aliases resolved.

    WO-12: findings.json used to be labelled mode "1" unconditionally, so a
    Mode 2/3 case compared its own staged findings against its own run records
    as if two modes disagreed. The stored mode (CASE.yaml) is the truth.
    """
    import yaml

    from nexus.langgraph.mode_mapping import resolve_stored_mode

    meta: dict[str, Any] = {}
    y = case_dir / "CASE.yaml"
    if y.is_file():
        try:
            loaded = yaml.safe_load(y.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                meta = loaded
        except (OSError, ValueError):
            meta = {}
    resolved = resolve_stored_mode(
        meta.get("investigation_mode"), meta.get("mode_scheme")
    )
    return str(resolved) if resolved in (1, 2, 3) else "1"


def collect_mode_claims(case_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """Gather claim rows per product mode from a case's own artifacts.

    Reads what the case actually produced: ``findings.json`` for the mode the
    case was created in (CASE.yaml; WO-12), and the ``analysis/mode2_runs`` /
    ``analysis/mode3_runs`` records for agent runs. A mode with no artifact
    contributes nothing and is reported as ``unknown``.
    """
    case_dir = Path(case_dir)
    by_mode: dict[str, list[dict[str, Any]]] = {"1": [], "2": [], "3": []}

    fp = case_dir / "findings.json"
    if fp.is_file():
        try:
            findings = json.loads(fp.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            findings = []
        if isinstance(findings, list):
            stored = _stored_mode(case_dir)
            for f in findings:
                if isinstance(f, dict):
                    by_mode[stored].extend(_claim_from_finding(stored, f))

    for mode, sub in (("2", "mode2_runs"), ("3", "mode3_runs")):
        d = case_dir / "analysis" / sub
        if not d.is_dir():
            continue
        for rec in sorted(d.glob("*.json")):
            try:
                loaded = json.loads(rec.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(loaded, dict):
                by_mode[mode].extend(_claims_from_run(mode, loaded))
    return by_mode


# Phrasings a tool or index actually emits when a query found nothing. These
# are deliberately not word-bounded on the right: the real strings are "no
# matching records", "0 hits", "no results", and a trailing \b after "match"
# fails on "matching".
_DENIAL_PHRASES = (
    re.compile(r"\bno\s+match\w*", re.I),
    re.compile(r"\bnot\s+found", re.I),
    re.compile(r"\bno\s+(?:results?|hits?|records?|rows?|entries)\b", re.I),
    re.compile(r"\b0\s+(?:results?|hits?|records?|rows?|matches|count)\b", re.I),
    re.compile(r"\btotal\s*[:=]\s*0\b", re.I),
    re.compile(r"\bcount\s*[:=]\s*0\b", re.I),
    re.compile(r"\babsent\b", re.I),
    re.compile(r"\bdid\s+not\s+(?:occur|execute|run|appear)", re.I),
    re.compile(r"\bempty\s+result", re.I),
)


def _rows_deny(rows_text: str, entity: str) -> bool:
    """The indexed rows mention the entity only inside a denial."""
    if not entity or not rows_text:
        return False
    low = rows_text.lower()
    needle = entity.lower()
    if needle not in low:
        return False
    for m in re.finditer(re.escape(needle), low):
        window = low[max(0, m.start() - 120): m.end() + 120]
        if any(p.search(window) for p in _DENIAL_PHRASES):
            return True
    return False


def check_cross_mode(
    case_dir: Path | None = None,
    *,
    claims_by_mode: dict[str, list[dict[str, Any]]] | None = None,
    rows_text: str | None = None,
) -> dict[str, Any]:
    """Compare modes and report shared conclusions and contradictions."""
    if claims_by_mode is None:
        if case_dir is None:
            raise ValueError("case_dir or claims_by_mode is required")
        claims_by_mode = collect_mode_claims(case_dir)
    claims_by_mode = {m: list(v or []) for m, v in claims_by_mode.items()}

    present = [m for m, rows in claims_by_mode.items() if rows]
    missing = [m for m in ("1", "2", "3") if not claims_by_mode.get(m)]

    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for rows in claims_by_mode.values():
        for row in rows:
            key = tuple(row["key"])
            if all(key):
                grouped.setdefault(key, []).append(row)

    shared: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []
    entity_sets: dict[str, set[str]] = {m: set() for m in claims_by_mode}

    for key, rows in sorted(grouped.items()):
        modes = sorted({r["mode"] for r in rows})
        for r in rows:
            entity_sets[r["mode"]].add(key[1])
        polarities = {r["polarity"] for r in rows}
        if len(modes) >= 2 and len(polarities) > 1:
            by_pol: dict[str, list[dict[str, Any]]] = {}
            for r in rows:
                by_pol.setdefault(r["polarity"], []).append(r)
            affirm = by_pol.get("affirm") or []
            deny = by_pol.get("deny") or []
            contradictions.append({
                "key": {"entity_type": key[0], "entity_value": key[1], "claim_kind": key[2]},
                "modes": modes,
                "affirms": [
                    {"mode": r["mode"], "source": r["source"], "title": r["title"],
                     "audit_ids": r["audit_ids"]}
                    for r in affirm
                ],
                "denials": [
                    {"mode": r["mode"], "source": r["source"], "title": r["title"],
                     "audit_ids": r["audit_ids"]}
                    for r in deny
                ],
                "why": "the same entity and claim kind is asserted and denied",
            })
        elif len(modes) >= 2:
            shared.append({
                "key": {"entity_type": key[0], "entity_value": key[1], "claim_kind": key[2]},
                "modes": modes,
                "polarity": rows[0]["polarity"],
                "audit_ids": sorted({a for r in rows for a in r["audit_ids"]})[:12],
            })

    # The "what the rows deny" half: an affirmed claim whose entity appears in
    # the indexed rows only inside a denial.
    row_conflicts: list[dict[str, Any]] = []
    if rows_text:
        for key, rows in sorted(grouped.items()):
            for r in rows:
                if r["polarity"] != "affirm" or not r["audit_ids"]:
                    continue
                if _rows_deny(rows_text, key[1]):
                    row_conflicts.append({
                        "key": {"entity_type": key[0], "entity_value": key[1],
                                "claim_kind": key[2]},
                        "mode": r["mode"], "source": r["source"], "title": r["title"],
                        "audit_ids": r["audit_ids"],
                        "why": "the cited rows mention this entity only in a denial",
                    })

    total = sum(len(v) for v in claims_by_mode.values())
    # Do the modes name anything in common at all? Computed from the entity sets
    # rather than the Jaccard dict, which is filled in below.
    shared_entities = set()
    seen_sets = [s for s in entity_sets.values() if s]
    for i, a in enumerate(seen_sets):
        for b in seen_sets[i + 1:]:
            shared_entities |= a & b

    # A contradiction outranks an absent mode. Reporting "incomplete" while a
    # real contradiction is on the table would hide the defect behind a gap in
    # coverage, which is exactly what this check exists to prevent.
    if contradictions or row_conflicts:
        verdict = "contradictory"
    elif missing and present:
        verdict = "incomplete"
    elif not present:
        verdict = "unknown"
    elif not shared_entities and len(present) >= 2:
        # Zero overlap with no contradiction is NOT agreement. It means the modes
        # share no comparable vocabulary, so there was nothing for them to agree
        # or disagree about. Calling that "consistent" is false assurance - the
        # strongest honest statement is that the comparison established nothing.
        # This is the real corpus result: three modes over 81,115 indexed rows
        # named not one entity in common.
        verdict = "disjoint"
    else:
        verdict = "consistent"

    jaccard: dict[str, float] = {}
    pairs = [("1", "2"), ("1", "3"), ("2", "3")]
    for a, b in pairs:
        ea, eb = entity_sets.get(a, set()), entity_sets.get(b, set())
        union = ea | eb
        jaccard[f"{a}-{b}"] = round(len(ea & eb) / len(union), 3) if union else 0.0

    return {
        "modes_present": [MODES.get(m, m) for m in present],
        "modes_missing": [MODES.get(m, m) for m in missing],
        "verdict": verdict,
        "scope": "intra-case",
        "claim_rows": total,
        "shared_entities": sorted(shared_entities)[:40],
        "entity_overlap": jaccard,
        "shared": shared,
        "contradictions": contradictions,
        "row_contradictions": row_conflicts,
        "counts": {
            "shared": len(shared),
            "contradictions": len(contradictions),
            "row_contradictions": len(row_conflicts),
        },
    }


def _evidence_sha_set(case_dir: Path) -> frozenset[str]:
    """Registered evidence SHA-256 set for a case (SQLite system of record)."""
    import contextlib

    from nexus.case.evidence_service import list_evidence

    out: set[str] = set()
    with contextlib.suppress(Exception):
        for e in list_evidence(Path(case_dir)):
            h = str(e.get("sha256") or "").strip().lower()
            if h:
                out.add(h)
    return frozenset(out)


def sibling_cases(
    case_dir: Path | str, *, cases_root: Path | str | None = None
) -> list[Path]:
    """Cases whose registered evidence SHA-256 set is identical to this one.

    WO-12: sibling discovery needs no new intake field - a case is a sibling
    of another when they were registered on the same evidence bytes. An empty
    evidence set has no siblings (nothing to prove the grouping with).
    """
    import contextlib

    from nexus.config import settings

    case_dir = Path(case_dir)
    target = _evidence_sha_set(case_dir)
    if not target:
        return []
    root = Path(cases_root) if cases_root else Path(settings.cases_root)
    out: list[Path] = []
    with contextlib.suppress(OSError):
        for d in sorted(root.glob("CASE-*")):
            if (
                d.is_dir()
                and d.resolve() != case_dir.resolve()
                and _evidence_sha_set(d) == target
            ):
                out.append(d)
    return out


def check_cross_mode_group(case_dirs: list[Path | str]) -> dict[str, Any]:
    """Compare sibling cases across their stored modes (WO-12).

    Each case contributes its own claims under the mode that produced them, so
    a contradiction means two cases disagree - not one case against itself.
    Same-mode siblings merge into one bucket (their outputs are the same
    product). The result keeps the dispute-key vocabulary of the single-case
    check.
    """
    dirs = [Path(d) for d in case_dirs]
    combined: dict[str, list[dict[str, Any]]] = {"1": [], "2": [], "3": []}
    cases: list[dict[str, str]] = []
    for d in dirs:
        stored = _stored_mode(d)
        cases.append({"case_id": d.name, "mode": stored})
        for rows in collect_mode_claims(d).values():
            for r in rows:
                combined.setdefault(r["mode"], []).append(r)
    result = check_cross_mode(claims_by_mode=combined)
    result["scope"] = "group"
    result["cases"] = cases
    return result


def render_consistency_markdown(result: dict[str, Any]) -> str:
    if not result:
        return ""
    v = str(result.get("verdict") or "unknown").upper()
    scope = str(result.get("scope") or "intra-case")
    if scope == "group":
        out = [
            "## Cross-case consistency (siblings)",
            "",
            f"**Verdict: {v}**",
            "",
            "Sibling cases (identical registered evidence) compared across their "
            "stored modes.",
            "",
        ]
    else:
        out = [
            "## Intra-case consistency",
            "",
            f"**Verdict: {v}**",
            "",
            "This case's own artifacts, compared across the runs it holds; sibling "
            "cases are compared with `nexus cross-mode CASE-A CASE-B CASE-C`.",
            "",
        ]
    if v == "DISJOINT":
        out += [
            "The modes named **no entity in common**, so this comparison establishes "
            "nothing: there was no shared subject for them to agree or disagree "
            "about. That is not agreement, and it is not a clean bill of health.",
        ]
    if result.get("modes_missing"):
        out += [
            f"- Not run: {', '.join(result['modes_missing'])} - absence is not agreement.",
        ]
    c = result.get("counts") or {}
    out += [
        f"- Claim rows compared: {result.get('claim_rows', 0)}",
        f"- Shared conclusions: {c.get('shared', 0)}",
        f"- Contradictions: {c.get('contradictions', 0)}",
        f"- Contradicted by cited rows: {c.get('row_contradictions', 0)}",
    ]
    ov = result.get("entity_overlap") or {}
    if ov:
        out += ["", "**Entity overlap (Jaccard)**", ""]
        out += [f"- {k}: {v}" for k, v in sorted(ov.items())]
    for title, key in (("Contradictions", "contradictions"),
                       ("Claims contradicted by their own cited rows", "row_contradictions")):
        rows = result.get(key) or []
        if not rows:
            continue
        out += ["", f"**{title}**", ""]
        for r in rows:
            k = r["key"]
            out.append(
                f"- `{k['entity_value']}` ({k['entity_type']}/{k['claim_kind']}) - {r['why']}"
            )
            for side in ("affirms", "denials"):
                for c2 in r.get(side) or ():
                    out.append(
                        f"    - {c2['mode']} {c2['source']}: {c2['title']}"
                        f" {('audit_ids=' + ', '.join(c2['audit_ids'][:4])) if c2['audit_ids'] else '(no audit ids)'}"
                    )
            if r.get("mode"):
                out.append(f"    - {r['mode']} {r['source']}: {r['title']} "
                           f"audit_ids={', '.join(r['audit_ids'][:4])}")
    out.append("")
    return "\n".join(out)


def write_consistency(case_dir: Path, result: dict[str, Any]) -> Path:
    case_dir = Path(case_dir)
    target = case_dir / "analysis"
    target.mkdir(parents=True, exist_ok=True)
    out = target / "cross_mode.json"
    tmp = out.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    tmp.replace(out)
    return out
