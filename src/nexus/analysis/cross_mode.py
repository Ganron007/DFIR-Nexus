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
    "render_consistency_markdown",
    "write_consistency",
]

# Canonical product mode -> the labels a case may record.
MODES: dict[str, str] = {"1": "Mode 1 (LLM)", "2": "Mode 2 (multi-role)", "3": "Mode 3 (multi-agent)"}

# Polarity vocabulary, aligned with the multi-agent board.
_AFFIRM = {"affirm", "true", "present", "executed", "occurred", "yes", "support", "supports"}
_DENY = {"deny", "false", "absent", "not_executed", "did_not_occur", "no", "refute", "refutes", "contradicts"}

_ENTITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("process", re.compile(r"\b([A-Za-z0-9_.\-]{3,}\.exe)\b", re.I)),
    ("domain", re.compile(r"\b((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b", re.I)),
    ("ipv4", re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")),
    ("sha256", re.compile(r"\b([0-9a-f]{64})\b", re.I)),
    ("sha1", re.compile(r"\b([0-9a-f]{40})\b", re.I)),
    ("registry_key", re.compile(r"\b((?:HKEY_[A-Z_]+|HKLM|HKCU|HKU|Software)\\[^\s,;\"']{3,})", re.I)),
    ("user", re.compile(r"\b([A-Za-z0-9._\-]{2,}\\Users\\[A-Za-z0-9._\-]+)\b", re.I)),
    ("file", re.compile(r"\b([A-Za-z]:\\[^\s,;\"'<>|]{4,}|[^\s,;\"']{3,}\\(?:\d{4}\.[A-Za-z]{2,3}))\b")),
    ("url", re.compile(r"\b(https?://[^\s,;\"'<>]{6,})", re.I)),
)

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
    """(entity_type, entity_value) pairs named in the text."""
    out: list[tuple[str, str]] = []
    for etype, pat in _ENTITY_PATTERNS:
        for m in pat.finditer(text or ""):
            val = m.group(1).strip().strip('".,;')
            if len(val) < 3:
                continue
            out.append((etype, val.lower()))
    # Stable dedupe, deterministic order.
    seen: set[tuple[str, str]] = set()
    uniq: list[tuple[str, str]] = []
    for pair in out:
        if pair not in seen:
            seen.add(pair)
            uniq.append(pair)
    return uniq


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


def collect_mode_claims(case_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """Gather claim rows per product mode from a case's own artifacts.

    Reads what the case actually produced: ``findings.json`` for the mode the
    case was created in, and the ``analysis/mode2_runs`` / ``analysis/mode3_runs``
    records for agent runs. A mode with no artifact contributes nothing and is
    reported as ``unknown``.
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
            for f in findings:
                if isinstance(f, dict):
                    by_mode["1"].extend(_claim_from_finding("1", f))

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
    # A contradiction outranks an absent mode. Reporting "incomplete" while a
    # real contradiction is on the table would hide the defect behind a gap in
    # coverage, which is exactly what this check exists to prevent.
    if contradictions or row_conflicts:
        verdict = "contradictory"
    elif missing and present:
        verdict = "incomplete"
    elif present:
        verdict = "consistent"
    else:
        verdict = "unknown"

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
        "claim_rows": total,
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


def render_consistency_markdown(result: dict[str, Any]) -> str:
    if not result:
        return ""
    v = str(result.get("verdict") or "unknown").upper()
    out = ["## Cross-mode consistency", "", f"**Verdict: {v}**", ""]
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
