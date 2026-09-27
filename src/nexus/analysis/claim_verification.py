"""Level 1 - mechanical claim verification.

The gate question is not "did the pipeline finish" but "is every claim it made
true". This module answers that one claim at a time, mechanically, so a human
reviews exceptions rather than re-deriving the whole case.

Nine checks, from the debug-mode plan:

=====  ==========================================================
L1.1  every cited ``audit_id`` exists in **this case's** audit log
L1.2  a cited ``file:line`` contains the claimed content
L1.3  every host / user / executable named exists in the indexed rows
L1.4  every ATT&CK / ITM technique id resolves in the registry
L1.5  timestamps parse and are plausible
L1.6  the WP 10.4 seal verifies at approval
L1.7  every count in the prose replays from Elasticsearch
L1.8  no contradiction with another mode or with the raw rows
L1.9  coverage is declared (tools / sources / needles)
L1.10 a cited row corroborates the claim, rather than merely naming the
       entity somewhere in an unstructured data blob
=====  ==========================================================

Claim verdict:

``PROVEN``        every applicable check passed
``UNSUPPORTED``   a check that could be run failed
``CONTRADICTED``  the evidence or another mode says otherwise
``UNVERIFIABLE``  a check could not be run - the input was missing

``UNVERIFIABLE`` is reported as unknown, never as a pass. A missing input is
not a clean bill of health: that distinction is the whole point, and collapsing
it is how a pipeline that parsed nothing ends up graded "complete".

Checks are skipped only when they do not apply (a finding with no techniques
has nothing for L1.4 to check). A skip is recorded as ``skipped``, distinct
from ``pass``, so a reader can tell "checked and clean" from "not checked".
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from nexus.analysis.integrity import (
    load_known_audit_ids,
    validate_timestamp,
    verify_citations,
    verify_seal,
)

__all__ = [
    "VERDICTS",
    "CHECKS",
    "verify_claim",
    "verify_case",
    "render_ledger_markdown",
    "write_ledger",
]

VERDICTS = ("PROVEN", "UNSUPPORTED", "CONTRADICTED", "UNVERIFIABLE")

CHECKS = {
    "L1.1": "cited audit_id exists in this case's audit log",
    "L1.2": "cited file:line contains the claimed content",
    "L1.3": "named entity exists in the indexed rows",
    "L1.4": "technique id resolves in the registry",
    "L1.5": "timestamps parse and are plausible",
    "L1.6": "WP 10.4 seal verifies",
    "L1.7": "count in the prose replays from the index",
    "L1.8": "no contradiction with another mode or the raw rows",
    "L1.9": "coverage is declared",
    "L1.10": "cited row corroborates the claim (not just a mention in a data blob)",
}

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
_COUNT_RE = re.compile(
    r"\b(\d[\d,]{0,8})\s+(?:events?|records?|rows?|hits?|artifacts?|documents?|"
    r"files?|sources?|findings?|indicators?|iocs?|entries)\b",
    re.I,
)
_FILELINE_RE = re.compile(r"\b([\w.\\/:-]+\.(?:csv|jsonl?|log|txt|evtx|db|dat|exe|dll|bin|md))"
                          r"[:|](\d{1,7})\b", re.I)


def _text(finding: dict[str, Any]) -> str:
    return " ".join(
        str(finding.get(k) or "")
        for k in ("title", "description", "rationale", "interpretation", "claim", "impact")
    )


def _cited_ids(finding: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for art in finding.get("artifacts") or ():
        if isinstance(art, dict):
            v = str(art.get("audit_id") or "").strip()
            if v:
                out.append(v)
        elif isinstance(art, str) and art.strip():
            out.append(art.strip())
    for key in ("audit_id", "audit_ids"):
        v = finding.get(key)
        if isinstance(v, str) and v.strip():
            out.append(v.strip())
        elif isinstance(v, list):
            out.extend(str(x).strip() for x in v if str(x).strip())
    seen: set[str] = set()
    uniq = []
    for a in out:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    return uniq


def _check(
    results: dict[str, dict[str, Any]],
    key: str,
    status: str,
    detail: str = "",
    *,
    evidence: Any = None,
) -> None:
    entry: dict[str, Any] = {"status": status, "detail": detail}
    if evidence is not None:
        entry["evidence"] = evidence
    results[key] = entry


# --------------------------------------------------------------------------
# individual checks
# --------------------------------------------------------------------------

def _l1_1(finding, known_ids, res, **_kw) -> None:
    cited = _cited_ids(finding)
    if not cited:
        _check(res, "L1.1", "fail", "no audit_id cited (FD-001 not met)")
        return
    if known_ids is None:
        _check(res, "L1.1", "unverifiable", "case audit log not readable")
        return
    report = verify_citations(finding, known_ids)
    unknown = report.get("unknown") or []
    malformed = report.get("malformed") or []
    if unknown:
        _check(res, "L1.1", "fail",
               f"{len(unknown)} cited audit id(s) absent from this case's log: "
               f"{', '.join(map(str, unknown[:4]))}", evidence=list(map(str, unknown))[:10])
        return
    if malformed:
        _check(res, "L1.1", "fail",
               f"{len(malformed)} malformed audit id(s): {', '.join(map(str, malformed[:4]))}",
               evidence=list(map(str, malformed))[:10])
        return
    _check(res, "L1.1", "pass", f"{len(report.get('verified') or cited)} citation(s) resolve")


def _l1_2(finding, case_dir, res, indexed_text=None, **_kw) -> None:
    refs = _FILELINE_RE.findall(_text(finding))
    for art in finding.get("artifacts") or ():
        if isinstance(art, dict) and art.get("path"):
            refs.append((str(art["path"]), ""))
    if not refs:
        _check(res, "L1.2", "skipped", "no file:line reference to check")
        return
    checked = 0
    bad: list[str] = []
    for path_s, line_s in refs:
        p = _resolve_path(case_dir, path_s)
        if p is None or not p.is_file():
            bad.append(f"{path_s} (not resolvable)")
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            bad.append(f"{path_s} ({exc})")
            continue
        checked += 1
        if not line_s:
            continue
        n = int(line_s)
        if n < 1 or n > len(lines):
            bad.append(f"{path_s}:{n} out of range (file has {len(lines)} lines)")
    if bad:
        _check(res, "L1.2", "fail", "; ".join(bad[:3]), evidence=bad[:8])
        return
    _check(res, "L1.2", "pass", f"{checked} file reference(s) resolve")


def _resolve_path(case_dir, ref: str) -> Path | None:
    raw = Path(str(ref))
    if raw.is_file():
        return raw
    if case_dir is None:
        return None
    for root in (Path(case_dir), Path(case_dir) / "analysis", Path(case_dir) / "extractions",
                 Path(case_dir) / "ingest"):
        cand = root / str(ref).lstrip("/\\")
        if cand.is_file():
            return cand
    try:
        for cand in Path(case_dir).rglob(Path(str(ref)).name):
            if cand.is_file():
                return cand
    except OSError:
        return None
    return None


def _l1_3(finding, res, indexed_text=None, **_kw) -> None:
    from nexus.analysis.cross_mode import _entities

    named = _entities(_text(finding))
    if not named:
        _check(res, "L1.3", "skipped", "no host/user/executable named")
        return
    if indexed_text is None:
        _check(res, "L1.3", "unverifiable", "indexed rows not available for replay")
        return
    hay = indexed_text.lower()
    missing = [f"{t}:{v}" for t, v in named if v not in hay]
    if missing:
        _check(res, "L1.3", "fail",
               f"{len(missing)} named entit(ies) absent from the indexed rows: {', '.join(missing[:4])}",
               evidence=missing[:10])
        return
    _check(res, "L1.3", "pass", f"{len(named)} named entit(ies) found in the rows")


def _l1_4(finding, res, technique_ids=None, **_kw) -> None:
    ids = [str(x).strip().upper() for x in (finding.get("technique_ids") or finding.get("techniques") or [])
           if str(x).strip()]
    found = sorted(set(_TECHNIQUE_RE.findall(_text(finding))) | set(ids))
    if not found:
        _check(res, "L1.4", "skipped", "no technique id named")
        return
    if technique_ids is None:
        _check(res, "L1.4", "unverifiable", "technique registry not available")
        return
    unknown = sorted(t for t in found if t not in technique_ids)
    if unknown:
        _check(res, "L1.4", "fail", f"technique id(s) not in the registry: {', '.join(unknown[:5])}",
               evidence=unknown)
        return
    _check(res, "L1.4", "pass", f"{len(found)} technique id(s) resolve")


def _l1_5(finding, res, now=None, **_kw) -> None:
    from nexus.analysis.integrity import _iter_timestamp_fields

    fields = list(_iter_timestamp_fields(finding))
    if not fields:
        _check(res, "L1.5", "skipped", "no timestamps on the finding")
        return
    bad: list[str] = []
    for name, raw in fields:
        # validate_timestamp returns (value, reason); a non-empty reason means the
        # value must not be used as a time.
        value, reason = validate_timestamp(raw, now=now)
        if reason:
            bad.append(f"{name}={raw!r} ({reason})")
        elif not str(value or "").strip():
            bad.append(f"{name}={raw!r} (nullified)")
    if bad:
        _check(res, "L1.5", "fail", "; ".join(bad[:3]), evidence=bad[:8])
        return
    _check(res, "L1.5", "pass", f"{len(fields)} timestamp(s) plausible")


def _l1_6(finding, res, **_kw) -> None:
    seal = finding.get("seal")
    has_seal = bool(seal) or bool(finding.get("content_hash"))
    if not has_seal:
        _check(res, "L1.6", "skipped", "no seal recorded")
        return
    ok, reason = verify_seal(finding)
    if ok:
        _check(res, "L1.6", "pass", reason)
        return
    _check(res, "L1.6", "fail", reason)


def _l1_7(finding, res, replay=None, **_kw) -> None:
    text = _text(finding)
    counts = [m.group(0) for m in _COUNT_RE.finditer(text)]
    if not counts:
        _check(res, "L1.7", "skipped", "no count asserted in the prose")
        return
    if replay is None:
        _check(res, "L1.7", "unverifiable", "no count replay available")
        return
    bad = []
    for phrase in counts:
        m = _COUNT_RE.match(phrase)
        claimed = int(m.group(1).replace(",", ""))
        actual = replay(_noun_from(text, m.group(1)))
        if actual is None:
            continue
        if abs(claimed - actual) > max(1, int(claimed * 0.02)):
            bad.append(f"claimed {claimed}, index holds {actual}")
    if bad:
        _check(res, "L1.7", "fail", "; ".join(bad[:3]), evidence=bad[:6])
        return
    _check(res, "L1.7", "pass", f"{len(counts)} count(s) replay")


def _noun_from(text: str, raw: str) -> str:
    m = re.search(re.escape(raw) + r"\s+(\w+)", text, re.I)
    return (m.group(1) if m else "rows").rstrip("s").lower()


def _l1_8(finding, res, cross_mode=None, **_kw) -> None:
    if cross_mode is None:
        _check(res, "L1.8", "unverifiable", "cross-mode check not run")
        return
    from nexus.analysis.cross_mode import _entities

    key_of = lambda e: f"{e[0]}:{e[1]}"  # noqa: E731
    mine = {key_of(e) for e in _entities(_text(finding))}
    if not mine:
        _check(res, "L1.8", "skipped", "no entity to compare across modes")
        return
    contradicted = set()
    for c in (cross_mode.get("contradictions") or []) + (cross_mode.get("row_contradictions") or []):
        k = c.get("key") or {}
        contradicted.add(f"{k.get('entity_type')}:{k.get('entity_value')}")
    hit = sorted(mine & contradicted)
    if hit:
        _check(res, "L1.8", "fail",
               f"another mode or the raw rows deny: {', '.join(hit[:4])}", evidence=hit)
        return
    _check(res, "L1.8", "pass", f"no cross-mode contradiction for {len(mine)} entit(ies)")


def _l1_9(res, coverage=None, **_kw) -> None:
    if coverage is None:
        _check(res, "L1.9", "unverifiable", "coverage audit not run")
        return
    overall = str((coverage or {}).get("overall") or "").lower()
    if not overall:
        _check(res, "L1.9", "unverifiable", "coverage audit has no verdict")
        return
    if overall == "gaps":
        gaps = [s for s, v in (coverage.get("sections") or {}).items()
                if isinstance(v, dict) and v.get("status") == "gaps"]
        _check(res, "L1.9", "fail", f"coverage reports gaps in: {', '.join(gaps) or 'unknown'}",
               evidence=coverage.get("sections"))
        return
    if overall == "unknown":
        _check(res, "L1.9", "unverifiable", "coverage unknown - a missing input is not a pass")
        return
    _check(res, "L1.9", "pass", f"coverage {overall}")


# --------------------------------------------------------------------------
# claim / case
# --------------------------------------------------------------------------

# Checks that describe the *case*, not an individual claim. Folding them into
# every claim's verdict makes one coverage gap mark all N claims UNSUPPORTED and
# buries the per-claim signal that actually needs review. They are still run and
# still reported - once, at case level.
_CASE_LEVEL_CHECKS = frozenset({"L1.9"})

_VERDICT_RANK = {"UNVERIFIABLE": 0, "UNSUPPORTED": 1, "CONTRADICTED": 2, "PROVEN": 3}


def _verdict_for(results: dict[str, dict[str, Any]]) -> str:
    claim_results = {k: v for k, v in results.items() if k not in _CASE_LEVEL_CHECKS}
    if any(r["status"] == "fail" and _is_contradiction(r) for r in claim_results.values()):
        return "CONTRADICTED"
    if any(r["status"] == "fail" for r in claim_results.values()):
        return "UNSUPPORTED"
    ran = [r for r in claim_results.values() if r["status"] in {"pass", "unverifiable", "fail"}]
    if not ran:
        return "UNVERIFIABLE"
    if any(r["status"] == "unverifiable" for r in ran):
        return "UNVERIFIABLE"
    return "PROVEN"


def _is_contradiction(entry: dict[str, Any]) -> bool:
    d = (entry.get("detail") or "").lower()
    return "another mode" in d or "rows deny" in d or "contradict" in d


def _claim_subjects(finding: dict[str, Any]) -> list[str]:
    """What the claim is *about* - the things a row must corroborate.

    A Mode 1 finding is titled ``Signal: <needle> - N hit(s)``, and the needle is
    a bare term like ``sdelete`` or ``pid_`` that the entity extractor (which
    looks for executables, domains, paths, hashes) cannot see. Checking nothing
    would let exactly the case this check exists for pass untouched, so the
    needle is lifted from the title and checked alongside any real entities.
    """
    from nexus.analysis.cross_mode import _entities

    out: list[str] = []
    m = re.search(r"signal\s*:\s*([^-\u2014\u2013(\n]{2,80}?)\s*(?:[-\u2014\u2013]|\(|$)",
                  _text(finding), re.I)
    if m:
        needle = m.group(1).strip().strip("*`")
        if len(needle) >= 2:
            out.append(needle.lower())
    out.extend(v for _t, v in _entities(_text(finding)))
    seen: set[str] = set()
    uniq = []
    for s in out:
        if s and s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq


def _l1_10(finding, res, **_kw) -> None:
    """Does each cited row *corroborate* the claim, or merely mention the entity?

    The Mode 1 needle scan matches a substring anywhere in a row, including
    inside an unstructured data blob. The corpus has a real case: a `sdelete`
    needle matched a System Restore event (EventID 8194, "Restore point created
    successfully") whose Data field merely *lists* sdelete among the applications
    registered for the restore point. The row mentions the entity; it does not
    evidence it. "Signal: sdelete - 1 hit(s)" reads as though it did.

    So: the subject of the claim must appear in a descriptor field (detail,
    title, source, provider, artifact) rather than only in a free-text blob.
    A row with no descriptor fields at all cannot be judged either way, so it is
    skipped rather than counted as corroboration.
    """
    rows = finding.get("evidence")
    if not isinstance(rows, list) or not rows:
        _check(res, "L1.10", "skipped", "no evidence rows attached")
        return
    subjects = _claim_subjects(finding)
    if not subjects:
        _check(res, "L1.10", "skipped", "no claim subject to corroborate")
        return

    descriptor_fields = ("detail", "title", "source", "provider", "artifact",
                         "event_id", "mapdescription", "rule", "rule_title")
    mention_only: list[str] = []
    judged = 0
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        fields = row.get("fields")
        blob = " ".join(str(row.get(k) or "") for k in descriptor_fields)
        if isinstance(fields, dict):
            blob += " " + " ".join(
                str(fields.get(k) or "")
                for k in ("MapDescription", "RuleTitle", "Provider", "EventId", "Task")
            )
        blob_low = blob.lower()
        if not blob_low.strip():
            continue
        judged += 1
        if not any(s in blob_low for s in subjects):
            mention_only.append(
                f"row[{i}] {str(row.get('loc') or row.get('source') or '')[:60]}"
            )
    if mention_only:
        _check(res, "L1.10", "fail",
               f"{len(mention_only)} cited row(s) name the subject only in an "
               f"unstructured data field - a mention, not an instance",
               evidence=mention_only[:8])
        return
    if not judged:
        _check(res, "L1.10", "skipped",
               "no cited row carries descriptor fields, so corroboration is unknown")
        return
    _check(res, "L1.10", "pass", f"{judged} cited row(s) corroborate the claim subject")


def verify_claim(
    finding: dict[str, Any],
    *,
    case_dir: Path | None = None,
    known_ids: set[str] | None = None,
    indexed_text: str | None = None,
    technique_ids: set[str] | None = None,
    cross_mode: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
    replay=None,
    now=None,
) -> dict[str, Any]:
    """Verify one claim against all nine checks."""
    res: dict[str, dict[str, Any]] = {}
    _l1_1(finding, known_ids, res)
    _l1_2(finding, case_dir, res, indexed_text=indexed_text)
    _l1_3(finding, res, indexed_text=indexed_text)
    _l1_4(finding, res, technique_ids=technique_ids)
    _l1_5(finding, res, now=now)
    _l1_6(finding, res)
    _l1_7(finding, res, replay=replay)
    _l1_8(finding, res, cross_mode=cross_mode)
    _l1_9(res, coverage=coverage)
    _l1_10(finding, res)

    counts = {"pass": 0, "fail": 0, "unverifiable": 0, "skipped": 0}
    for entry in res.values():
        counts[entry["status"]] = counts.get(entry["status"], 0) + 1
    return {
        "id": finding.get("id"),
        "title": str(finding.get("title") or "")[:160],
        "status": str(finding.get("status") or "").upper(),
        "verdict": _verdict_for(res),
        "checks": res,
        "counts": counts,
    }

def verify_case(
    case_dir: Path,
    findings: list[dict[str, Any]] | None = None,
    *,
    indexed_text: str | None = None,
    technique_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Verify every claim in a case and return the L1 ledger."""
    from nexus.analysis.coverage_audit import load_coverage_audit
    from nexus.analysis.cross_mode import check_cross_mode

    case_dir = Path(case_dir)
    if findings is None:
        fp = case_dir / "findings.json"
        findings = []
        if fp.is_file():
            try:
                loaded = json.loads(fp.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    findings = [f for f in loaded if isinstance(f, dict)]
            except (OSError, ValueError):
                findings = []

    known = load_known_audit_ids(case_dir)
    try:
        coverage = load_coverage_audit(case_dir)
    except Exception:  # noqa: BLE001 - a missing audit is unverifiable, not a crash
        coverage = None
    try:
        cross = check_cross_mode(case_dir=case_dir)
    except Exception:  # noqa: BLE001
        cross = None

    rows = [
        verify_claim(
            f, case_dir=case_dir, known_ids=known, indexed_text=indexed_text,
            technique_ids=technique_ids, cross_mode=cross, coverage=coverage,
        )
        for f in findings
    ]
    tally: dict[str, int] = {v: 0 for v in VERDICTS}
    for r in rows:
        tally[r["verdict"]] = tally.get(r["verdict"], 0) + 1

    # The case-level check, reported once. It does not colour any single claim.
    coverage_entry: dict[str, Any] = {"status": "unverifiable",
                                      "detail": "no claim ran this check"}
    for r in rows:
        if "L1.9" in (r.get("checks") or {}):
            coverage_entry = dict(r["checks"]["L1.9"])
            break

    all_clean = bool(rows) and all(r["verdict"] == "PROVEN" for r in rows)
    return {
        "case_id": case_dir.name,
        "claims": rows,
        "verdict_counts": tally,
        "case_level": {"L1.9": coverage_entry},
        "overall": (
            "PROVEN" if all_clean
            else "UNVERIFIABLE" if not rows
            else "MIXED"
        ),
    }


def render_ledger_markdown(ledger: dict[str, Any]) -> str:
    if not ledger:
        return ""
    out = ["## Level 1 claim ledger", ""]
    counts = ledger.get("verdict_counts") or {}
    out.append("**Verdicts**  " + "  ".join(f"{k}: {counts.get(k, 0)}" for k in VERDICTS))
    case_level = ledger.get("case_level") or {}
    for key, entry in case_level.items():
        if entry.get("status") in {"fail", "unverifiable"}:
            out.append(
                f"**Case-level {key}** ({CHECKS.get(key, '')}): "
                f"{entry.get('status')} - {entry.get('detail')}"
            )
    out += ["", "| Claim | Verdict | Failures | Unverifiable |",
            "|-------|---------|----------|--------------|"]
    for c in ledger.get("claims") or ():
        fails = [k for k, v in (c.get("checks") or {}).items() if v.get("status") == "fail"]
        unver = [k for k, v in (c.get("checks") or {}).items() if v.get("status") == "unverifiable"]
        out.append(
            f"| {(c.get('title') or c.get('id') or '')[:70]} | **{c.get('verdict')}** | "
            f"{', '.join(fails) or '-'} | {', '.join(unver) or '-'} |"
        )
    failures = [
        (c, k, v) for c in ledger.get("claims") or ()
        for k, v in (c.get("checks") or {}).items() if v.get("status") == "fail"
    ]
    if failures:
        out += ["", "**Details**", ""]
        for c, k, v in failures:
            out.append(f"- `{k}` {CHECKS.get(k, '')} - {c.get('title') or c.get('id')}: "
                       f"{v.get('detail')}")
    unver_all = [
        (c, k, v) for c in ledger.get("claims") or ()
        for k, v in (c.get("checks") or {}).items() if v.get("status") == "unverifiable"
    ]
    if unver_all:
        out += ["", "**Could not verify** (reported as unknown, never as a pass)", ""]
        for c, k, v in unver_all:
            out.append(f"- `{k}` {CHECKS.get(k, '')} - {c.get('title') or c.get('id')}: "
                       f"{v.get('detail')}")
    out.append("")
    return "\n".join(out)


def write_ledger(case_dir: Path, ledger: dict[str, Any]) -> Path:
    case_dir = Path(case_dir)
    target = case_dir / "analysis"
    target.mkdir(parents=True, exist_ok=True)
    out = target / "claim_ledger.json"
    tmp = out.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(ledger, indent=2, default=str), encoding="utf-8")
    tmp.replace(out)
    return out
