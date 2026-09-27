"""WP 10.0a - report quality classifier.

Grades the *generated report*, not just the findings. A case can stage five
well-cited findings and still produce a report that overclaims its scope, hides
its limitations, or asserts a conclusion no row supports. That failure is
invisible to the findings list, so the report needs its own grader.

Seven axes, each 0-5:

==========================  ==========================================
Axis                        What a low score means
==========================  ==========================================
``analytical_soundness``     restatement, not analysis; severity not
                            proportionate to the evidence
``scope_honesty``           implies whole-host scope from a handful of
                            registered files, or omits what was excluded
``limitations``             no statement of caps, gaps or unparsed
                            families; the reader cannot tell what the
                            report does not cover
``structure``               not navigable: no headings, no per-finding
                            block, findings run together
``actionability``           no next step, no remediation, nothing the
                            reader can act on
``non_fabrication``         cites a tool call that does not exist, or
                            asserts an entity with no supporting row
``traceability``            findings do not resolve to audit_ids or
                            evidence rows
==========================  ==========================================

Report class, worst-wins:

``F`` Misleading - a fabricated citation, or a claim the evidence denies
``D`` Unsupported - claims that carry no artifacts
``C`` Indicative - artifacts support the claims but scope/limitations are
   absent or the scope is overstated
``B`` Sound - artifacts support the claims and limitations are stated
``A`` Defensible - B, plus full traceability, coverage ``ok``/``gaps`` with
   no uncited-source gap, and no fabricated entity

Per-finding class reuses the Mode 2/3 verifier vocabulary so an agent verdict
and an expert verdict are comparable: ``CONFIRMED`` / ``INDICATED`` /
``REFUTED`` / ``UNRESOLVED``.

The grade is a pure function of its inputs. Grading the same report twice must
return the same object - that is the acceptance criterion, and it is why
nothing here calls a model. An LLM grader would grade a report differently on
every pass, which makes a gate meaningless.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

__all__ = [
    "AXES",
    "REPORT_CLASSES",
    "FINDING_CLASSES",
    "classify_finding",
    "grade_report",
    "render_grade_markdown",
    "write_grade",
]

# Axis id -> (label, what earns a high score)
AXES: dict[str, str] = {
    "analytical_soundness": "Analytical soundness",
    "scope_honesty": "Scope honesty",
    "limitations": "Limitations",
    "structure": "Structure",
    "actionability": "Actionability",
    "non_fabrication": "Non-fabrication",
    "traceability": "Traceability",
}

# Report class -> (label, one-line meaning)
REPORT_CLASSES: dict[str, str] = {
    "A": "Defensible",
    "B": "Sound",
    "C": "Indicative",
    "D": "Unsupported",
    "F": "Misleading",
}

FINDING_CLASSES = ("CONFIRMED", "INDICATED", "REFUTED", "UNRESOLVED")

_MAX = 5

# Language that asserts more than the artifact set can carry. Each pattern is
# (regex, axis_penalised, points). A report carrying these without a scope
# statement is the classic overclaim and drops the class to C or below.
_OVERCLAIM: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"\bproves?\b", re.I), 1),
    (re.compile(r"\bconfirms?\s+(?:that\s+)?(?:the\s+)?(?:attacker|adversary|intruder)\b", re.I), 1),
    (re.compile(r"\b(?:definitely|certainly|undoubtedly|unquestionably)\b", re.I), 1),
    (re.compile(r"\bfully\s+(?:determined|established|reconstructed)\b", re.I), 1),
    (re.compile(r"\bcomplete\s+(?:picture|timeline|account)\b", re.I), 1),
    (re.compile(r"\bno\s+other\s+(?:activity|artifacts?|evidence)\b", re.I), 1),
    (re.compile(r"\b(?:all|every)\s+(?:activity|execution|artifact)\s+(?:was|is)\s+(?:captured|accounted|covered)\b", re.I), 1),
    (re.compile(r"\bruled\s+out\b", re.I), 1),
)

# Sections that disclose limits. Matched against headings, so a report needs a
# real section, not an apology buried in a paragraph.
_LIMITATION_HEADINGS = (
    "limitation", "caveat", "scope", "coverage", "not examined", "out of scope",
    "what this report does not", "gaps", "unparsed", "constraints",
)
_NEGATIVE_FINDINGS_HEADINGS = ("negative finding", "not found", "no findings", "unresolved")

_ACTION_MARKERS = (
    "next step", "next steps", "recommend", "remediat", "contain", "remediate",
    "action:", "actions:", "mitigat", "should be", "must be", "isolate", "preserve",
)
_SCOPE_MARKERS = (
    "registered", "examined", "analysis of", "evidence set", "artifact count",
    "files were", "sources:", "this report covers", "scope of", "input",
)

_CITATION_RE = re.compile(r"\baudit[_-]?id\b|\bnx-[0-9a-f]{8,}\b|\bnexus-[0-9a-f]{8,}\b", re.I)
_ROW_REF_RE = re.compile(r"\b[\w./\\-]+\.(?:csv|jsonl?|log|txt|evtx|db|dat|exe|dll|bin)\b", re.I)


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _headings(markdown: str) -> list[str]:
    return [
        line.lstrip("#").strip().lower()
        for line in markdown.splitlines()
        if line.lstrip().startswith("#")
    ]


def _has_limitations(markdown: str) -> bool:
    return any(
        any(marker in h for marker in _LIMITATION_HEADINGS)
        for h in _headings(markdown)
    )


def _states_scope(markdown: str) -> bool:
    body = markdown.lower()
    if any(marker in body for marker in _SCOPE_MARKERS):
        return True
    # An explicit count of what was ingested is scope, stated as a number.
    return bool(re.search(r"\b\d+\s+(?:files?|artifacts?|sources?|families|records?|events?)\b", body))


def _mentions_partial_processing(markdown: str) -> bool:
    body = markdown.lower()
    return any(
        m in body
        for m in (
            "unparsed", "not parsed", "not examined", "no parser", "skipped",
            "unsupported format", "could not be parsed", "parse failure",
            "discovery", "no tool", "unrouted",
        )
    )


def _collect_audit_ids(findings: Iterable[dict[str, Any]]) -> set[str]:
    ids: set[str] = set()
    for f in findings or ():
        for key in ("audit_id", "audit_ids"):
            v = f.get(key)
            if isinstance(v, str) and v.strip():
                ids.add(v.strip())
            elif isinstance(v, list):
                ids.update(str(x).strip() for x in v if str(x).strip())
        for art in f.get("artifacts") or ():
            if isinstance(art, dict):
                v = _norm(art.get("audit_id"))
                if v:
                    ids.add(v)
            elif isinstance(art, str) and art.strip():
                ids.add(art.strip())
    return ids


def _artifact_sources(f: dict[str, Any]) -> set[str]:
    """Distinct evidence sources a finding rests on (FD-006 corroboration)."""
    out: set[str] = set()
    for art in f.get("artifacts") or ():
        if isinstance(art, dict):
            for key in ("source", "family", "artifact", "file", "path", "tool"):
                v = _norm(art.get(key))
                if v:
                    out.add(v.lower())
        elif isinstance(art, str) and art.strip():
            out.add(art.strip().lower())
    for key in ("sources", "families", "source", "family"):
        v = f.get(key)
        if isinstance(v, list):
            out.update(str(x).strip().lower() for x in v if str(x).strip())
        elif isinstance(v, str) and v.strip():
            out.add(v.strip().lower())
    return out


def classify_finding(
    finding: dict[str, Any],
    *,
    known_audit_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Classify one finding: CONFIRMED / INDICATED / REFUTED / UNRESOLVED.

    ``known_audit_ids`` is the set of audit ids that actually exist in the case
    audit log. Passing it turns an invented citation into a REFUTED rather than a
    silent pass; omitting it grades the finding on its own merits.
    """
    f = finding or {}
    cited = _collect_audit_ids([f])
    sources = _artifact_sources(f)

    # An explicit verifier refutation wins over everything else.
    for key in ("verdict", "verification", "verifier_verdict", "refutation"):
        v = _norm(f.get(key)).lower()
        if v in {"refuted", "rejected", "contradicted", "false"}:
            return {
                "id": f.get("id"), "class": "REFUTED",
                "why": f"verifier recorded '{_norm(f.get(key))}'",
                "cited_audit_ids": sorted(cited), "sources": sorted(sources),
            }
    if f.get("refuted") is True:
        return {
            "id": f.get("id"), "class": "REFUTED",
            "why": "finding carries a refutation flag",
            "cited_audit_ids": sorted(cited), "sources": sorted(sources),
        }

    if known_audit_ids is not None:
        invented = sorted(a for a in cited if a not in known_audit_ids)
        if invented:
            return {
                "id": f.get("id"), "class": "REFUTED",
                "why": f"cites audit id(s) absent from the case audit log: {', '.join(invented[:4])}",
                "cited_audit_ids": sorted(cited), "sources": sorted(sources),
                "invented_audit_ids": invented,
            }

    if not cited and not sources:
        return {
            "id": f.get("id"), "class": "UNRESOLVED",
            "why": "no artifacts and no audit ids (FD-001 not met)",
            "cited_audit_ids": [], "sources": [],
        }
    if len(sources) >= 2 or len(cited) >= 2:
        return {
            "id": f.get("id"), "class": "CONFIRMED",
            "why": f"{len(sources)} artifact source(s), {len(cited)} audit id(s)",
            "cited_audit_ids": sorted(cited), "sources": sorted(sources),
        }
    return {
        "id": f.get("id"), "class": "INDICATED",
        "why": f"{len(sources) or 1} artifact source, no corroboration (FD-006)",
        "cited_audit_ids": sorted(cited), "sources": sorted(sources),
    }


def _score_axes(
    *,
    markdown: str,
    findings: list[dict[str, Any]],
    known_audit_ids: set[str] | None,
    coverage: dict[str, Any] | None,
    evidence_count: int,
) -> tuple[dict[str, int], list[str]]:
    """Score the seven axes. Returns (scores, reasons_why_not_higher)."""
    body = markdown
    lower = body.lower()
    heads = _headings(body)
    notes: list[str] = []

    n_findings = len(findings)
    has_limitations = _has_limitations(body)
    has_scope = _states_scope(body)

    # --- non_fabrication -------------------------------------------------
    # A citation that does not exist is a hard defect, not a deduction.
    fabricated: list[str] = []
    if known_audit_ids is not None:
        for aid in sorted(_collect_audit_ids(findings)):
            if aid not in known_audit_ids:
                fabricated.append(aid)
    overclaims = [p.pattern for p, _ in _OVERCLAIM if p.search(body)]
    nf = _MAX
    if fabricated:
        nf = 0
        notes.append(f"non_fabrication: {len(fabricated)} cited audit id(s) do not exist")
    elif len(overclaims) >= 3:
        nf = 1
        notes.append("non_fabrication: repeated overclaiming language")
    elif overclaims:
        nf = 3
        notes.append(f"non_fabrication: {len(overclaims)} overclaiming phrase(s)")

    # --- traceability ----------------------------------------------------
    per_finding = sum(1 for f in findings if _collect_audit_ids([f]))
    tr = 0 if n_findings == 0 else int(round(_MAX * per_finding / n_findings))
    tr = max(tr, 2 if _CITATION_RE.search(body) else 0)
    if tr < _MAX:
        notes.append(f"traceability: {per_finding}/{n_findings} findings carry audit ids")
    elif n_findings == 0:
        notes.append("traceability: no findings to trace")

    # --- analytical_soundness -------------------------------------------
    if n_findings == 0:
        as_ = 0
        notes.append("analytical_soundness: report asserts nothing")
    else:
        as_ = 2
        # Severity proportionate to evidence, and a stated reasoning step.
        evidenced = sum(1 for f in findings if _artifact_sources(f) or _collect_audit_ids([f]))
        ratio = evidenced / n_findings
        as_ = min(_MAX, 1 + int(round(4 * ratio)))
        if re.search(r"\b(?:because|indicat\w+|consistent with|therefore|which suggests|based on)\b", lower):
            as_ = min(_MAX, as_ + 1)
        if as_ < _MAX:
            notes.append(f"analytical_soundness: {evidenced}/{n_findings} findings rest on artifacts")

    # --- scope_honesty ----------------------------------------------------
    sh = 0
    if has_scope:
        sh = 3
    if has_scope and _mentions_partial_processing(body):
        sh = _MAX
    if evidence_count and has_scope:
        m = re.search(r"\b(\d+)\s+(?:files?|artifacts?|sources?|families)\b", lower)
        if m and abs(int(m.group(1)) - evidence_count) > max(3, evidence_count // 2):
            sh = min(sh, 2)
            notes.append(
                f"scope_honesty: report states {m.group(1)} source(s); {evidence_count} were registered"
            )
    if sh < _MAX:
        notes.append("scope_honesty: the report does not say what was and was not examined")

    # --- limitations ------------------------------------------------------
    lim = 0
    if has_limitations:
        lim = 3
        if _mentions_partial_processing(body):
            lim = _MAX
    if lim < _MAX:
        notes.append("limitations: no section stating gaps, caps or unparsed evidence")

    # --- structure -------------------------------------------------------
    if n_findings and len(heads) >= 4:
        st = 5
    elif len(heads) >= 3:
        st = 3
    else:
        st = 1
    if st < _MAX:
        notes.append(f"structure: {len(heads)} heading(s) for {n_findings} finding(s)")

    # --- actionability ---------------------------------------------------
    hits = sum(1 for m in _ACTION_MARKERS if m in lower)
    ac = 0 if n_findings == 0 else min(_MAX, hits * 2)
    if ac < _MAX:
        notes.append("actionability: no next step or remediation guidance")

    return {
        "analytical_soundness": max(0, min(_MAX, as_)),
        "scope_honesty": max(0, min(_MAX, sh)),
        "limitations": max(0, min(_MAX, lim)),
        "structure": max(0, min(_MAX, st)),
        "actionability": max(0, min(_MAX, ac)),
        "non_fabrication": max(0, min(_MAX, nf)),
        "traceability": max(0, min(_MAX, tr)),
    }, notes


def _class_for(scores: dict[str, int], *, n_findings: int, coverage: dict[str, Any] | None) -> str:
    """Worst-wins class from the axis scores plus the hard gates.

    Only the *evidence* axes can demote a report to D. ``structure`` and
    ``actionability`` are craft: a beautifully written report whose claims
    carry no artifacts is still Unsupported, and a thin report whose claims are
    well-grounded is not. Craft caps the ceiling at B, it does not decide the
    floor.
    """
    if scores["non_fabrication"] == 0:
        return "F"                       # a fabricated citation is Misleading
    if n_findings == 0:
        return "D"                       # nothing asserted, nothing supported
    if scores["traceability"] <= 1 or scores["analytical_soundness"] <= 1:
        return "D"
    if scores["scope_honesty"] < _MAX or scores["limitations"] < _MAX:
        return "C"

    # Reaching A needs full craft as well as full evidence discipline.
    if sum(scores.values()) < 30:
        return "B"
    # A defensible report also has nothing the coverage audit calls a gap in the
    # sources it relied on. A missing input stays `unknown`, which is not a pass.
    src = ((coverage or {}).get("sources") or {})
    if src.get("status") in {"gaps"} or (src and src.get("status") not in {"ok", None}):
        return "B"
    return "A"


def grade_report(
    *,
    markdown: str,
    findings: list[dict[str, Any]] | None = None,
    known_audit_ids: set[str] | None = None,
    coverage: dict[str, Any] | None = None,
    evidence_count: int | None = None,
    case_id: str = "",
) -> dict[str, Any]:
    """Grade a rendered report. Pure function: same inputs, same output."""
    md = markdown or ""
    fs = [f for f in (findings or ()) if isinstance(f, dict)]
    ec = int(evidence_count or 0)

    scores, notes = _score_axes(
        markdown=md, findings=fs, known_audit_ids=known_audit_ids,
        coverage=coverage, evidence_count=ec,
    )
    finding_classes = [classify_finding(f, known_audit_ids=known_audit_ids) for f in fs]
    n = len(fs)
    cls = _class_for(scores, n_findings=n, coverage=coverage)

    total = sum(scores.values())
    by_class: dict[str, int] = {}
    for fc in finding_classes:
        by_class[fc["class"]] = by_class.get(fc["class"], 0) + 1

    return {
        "case_id": case_id,
        "report_class": cls,
        "report_class_label": REPORT_CLASSES[cls],
        "axes": {k: {"label": AXES[k], "score": v, "max": _MAX} for k, v in scores.items()},
        "total": total,
        "max_total": _MAX * len(AXES),
        "findings_total": n,
        "finding_classes": finding_classes,
        "finding_class_counts": by_class,
        "why_not_higher": notes,
    }


def render_grade_markdown(grade: dict[str, Any]) -> str:
    """The REPORT.md section."""
    if not grade:
        return ""
    cls = str(grade.get("report_class") or "?")
    label = REPORT_CLASSES.get(cls, "?")
    out = [
        "## Report quality grade",
        "",
        f"**Class {cls} - {label}**  "
        f"(total {grade.get('total', 0)}/{grade.get('max_total', 0)} across "
        f"{len(grade.get('axes') or {})} axes)",
        "",
        "| Axis | Score |",
        "|------|-------|",
    ]
    for key, a in (grade.get("axes") or {}).items():
        out.append(f"| {a.get('label', key)} | {a.get('score', 0)}/{a.get('max', 5)} |")
    counts = grade.get("finding_class_counts") or {}
    if counts:
        out += ["", "**Findings**"]
        for c in FINDING_CLASSES:
            if counts.get(c):
                out.append(f"- {c}: {counts[c]}")
    if grade.get("why_not_higher"):
        out += ["", "**Why not higher**", ""]
        out += [f"- {n}" for n in grade["why_not_higher"]]
    out.append("")
    return "\n".join(out)


def write_grade(case_dir: Path, grade: dict[str, Any]) -> Path:
    """Persist to ``analysis/report_grade.json`` (atomic)."""
    case_dir = Path(case_dir)
    target = case_dir / "analysis"
    target.mkdir(parents=True, exist_ok=True)
    out = target / "report_grade.json"
    tmp = out.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(grade, indent=2, default=str), encoding="utf-8")
    tmp.replace(out)
    return out
