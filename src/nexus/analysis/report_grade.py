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

WO-11: the class cannot outrun the L1 ledger or a live contradiction. The caps
are applied after the axis scores, and the reason is surfaced in the grade
section and in ``why_not_higher``:

- **A** requires the ledger overall ``PROVEN`` (no ``UNSUPPORTED`` /
  ``UNVERIFIABLE`` / ``CONTRADICTED`` claim) and **zero** unresolved
  contradictions.
- any ``UNSUPPORTED`` or ``UNVERIFIABLE`` claim -> max **B**;
  ``UNSUPPORTED`` > 25 % of claims -> max **C**.
- any ``CONTRADICTED`` claim, or an unresolved contradiction -> max **D**
  (surfaced; an unsurfaced contradiction still grades F via non_fabrication).

Thresholds are a proposal - tune them here, in one place.
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

# Language that asserts more than the artifact set can carry.
#
# Two things are deliberately NOT here. A bare "prove(s)" is not an overclaim
# signal: this corpus writes "the current evidence only proves a Winlogon-to-LSA
# registration", "the cluster is insufficient to prove phishing delivery", "map
# the hypothesis to the event IDs that prove it", "Failures prove spoofing" and
# "**Interpretation** Prove what was deleted, when, and by which path". Those
# are limitations, methodology and general rules - scoring them as overclaims
# penalises the report for writing correctly, and an axis that fires on good
# writing is worse than a slightly weaker axis. Invented entities and invented
# counts are already caught mechanically by L1.1 and L1.3.
#
# So the list holds only phrases that are overclaiming *about this case*, and
# only count when no negation or limiting word shares the sentence.
_OVERCLAIM: tuple[tuple[re.Pattern[str], int], ...] = (
    (re.compile(r"\bconfirms?\s+(?:that\s+)?(?:the\s+)?(?:attacker|adversary|intruder)\b", re.I), 1),
    (re.compile(r"\b(?:definitely|certainly|undoubtedly|unquestionably)\b", re.I), 1),
    (re.compile(r"\bfully\s+(?:determined|established|reconstructed)\b", re.I), 1),
    (re.compile(r"\bcomplete\s+(?:picture|timeline|account)\b", re.I), 1),
    (re.compile(r"\bno\s+other\s+(?:activity|artifacts?|evidence)\b", re.I), 1),
    (re.compile(r"\b(?:all|every)\s+(?:activity|execution|artifact)\s+(?:was|is)\s+(?:captured|accounted|covered)\b", re.I), 1),
    (re.compile(r"\bruled\s+out\b", re.I), 1),
    (re.compile(r"\b(?:establishes|establish)\s+(?:that\s+)?(?:the\s+)?"
                r"(?:attacker|adversary|intruder|compromise|breach)\s+(?:occurred|happened|took\s+place)\b", re.I), 1),
)

# A hedge or negation in the same sentence makes the statement a claim about the
# *limits* of the evidence, which is exactly what a defensible report does.
_HEDGE = re.compile(
    r"\b(?:only|just|merely|not|no|never|cannot|can\s+not|does\s+not|doesn't|do\s+not|don't|"
    r"did\s+not|didn't|is\s+not|isn't|was\s+not|wasn't|were\s+not|weren't|"
    r"insufficient|unable|fails?\s+to|nothing\s+in|absent|without)\b",
    re.I,
)

# Knowledge-base statistics are not evidence-scope claims. The corpus prints
# "1160 capa-YARA rules (50 families)" in its ATT&CK/MBC reference block; reading
# that as the report's evidence scope accuses a report of overstating a scope
# it never claimed - which is what the first graded run of this corpus did.
_SCOPE_COUNT_CONTEXT = re.compile(
    r"(?:evidence\s+registry|registry\s+size|registered\s+items?|files?\s+(?:were|was)\s+"
    r"(?:registered|examined|collected|analyzed|analysed|ingested)|evidence\s+set|"
    r"artifact\s+count|sources?\s*:|this\s+report\s+covers|scope\s+of|"
    r"\bparsed\b|\bingested\b|\bexamined\b|\bregistered\b)",
    re.I,
)
# Nouns that are inventory of the *knowledge base*, not of the case.
_KB_COUNT_NOUNS = re.compile(
    r"\b(?:techniques?|mitigations?|behaviors?|methods?|rules?|case\s+studies|"
    r"detections?|signatures|queries|indicators?\s+in\s+the\s+corpus)\b",
    re.I,
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

# A title that names the machine rather than the finding. The Mode 1 scribe emits
# "Signal: <needle> - N hit(s) across <family>", so a report of these is an
# inventory of search terms, not a set of conclusions.
_MACHINE_TITLE_RE = re.compile(
    r"^\s*signal\s*:", re.I
)
# A bare needle: no spaces, no verb, no conclusion - `sdelete`, `pid_`, `vid_`,
# `usbstor`, `onedrive`. Truncated needles keep a trailing underscore.
_BARE_NEEDLE_RE = re.compile(r"^[A-Za-z0-9_.\-]{2,24}$")
# Words that make a title a statement rather than a label.
_PROSE_TITLE_RE = re.compile(
    r"\b(?:executed|ran|created|modified|deleted|dropped|persisted|connected|"
    r"downloaded|registered|scheduled|injected|accessed|attempted|succeeded|"
    r"failed|contains|shows|indicates|was|were|has|had|is|are|after|before|"
    r"while|during|without|despite|following|via|through)\b",
    re.I,
)


def _is_machine_title(title: str) -> bool:
    """True when a finding title is a search term or rule id, not a conclusion."""
    t = (title or "").strip()
    if not t:
        return False
    if _PROSE_TITLE_RE.search(t):
        return False
    if _MACHINE_TITLE_RE.match(t):
        return True
    # "Signal: sdelete - 1 hit(s) across evtxecmd" is caught above; a bare
    # needle with no prose is the same problem in a different wrapper.
    return bool(_BARE_NEEDLE_RE.match(t))


def _norm(value: Any) -> str:
    return str(value or "").strip()


def _sentences(markdown: str) -> list[str]:
    """Sentence-ish units, so a hedge elsewhere in the line does not hide a claim."""
    out: list[str] = []
    for raw in markdown.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("|"):
            continue
        for part in re.split(r"(?<=[.;!?])\s+", line):
            part = part.strip()
            if part:
                out.append(part)
    return out


def _unhedged_overclaims(markdown: str) -> list[str]:
    """Overclaim phrases with no negation or limiting word in the same sentence."""
    hits: list[str] = []
    for sentence in _sentences(markdown):
        if _HEDGE.search(sentence):
            continue
        for pattern, _points in _OVERCLAIM:
            if pattern.search(sentence):
                hits.append(pattern.pattern)
    return hits


def _scope_count_claims(markdown: str) -> list[tuple[int, str]]:
    """Numbers asserted as *this case's* evidence scope.

    Only counted inside a sentence that actually talks about the evidence set.
    A number elsewhere - a knowledge-base statistic, a byte size, a count of
    samples - says nothing about scope, and treating it as a scope claim
    manufactures an inconsistency that is not there.
    """
    out: list[tuple[int, str]] = []
    for sentence in _sentences(markdown):
        if not _SCOPE_COUNT_CONTEXT.search(sentence):
            continue
        for m in re.finditer(
            r"\b(\d[\d,]{0,8})\s+([a-z]+(?:s|es)?)\b", sentence, re.I
        ):
            # "EventID 4611 row", "Event ID 4624 record": an identifier, not a
            # count. The corpus is full of them, and reading one as a scope
            # claim is how a 22-file case got accused of claiming 4611 sources.
            before = sentence[max(0, m.start() - 24):m.start()]
            if re.search(r"(?:event\s*id|eventid|\bid|\bcode|\bopcode|\bsid|"
                         r"\b4624|\b4625|\b4648|\b4672|\b4673)\s*[:=]?\s*$",
                         before, re.I):
                continue
            noun = m.group(2).lower()
            if not re.match(
                r"^(source|file|artifact|evidence|record|event|row|hit|item|"
                r"entry|document|log|registry|signal|finding)", noun
            ):
                continue
            if _KB_COUNT_NOUNS.search(noun):
                continue
            try:
                out.append((int(m.group(1).replace(",", "")), noun))
            except ValueError:
                continue
    return out


def _strip_appended_sections(markdown: str) -> str:
    """Drop the grade / ledger / cross-mode blocks this tool appends.

    Grading a report that already carries a grade must grade the same document:
    otherwise the grader reads its own note ("report states 50 source(s)") as
    evidence, and re-grading is not idempotent.
    """
    cut = len(markdown)
    for heading in ("## Report quality grade", "## Level 1 claim ledger",
                    "## Cross-mode consistency"):
        i = markdown.find(heading)
        if i > 0:
            cut = min(cut, i)
    return markdown[:cut]


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
    overclaims = _unhedged_overclaims(body)
    nf = _MAX
    if fabricated:
        nf = 0
        notes.append(f"non_fabrication: {len(fabricated)} cited audit id(s) do not exist")
    elif len(overclaims) >= 3:
        nf = 1
        notes.append("non_fabrication: repeated unhedged overclaiming language")
    elif overclaims:
        nf = 3
        notes.append(f"non_fabrication: {len(overclaims)} unhedged overclaiming phrase(s)")

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
    if evidence_count:
        for claimed, noun in _scope_count_claims(body):
            if abs(claimed - evidence_count) > max(3, evidence_count // 2):
                sh = min(sh, 2)
                notes.append(
                    f"scope_honesty: the report states {claimed} {noun}(s) "
                    f"were examined; {evidence_count} were registered"
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
    # Structure is navigable but unreadable when every heading is a machine
    # identifier. The Mode 1 scribe titles a finding after the needle that
    # matched, so a whole report can come out as "Signal: pid_ - 2+ hit(s)",
    # perfectly navigable and useless to the responder reading it.
    raw = [f for f in findings if _is_machine_title(str(f.get("title") or ""))]
    if raw and n_findings:
        st = max(1, st - (2 if len(raw) == n_findings else 1))
        notes.append(
            f"structure: {len(raw)}/{n_findings} finding title(s) are raw needle or "
            f"rule identifiers rather than analyst-readable conclusions"
        )
    if st < _MAX and not raw:
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


_L1_CAP_ORDER = ("F", "D", "C", "B", "A")  # worst -> best


def _cap_with_l1(
    cls: str, *, ledger: dict[str, Any] | None, contradictions: int
) -> tuple[str, dict[str, Any] | None]:
    """WO-11: the class cannot outrun the L1 ledger or a live contradiction.

    Thresholds live in the module docstring; tune them here, in one place.
    """
    if not ledger and not contradictions:
        return cls, None
    counts = dict((ledger or {}).get("verdict_counts") or {})
    if not counts:
        for row in (ledger or {}).get("claims") or ():
            v = str((row or {}).get("verdict") or "")
            if v:
                counts[v] = counts.get(v, 0) + 1
    unsupported = int(counts.get("UNSUPPORTED") or 0)
    unverifiable = int(counts.get("UNVERIFIABLE") or 0)
    contradicted = int(counts.get("CONTRADICTED") or 0)
    total = sum(int(v or 0) for v in counts.values())
    overall = str((ledger or {}).get("overall") or "").upper()

    cap = ""
    reason = ""
    if contradicted or contradictions:
        cap = "D"
        reason = (
            f"{contradicted} CONTRADICTED claim(s)"
            if contradicted
            else f"{contradictions} unresolved contradiction(s)"
        )
    elif unsupported and total and unsupported / total > 0.25:
        cap = "C"
        reason = f"{unsupported} UNSUPPORTED of {total} claim(s)"
    elif unsupported or unverifiable:
        cap = "B"
        parts = []
        if unsupported:
            parts.append(f"{unsupported} UNSUPPORTED")
        if unverifiable:
            parts.append(f"{unverifiable} UNVERIFIABLE")
        reason = f"{' and '.join(parts)} claim(s) of {total or '?'}"
    elif ledger and overall != "PROVEN":
        cap = "B"
        reason = f"L1 overall {overall or 'UNVERIFIABLE'}"
    if not cap or _L1_CAP_ORDER.index(cap) >= _L1_CAP_ORDER.index(cls):
        return cls, None
    return cap, {"cap": cap, "reason": reason}


def grade_report(
    *,
    markdown: str,
    findings: list[dict[str, Any]] | None = None,
    known_audit_ids: set[str] | None = None,
    coverage: dict[str, Any] | None = None,
    evidence_count: int | None = None,
    case_id: str = "",
    l1_ledger: dict[str, Any] | None = None,
    contradictions: int = 0,
) -> dict[str, Any]:
    """Grade a rendered report. Pure function: same inputs, same output.

    ``l1_ledger`` (``verify_case`` output) and ``contradictions`` (unresolved
    cross-mode + row contradictions) cap the class; see the module docstring.
    """
    md = _strip_appended_sections(markdown or "")
    fs = [f for f in (findings or ()) if isinstance(f, dict)]
    ec = int(evidence_count or 0)

    scores, notes = _score_axes(
        markdown=md, findings=fs, known_audit_ids=known_audit_ids,
        coverage=coverage, evidence_count=ec,
    )
    finding_classes = [classify_finding(f, known_audit_ids=known_audit_ids) for f in fs]
    n = len(fs)
    cls = _class_for(scores, n_findings=n, coverage=coverage)
    cls, l1_cap = _cap_with_l1(cls, ledger=l1_ledger, contradictions=contradictions)
    if l1_cap:
        notes.append(
            f"L1 ledger caps the class at {l1_cap['cap']}: {l1_cap['reason']}"
        )

    total = sum(scores.values())
    by_class: dict[str, int] = {}
    for fc in finding_classes:
        by_class[fc["class"]] = by_class.get(fc["class"], 0) + 1

    return {
        "case_id": case_id,
        "report_class": cls,
        "report_class_label": REPORT_CLASSES[cls],
        "l1_cap": l1_cap,
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
    ]
    cap = grade.get("l1_cap") or {}
    if cap:
        out.append(
            f"**Capped at {cap.get('cap')}**: {cap.get('reason')} "
            "(L1 ledger / contradictions)"
        )
    out += [
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
