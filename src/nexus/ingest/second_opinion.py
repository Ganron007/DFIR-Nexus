"""Second-LLM opinion reconciliation — deterministic disagreement surfacing.

Takes two sets of findings (produced by different LLM models or analyst
sessions) and surfaces:

- Findings present only in A or only in B
- Severity mismatches for overlapping findings
- MITRE technique IDs added or removed between the two sets

Matching is done by finding title similarity (normalised lowercase) with an
optional explicit ``finding_id`` override when callers supply stable IDs.

Pure/deterministic — no AI calls, no network I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any

from nexus.ingest.schemas import Severity

# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _normalise_title(title: str) -> str:
    """Lowercase, collapse whitespace, strip punctuation for fuzzy matching."""
    t = title.lower().strip()
    t = re.sub(r"[^\w\s]", " ", t)
    t = re.sub(r"\s+", " ", t)
    return t.strip()


def _titles_match(a: str, b: str, threshold: float = 0.75) -> bool:
    """Return True if two titles are similar enough to be the same finding."""
    na, nb = _normalise_title(a), _normalise_title(b)
    if na == nb:
        return True
    return SequenceMatcher(None, na, nb).ratio() >= threshold


# Severity ranking (higher index = more severe)
_SEVERITY_RANK: dict[str, int] = {
    Severity.INFORMATIONAL.value: 0,
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}


class DisagreementType:
    """Constants for disagreement kinds."""
    ONLY_IN_A = "only_in_a"
    ONLY_IN_B = "only_in_b"
    SEVERITY_MISMATCH = "severity_mismatch"
    MITRE_ADDED = "mitre_added"
    MITRE_REMOVED = "mitre_removed"


@dataclass
class Disagreement:
    """A single disagreement between two finding sets."""
    kind: str
    title: str
    detail: str
    finding_a: dict[str, Any] | None = None
    finding_b: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "title": self.title,
            "detail": self.detail,
            "finding_a": self.finding_a,
            "finding_b": self.finding_b,
        }


@dataclass
class ReconciliationResult:
    """Full output of reconciling two finding sets."""
    disagreements: list[Disagreement] = field(default_factory=list)
    matched_count: int = 0
    only_in_a_count: int = 0
    only_in_b_count: int = 0

    @property
    def total_disagreements(self) -> int:
        return len(self.disagreements)

    @property
    def agreement_count(self) -> int:
        """Number of matched findings with no severity or MITRE disagreements."""
        mismatched_titles = {d.title for d in self.disagreements if d.kind in {
            DisagreementType.SEVERITY_MISMATCH,
            DisagreementType.MITRE_ADDED,
            DisagreementType.MITRE_REMOVED,
        }}
        return max(0, self.matched_count - len(mismatched_titles))

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_disagreements": self.total_disagreements,
            "matched_count": self.matched_count,
            "only_in_a_count": self.only_in_a_count,
            "only_in_b_count": self.only_in_b_count,
            "agreement_count": self.agreement_count,
            "disagreements": [d.to_dict() for d in self.disagreements],
        }


# ---------------------------------------------------------------------------
# Finding normalisation (accepts dicts or dataclass-like objects)
# ---------------------------------------------------------------------------

def _f(obj: Any, key: str, default: Any = None) -> Any:
    """Extract a field from a dict or an object with attributes."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def reconcile(
    findings_a: list[dict[str, Any]],
    findings_b: list[dict[str, Any]],
    *,
    title_threshold: float = 0.75,
) -> ReconciliationResult:
    """Reconcile two sets of findings and surface disagreements.

    Parameters
    ----------
    findings_a, findings_b:
        Lists of finding dicts.  Each dict is expected to have at least
        ``title`` and ``severity`` keys.  Optional keys: ``finding_id``,
        ``technique_ids``, ``confidence``.
    title_threshold:
        Similarity ratio (0-1) above which two titles are considered the same
        finding.  Defaults to 0.75.

    Returns
    -------
    ReconciliationResult
        Contains every disagreement and summary counts.
    """
    result = ReconciliationResult()

    # Build quick lookup by explicit ID (if present)
    by_id_a: dict[str, dict[str, Any]] = {}
    by_id_b: dict[str, dict[str, Any]] = {}
    unmatched_a: list[dict[str, Any]] = list(findings_a)
    unmatched_b: list[dict[str, Any]] = list(findings_b)

    for f_a in findings_a:
        fid = _f(f_a, "finding_id")
        if fid:
            by_id_a[str(fid)] = f_a
    for f_b in findings_b:
        fid = _f(f_b, "finding_id")
        if fid:
            by_id_b[str(fid)] = f_b

    # Phase 1: match by explicit finding_id
    matched_pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for fid in set(by_id_a) & set(by_id_b):
        matched_pairs.append((by_id_a[fid], by_id_b[fid]))
        unmatched_a = [f for f in unmatched_a if _f(f, "finding_id") != fid]
        unmatched_b = [f for f in unmatched_b if _f(f, "finding_id") != fid]

    # Phase 2: match remaining by title similarity
    used_b_indices: set[int] = set()
    for f_a in list(unmatched_a):
        title_a = _f(f_a, "title", "")
        for idx, f_b in enumerate(unmatched_b):
            if idx in used_b_indices:
                continue
            title_b = _f(f_b, "title", "")
            if _titles_match(title_a, title_b, title_threshold):
                matched_pairs.append((f_a, f_b))
                used_b_indices.add(idx)
                unmatched_a = [f for f in unmatched_a if f is not f_a]
                break

    # unmatched_a and unmatched_b are now the "only in" sets
    result.matched_count = len(matched_pairs)
    result.only_in_a_count = len(unmatched_a)
    result.only_in_b_count = len(unmatched_b)

    for f_a in unmatched_a:
        result.disagreements.append(Disagreement(
            kind=DisagreementType.ONLY_IN_A,
            title=_f(f_a, "title", "<untitled>"),
            detail="Finding exists only in set A.",
            finding_a=f_a,
        ))

    for f_b in unmatched_b:
        result.disagreements.append(Disagreement(
            kind=DisagreementType.ONLY_IN_B,
            title=_f(f_b, "title", "<untitled>"),
            detail="Finding exists only in set B.",
            finding_b=f_b,
        ))

    # Phase 3: compare matched pairs for severity / MITRE disagreements
    for f_a, f_b in matched_pairs:
        title = _f(f_a, "title", _f(f_b, "title", "<untitled>"))

        sev_a = _f(f_a, "severity", "informational")
        sev_b = _f(f_b, "severity", "informational")
        sev_a_val = str(sev_a).lower() if sev_a else "informational"
        sev_b_val = str(sev_b).lower() if sev_b else "informational"

        if sev_a_val != sev_b_val:
            rank_a = _SEVERITY_RANK.get(sev_a_val, 0)
            rank_b = _SEVERITY_RANK.get(sev_b_val, 0)
            direction = "higher" if rank_a > rank_b else "lower"
            result.disagreements.append(Disagreement(
                kind=DisagreementType.SEVERITY_MISMATCH,
                title=title,
                detail=(
                    f"Severity differs: A={sev_a_val}, B={sev_b_val}. "
                    f"A is {direction} than B."
                ),
                finding_a=f_a,
                finding_b=f_b,
            ))

        tech_a = set(_f(f_a, "technique_ids") or [])
        tech_b = set(_f(f_b, "technique_ids") or [])
        added = sorted(tech_a - tech_b)
        removed = sorted(tech_b - tech_a)

        if added:
            result.disagreements.append(Disagreement(
                kind=DisagreementType.MITRE_ADDED,
                title=title,
                detail=f"MITRE techniques in A but not B: {', '.join(added)}",
                finding_a=f_a,
                finding_b=f_b,
            ))

        if removed:
            result.disagreements.append(Disagreement(
                kind=DisagreementType.MITRE_REMOVED,
                title=title,
                detail=f"MITRE techniques in B but not A: {', '.join(removed)}",
                finding_a=f_a,
                finding_b=f_b,
            ))

    return result
