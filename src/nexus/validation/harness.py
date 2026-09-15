"""Validation harness — WP 9.6.

Measures how well the deterministic skill/pipeline layer recovers a
**known answer** from a case. An answer key lists what a case *should*
yield (evidence families, ATT&CK techniques, artifacts, entities); the
harness runs the matching skills' queries over the case and reports
recall / precision / F1 per dimension.

This is the honest "enterprise" metric: it turns "we have skills" into
"on known evidence we recover X% of the truth with Y% precision".

Known-answer corpora to point it at (documented in the roadmap):
CFReDS, Digital Corpora, DFIR ORC and AXIOM test images — extract to a case
with the normal tool lane, then write `answer_key.yaml` from the published
ground truth.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from nexus.knowledge.skills import retrieve_skills, skill_queries

_MAX_NEEDLES = 40


@dataclass
class Dimension:
    """Recall/precision for one dimension (techniques, families, …)."""

    name: str
    expected: set[str] = field(default_factory=set)
    found: set[str] = field(default_factory=set)

    @property
    def true_positives(self) -> set[str]:
        return self.expected & self.found

    @property
    def missing(self) -> set[str]:
        return self.expected - self.found

    @property
    def extra(self) -> set[str]:
        return self.found - self.expected

    @property
    def recall(self) -> float:
        return len(self.true_positives) / len(self.expected) if self.expected else 1.0

    @property
    def precision(self) -> float:
        return len(self.true_positives) / len(self.found) if self.found else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.name,
            "expected": sorted(self.expected),
            "found": sorted(self.found),
            "missing": sorted(self.missing),
            "extra": sorted(self.extra),
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "f1": round(self.f1, 4),
        }


def load_answer_key(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"answer key is not a mapping: {path}")
    return data


def _expected(key: dict[str, Any]) -> dict[str, Any]:
    exp = key.get("expected")
    return exp if isinstance(exp, dict) else {}


def _search(case_dir: Path, needles: list[str]) -> list[dict[str, Any]]:
    """Run the N4 engine over the case for the given needles."""
    from nexus.langgraph.query_pack import attach_hit_fields, n4_hits

    if not needles:
        return []
    try:
        hits, _backend = n4_hits(case_dir, needles, (None, None))
    except Exception:  # noqa: BLE001 — a broken case yields no hits, not a crash
        return []
    try:
        return attach_hit_fields(case_dir, hits)
    except Exception:  # noqa: BLE001
        return hits


def _attack_packs() -> list[dict[str, Any]]:
    from nexus.knowledge.loader import get_attack_needles

    return [p for p in get_attack_needles() if isinstance(p, dict)]


def _technique_needles(exp_techs: set[str], packs: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Needles per expected technique — curated ATT&CK pack first.

    Techniques without a curated pack (ICS/cloud/mobile — the curated pack
    file is Windows-oriented) fall back to the synced ATT&CK techniques
    (WP 9.4): the technique id itself plus ≥4-char name tokens, so a
    known-answer for any matrix is still scorable instead of guaranteed-miss.
    """
    needles_by_tech: dict[str, list[str]] = {}
    for pack in packs:
        tid = str(pack.get("technique") or "").upper()
        ns = [str(n) for n in (pack.get("needles") or []) if str(n).strip()]
        if tid and ns:
            needles_by_tech[tid] = ns
    missing = [t for t in exp_techs if not needles_by_tech.get(t)]
    if missing:
        from nexus.knowledge.loader import get_attack_techniques

        meta = {str(t.get("technique") or "").upper(): t for t in get_attack_techniques()}
        for tid in missing:
            info = meta.get(tid)
            derived: list[str] = [tid.lower()]
            if info:
                derived.extend(re.findall(r"[A-Za-z]{4,}", str(meta.get("name") or "")))
            derived = [d for d in dict.fromkeys(derived) if len(d) >= 4][:12]
            if len(derived) > 1:
                needles_by_tech[tid] = derived
    return needles_by_tech


def gather_found(case_dir: Path, key: dict[str, Any]) -> dict[str, Any]:
    """Collect what the skill layer actually recovers from the case.

    Returns ``{dimension: (expected_set, found_set), "needles": [...], "hits": n}``.
    A technique counts as *found* only when one of its ATT&CK needles appears
    in the recovered hits — evidence-backed, not merely declared by a skill.
    """
    case_dir = Path(case_dir)
    exp = _expected(key)
    exp_techs = {str(t).upper() for t in (exp.get("techniques") or [])}
    exp_fams = {str(f).lower() for f in (exp.get("families") or [])}
    exp_artifacts = {str(a) for a in (exp.get("artifacts") or []) if str(a).strip()}
    exp_entities = {
        str(e.get("value"))
        for e in (exp.get("entities") or [])
        if isinstance(e, dict) and str(e.get("value") or "").strip()
    }

    skills = retrieve_skills(families=exp_fams, techniques=exp_techs, limit=8)
    packs = _attack_packs()
    tech_needles = _technique_needles(exp_techs, packs)

    needles: list[str] = []
    for s in skills:
        needles.extend(skill_queries(s))
    # Expected techniques' ATT&CK needles pull the supporting evidence in.
    for tid in sorted(exp_techs):
        needles.extend(tech_needles.get(tid, []))
    needles.extend(sorted(exp_artifacts))
    needles.extend(sorted(exp_entities))
    needles = [n for n in dict.fromkeys(str(n).strip() for n in needles if str(n).strip())]
    needles = needles[:_MAX_NEEDLES]

    hits = _search(case_dir, needles)
    blob_parts: list[str] = []
    found_fams: set[str] = set()
    for h in hits:
        found_fams.add(str(h.get("family") or "").lower())
        blob_parts.append(str(h.get("text") or ""))
        fields = h.get("fields") or {}
        if isinstance(fields, dict):
            blob_parts.extend(str(v) for v in fields.values())
    blob = " ".join(blob_parts).lower()

    # Techniques: any curated pack whose needles appear in the recovered hits
    # (open world), plus every expected technique matched via its needles.
    found_techs: set[str] = set()
    for pack in packs:
        tid = str(pack.get("technique") or "").upper()
        pack_needles = [str(n).lower() for n in (pack.get("needles") or []) if str(n).strip()]
        if tid and any(nd in blob for nd in pack_needles):
            found_techs.add(tid)
    for tid in exp_techs:
        if any(nd.lower() in blob for nd in tech_needles.get(tid, [])):
            found_techs.add(tid)

    found_artifacts = {a for a in exp_artifacts if a.lower() in blob}
    found_entities = {v for v in exp_entities if v.lower() in blob}

    return {
        "techniques": (exp_techs, found_techs),
        "families": (exp_fams, found_fams),
        "artifacts": (exp_artifacts, found_artifacts),
        "entities": (exp_entities, found_entities),
        "needles": needles,
        "hits": len(hits),
    }


def run_validation(case_dir: str | Path, answer_key: dict[str, Any] | str | Path) -> dict[str, Any]:
    """Score a case against a known-answer key. Returns a JSON-ready report."""
    if isinstance(answer_key, (str, Path)):
        answer_key = load_answer_key(answer_key)
    case_dir = Path(case_dir)
    found = gather_found(case_dir, answer_key)

    dimensions: list[Dimension] = []
    overall = Dimension("overall")
    for name in ("techniques", "families", "artifacts", "entities"):
        exp, fnd = found[name]
        d = Dimension(name, set(exp), set(fnd))
        dimensions.append(d)
        overall.expected |= d.expected
        overall.found |= d.found

    return {
        "case": answer_key.get("case") or str(case_dir.name),
        "case_dir": str(case_dir),
        "needles_searched": len(found["needles"]),
        "hits": found["hits"],
        "overall": overall.to_dict(),
        "dimensions": [d.to_dict() for d in dimensions],
        "recall": round(overall.recall, 4),
        "precision": round(overall.precision, 4),
        "f1": round(overall.f1, 4),
    }
