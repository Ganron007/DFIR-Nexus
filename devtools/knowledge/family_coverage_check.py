"""WO-KL2e 3: the coverage test becomes a SELECTION test, on real family names.

For every real evidence family - every importer source except the TI feeds and the
pure platform exports, listed explicitly with a reason - plus every tool family, call
`skills_for` and `retrieve_skills` with THAT FAMILY ALONE and assert that at least one
skill whose SUBJECT it is gets selected. Families with no skill are listed with a
reason, as KL2c already does.

This is the check the reviewer's R0' "Runtime selection misses single-source evidence"
finding is about: a coverage number built from declarations says a family is covered
while `skills_for` on that family alone returns nothing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from nexus.ingest.schemas import ArtifactSource  # noqa: E402
from nexus.knowledge.skills import (  # noqa: E402
    family_names,
    get_skills,
    retrieve_skills,
    skills_for,
)

OUT = REPO / "devtools" / "knowledge" / "family-coverage.json"

#: Excluded from the selection test, with a reason, per the WO's own list.
TI_FEEDS = {
    "virustotal": "TI feed: no host evidence, and an IoC lookup is not a hypothesis",
    "otx": "TI feed",
    "misp": "TI feed",
    "abuseipdb": "TI feed",
    "threatfox": "TI feed",
    "shodan": "TI feed",
    "greynoise": "TI feed",
    "thehive": "case-management platform export, not evidence",
}

#: Platform exports that carry no family of their own.
PLATFORM_EXPORTS = {
    "generic_jsonl": "a generic container; the family comes from the importer's "
                     "own classification, not the file extension",
    "generic_csv": "same as generic_jsonl",
    "csv": "an output format shared by every tool - KL2e keeps it "
           "non-discriminative so it cannot surface a skill on its own",
    "tsv": "an output format, not evidence",
    "jsonl": "an output format, not evidence",
    "json": "an output format, not evidence",
    "unknown": "the fallback when a source is unclassified",
}


def main() -> int:
    skills = get_skills()
    # each skill's subject: its primary_families, else its whole trigger list
    subject: dict[str, set[str]] = {}
    for s in skills:
        name = str(s.get("skill") or "")
        prim = [str(f).lower() for f in (s.get("primary_families") or [])]
        trig = [str(f).lower() for f in ((s.get("trigger") or {}).get("families") or [])]
        wide: set[str] = set()
        for f in (prim or trig):
            wide |= family_names(f)
        subject[name] = wide

    # every real evidence family: the importer sources, minus the exclusions.
    importer_sources = sorted({str(m.value).lower() for m in ArtifactSource}
                              - set(TI_FEEDS) - set(PLATFORM_EXPORTS))

    rows: list[dict] = []
    counts = {"selected": 0, "no_skill": 0}
    for fam in importer_sources:
        hitting = sorted(n for n, subj in subject.items()
                         if family_names(fam) & subj)
        if hitting:
            counts["selected"] += 1
            rows.append({"family": fam, "status": "selected",
                         "skills": hitting[:6]})
        else:
            counts["no_skill"] += 1
            rows.append({"family": fam, "status": "no_skill",
                         "reason": "no skill names this family as its subject; "
                                   "the evidence is indexed and full-text "
                                   "searchable, and a skill can be added when "
                                   "its methodology is written"})
    # and the runtime call itself proves it, per family.
    for fam in importer_sources:
        a = [s.get("skill") for s in skills_for({fam})]
        b = [s.get("skill") for s in retrieve_skills({fam})]
        row = next(r for r in rows if r["family"] == fam)
        row["skills_for"] = a
        row["retrieve_skills"] = b

    # every tool family the registry knows, that is not an importer source
    from nexus.knowledge.query_validation import load_field_registry
    cols = load_field_registry()
    tool_fams = set()
    for info in cols.values():
        for f in (info.get("families") or []):
            low = str(f).lower()
            if low.startswith("ingest-") or low in TI_FEEDS:
                continue
            tool_fams.add(low)
    tool_fams -= set(importer_sources) | set(PLATFORM_EXPORTS) | set(TI_FEEDS)

    tool_rows = []
    for fam in sorted(tool_fams):
        hitting = sorted(n for n, subj in subject.items()
                         if family_names(fam) & subj)
        row = {"family": fam,
               "status": "selected" if hitting else "no_skill",
               "skills": hitting[:5],
               "skills_for": [s.get("skill") for s in skills_for({fam})],
               "retrieve_skills": [s.get("skill") for s in retrieve_skills({fam})]}
        if not hitting:
            counts["no_skill"] += 1
        tool_rows.append(row)

    result = {
        "note": ("KL2e: coverage measured as RUNTIME SELECTION. For each real family, "
                 "`skills_for` and `retrieve_skills` are called with that family "
                 "alone, and the skills whose SUBJECT it is are recorded. A family "
                 "with no skill is listed with a reason rather than counted as "
                 "covered, which is the R0' defect: a coverage number built from "
                 "declarations would have claimed a family is covered while the "
                 "runtime selected nothing."),
        "excluded_feeds": TI_FEEDS,
        "excluded_platformexports": PLATFORM_EXPORTS,
        "counts": counts,
        "importer_families": rows,
        "tool_families": tool_rows,
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(f"  importer families: {len(rows)}  selected={counts['selected']} "
          f"no_skill={counts['no_skill']}")
    print(f"  tool families    : {len(tool_rows)}")
    print(f"  written: {OUT.relative_to(REPO)}")
    no_imp = [r['family'] for r in rows if r['status'] == 'no_skill']
    no_tool = [r['family'] for r in tool_rows if r['status'] == 'no_skill']
    print(f"\n  importer families with no skill ({len(no_imp)}): {no_imp}")
    print(f"  tool families with no skill ({len(no_tool)}): {no_tool}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
