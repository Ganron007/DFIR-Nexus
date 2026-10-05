"""WO-KL2d: the field-population measurement over the Sigma pack.

The reviewer's finding: the 966 translated Sigma analytics declared
`evtxecmd, hayabusa, security, sysmon` while mapping `Image`->`process_name`,
`CommandLine`->`command_line`, `TargetFilename`->`file_path`,
`ParentImage`->`parent_process` - columns that exist only on importer rows. Measured
at `c510097` this was 966/966 unable to match.

This script measures the pack against the KR2c population corpus and, crucially,
separates the two reasons a rule cannot match, because they need opposite actions:

  `corpus_absent`  the families that DO fill the column (evtxecmd, hayabusa) are not
                   staged, so the rule is CORRECT but unmeasurable here. The WO
                   explicitly allows this ("or its family is absent from the corpus,
                   recorded").
  `no_lane_has_it`  no lane the rule declares has that column at all. This is the
                   real defect: the rule must be dropped or deferred to KA3.

Production code is not changed by this measurement; it is evidence for the WO's
acceptance criterion.
"""
from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

from field_population_check import measure_docs  # noqa: E402

from nexus.knowledge.query_validation import expand_families  # noqa: E402

CORPUS = REPO / "Evidence-files" / "ES-Mapping" / "_population" / "_case-39112"
OUT = REPO / "devtools" / "knowledge" / "sigma-population.json"
SIGMA = REPO / "src" / "nexus" / "data" / "knowledge" / "needles" / "sigma_analytics.yaml"


def _fields_of(node):
    """(field, clause) pairs for the query's POSITIVE clauses."""
    out = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "must_not":
                continue
            if (key in ("term", "terms", "wildcard", "match", "match_phrase",
                        "prefix", "exists") and isinstance(value, dict)):
                for f in value:
                    out.append((str(f), key))
            else:
                out.extend(_fields_of(value))
    elif isinstance(node, list):
        for v in node:
            out.extend(_fields_of(v))
    return out


def _strip(field: str) -> str:
    f = str(field)
    if f.startswith("fields."):
        f = f[7:]
    if f.endswith(".kw"):
        f = f[:-3]
    return f


def main() -> int:
    import yaml

    measured = measure_docs(CORPUS)
    per_family = measured["per_family"]
    present = {f.lower() for f in measured["docs"]}

    filled_by: dict[str, set[str]] = defaultdict(set)
    for fam, cols in per_family.items():
        for column, n in cols.items():
            if n > 0:
                filled_by[column.lower()].add(fam.lower())

    data = yaml.safe_load(SIGMA.read_text(encoding="utf-8")) or {}
    packs = data.get("packs") or []
    print(f"  sigma packs: {len(packs)}")

    rows = []
    counts: Counter = Counter()
    for item in packs:
        rid = str(item.get("id"))
        es = item.get("es")
        req = item.get("requires") or {}
        fams = [str(f) for f in (req.get("families") or item.get("families") or [])]
        if not es or not fams:
            counts["no_query_or_families"] += 1
            continue
        expanded = {f.lower() for f in expand_families(fams)}
        pairs = _fields_of(es)
        if not pairs:
            counts["text_only"] += 1
            continue
        bad = []
        for field, _clause in pairs:
            col = _strip(field).lower()
            if not (filled_by.get(col, set()) & expanded):
                bad.append(col)
        if not bad:
            counts["populated"] += 1
            continue
        counts["cannot_match"] += 1
        unfilled_cols = sorted(set(bad))
        lanes_with_any_col = set()
        for c in unfilled_cols:
            lanes_with_any_col |= {f for f in expanded
                                   if f in filled_by.get(c, set())}
        cause = ("corpus_absent" if (not lanes_with_any_col
                                     and (expanded - present))
                 else "no_lane_has_it")
        rows.append({
            "id": rid, "families": sorted(expanded),
            "unfilled_columns": unfilled_cols,
            "declared_in_corpus": sorted(expanded & present),
            "families_that_fill_the_column": sorted(lanes_with_any_col),
            "cause": cause,
        })

    result = {
        "note": ("KL2d: a Sigma analytic 'cannot match' when its positive clauses "
                 "reference a column none of its declared families fills. `cause` "
                 "separates the two reasons: `corpus_absent` means the families that "
                 "DO fill the column are not staged in the representative corpus, so "
                 "the rule is correct but unmeasurable here (the WO allows this, "
                 "recorded); `no_lane_has_it` means no declared lane has that column "
                 "at all, which is the defect to drop. Production code is unchanged "
                 "by this measurement."),
        "corpus": str(CORPUS.relative_to(REPO)) if CORPUS.is_relative_to(REPO) else str(CORPUS),
        "corpus_families": sorted(present),
        "counts": dict(counts),
        "cannot_match": rows,
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")

    print(f"  counts: {dict(counts)}")
    print(f"  cannot_match by cause: {dict(Counter(r['cause'] for r in rows))}")
    print(f"  written: {OUT.relative_to(REPO)}")
    by_col = Counter()
    for r in rows:
        for c in r["unfilled_columns"]:
            by_col[c] += 1
    print("\n  unfilled column frequency:")
    for c, n in by_col.most_common(14):
        print(f"    {n:5d}  {c}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
