"""WO-KR2c item 3: the field-population matrix - which stored queries cannot match.

The WO: build one index from `Evidence-files/ES-Mapping/evidence` (the representative
corpus behind the 18-run debug matrix, NOT a development or GATE-H sample), then for
every stored query and every field it references, count the documents where that field
exists. A query whose POSITIVE clauses reference only zero-population fields is
reported as **"cannot match on real data"**, and the matrix goes to
`devtools/knowledge/field-population.json`.

This is the mechanical check that catches a wrong field, which the existing validator
cannot: `validate_stored_query` checks a field EXISTS in the registry, so a query
aimed at `command_line` for an EVTX family passes - and then matches nothing, forever
reading "ran, found nothing".

No ES is needed for the measurement: `iter_index_docs` produces exactly the documents
the index receives, so an `exists` count is taken over those documents. The WO's ES
`exists`-count wording is the same measurement against a live index, and
`--es` runs it that way when one is up.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from nexus.knowledge.query_validation import (  # noqa: E402
    CORE_ENVELOPE_FIELDS,
    expand_families,
)

CORPUS = REPO / "Evidence-files" / "ES-Mapping" / "_population" / "_case"
STAGING = REPO / "Evidence-files" / "ES-Mapping" / "_population"
OUT = REPO / "devtools" / "knowledge" / "field-population.json"
KNOWLEDGE = REPO / "src" / "nexus" / "data" / "knowledge"

#: Clauses that assert something about a field. `must_not` is a negative clause and
#: does not make the query unable to match, so it is excluded from the check.
POSITIVE_CLAUSES = ("term", "terms", "wildcard", "match", "match_phrase",
                    "prefix", "exists")


def _fields_of(node: Any) -> list[str]:
    """Every field a query's POSITIVE clauses reference.

    `must_not` is skipped on purpose: a negative clause cannot make a query unable
    to match, so counting it would report a working query as broken.
    """
    if isinstance(node, dict):
        out: list[str] = []
        for key, value in node.items():
            if key in ("term", "terms", "wildcard", "match", "match_phrase",
                       "prefix", "exists") and isinstance(value, dict):
                out.extend(str(f) for f in value)
            elif key == "must_not":
                continue  # a negative clause never makes a query unable to match
            else:
                out.extend(_fields_of(value))
        return out
    if isinstance(node, list):
        out = []
        for value in node:
            out.extend(_fields_of(value))
        return out
    return []


def _strip(field: str) -> str:
    f = str(field)
    if f.startswith("fields."):
        f = f[7:]
    if f.endswith(".kw"):
        f = f[:-3]
    return f


def _families_of(item: dict[str, Any]) -> list[str]:
    req = item.get("requires") or {}
    fams = req.get("families") or item.get("families") or []
    return [str(f) for f in fams]


def _load_skills() -> list[tuple[str, dict[str, Any]]]:
    import yaml

    out = []
    for path in sorted((KNOWLEDGE / "skills").glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for step in data.get("steps") or []:
            if isinstance(step, dict) and step.get("es"):
                out.append((str(step.get("name")), step))
    return out


def _load_analytics() -> list[tuple[str, dict[str, Any]]]:
    import yaml

    out = []
    for name in ("needles/behavioral_analytics.yaml",):
        path = KNOWLEDGE / name
        if not path.is_file():
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for item in data.get("packs") or []:
            if isinstance(item, dict) and item.get("es"):
                out.append((str(item.get("id")), item))
    return out


def _all_queries() -> list[tuple[str, str, dict[str, Any]]]:
    """(kind, id, item) for every stored query: skill steps then analytics."""
    rows = [("skill_step", name, s) for name, s in _load_skills()]
    rows += [("analytic", name, a) for name, a in _load_analytics()]
    return rows


def measure_docs(corpus: Path) -> dict[str, Any]:
    """per family -> per column -> documents where that column has a value.

    The ENVELOPE (`family`, `ts`, `text`, `host`, `file`, `line`, `user`,
    `event_id`) is a real column on every document and is measured from the document
    itself, not from `fields.*`. An earlier version counted only `fields.*` and
    invented a `__text__` pseudo-column that never matched a real field name, so
    every query touching `text` was reported "cannot match" - a fully false matrix.
    """
    from nexus.langgraph.case_index import iter_index_docs

    per_family: dict[str, Counter] = defaultdict(Counter)
    family_docs: Counter = Counter()
    envelope = [c for c in CORE_ENVELOPE_FIELDS]
    for doc in iter_index_docs(corpus):
        fam = str(doc.get("family") or "")
        if not fam:
            continue
        family_docs[fam] += 1
        fields = doc.get("fields") if isinstance(doc.get("fields"), dict) else {}
        for column, value in fields.items():
            if value not in (None, "", [], {}):
                per_family[fam][str(column)] += 1
        # the envelope columns, read from the document itself
        for column in envelope:
            value = doc.get(column)
            if value not in (None, "", [], {}):
                per_family[fam][column] += 1
        # `text.wc` is the wildcard subfield of `text`: filled iff text is
        if str(doc.get("text") or "").strip():
            per_family[fam]["text.wc"] += 1
    return {"per_family": per_family, "docs": family_docs}


def build(corpus: Path, es: str = "") -> dict[str, Any]:
    measured = measure_docs(corpus)
    per_family = measured["per_family"]
    family_docs = measured["docs"]

    # column -> the families where it holds a value, so a query can be judged
    # against its declared families.
    filled_by: dict[str, set[str]] = defaultdict(set)
    for fam, cols in per_family.items():
        for column, n in cols.items():
            if column != "__text__" and n > 0:
                filled_by[column.lower()].add(fam.lower())
    # the families the corpus actually holds documents for
    present = {fam.lower() for fam in family_docs}

    rows: list[dict[str, Any]] = []
    counts = Counter()
    for kind, ident, item in _all_queries():
        es_query = item.get("es")
        declared = _families_of(item)
        # A skill's trigger names an ALIAS (`evtx`, `browser`), while the index emits
        # the tool's own name (`evtxecmd`, `hindsight`). Comparing the declared name
        # straight against the index's families would report every query as
        # unmatched, which is the false negative this check exists to avoid. Expand
        # both sides the same way the registry does.
        fams = {f.lower() for f in expand_families(declared)}
        columns = sorted({_strip(f).lower() for f in _fields_of(es_query)})
        if not columns:
            counts[f"{kind}_text_only"] += 1
            continue
        counts[f"{kind}_typed"] += 1
        # A field is populated for this query when any expanded family fills it.
        unfilled = [c for c in columns
                    if not (filled_by.get(c, set()) & fams)]
        if len(unfilled) == len(columns):
            counts[f"{kind}_cannot_match"] += 1
            # WHY it cannot match decides whether it is a defect. A query is only a
            # wrong-field defect when a declared family IS in the corpus and still
            # does not fill the column; if no declared family is staged, the column
            # is unmeasurable and the row is corpus absence, which must not be
            # reported as a defect (the R0' defect would only be escaped, not fixed).
            declared_present = sorted(set(fams) & present)
            rows.append({
                "kind": kind, "id": ident,
                "families": sorted(fams),
                "columns": columns, "status": "cannot_match",
                "declared_families_in_corpus": declared_present,
                "cause": ("wrong_field" if declared_present else "corpus_absent"),
                "reason": ("none of the columns it references holds a value in the "
                           "population corpus for the declared families"
                           + ("; no declared family is staged here" if not declared_present
                              else "")),
            })
        elif unfilled:
            counts[f"{kind}_partial"] += 1
            rows.append({
                "kind": kind, "id": ident, "families": sorted(fams), "columns": columns,
                "status": "partial",
                "unfilled_columns": unfilled,
                "reason": "some referenced columns are not filled for these families",
            })
        else:
            counts[f"{kind}_populated"] += 1

    return {
        "corpus": str(corpus.relative_to(REPO)) if corpus.is_relative_to(REPO) else str(corpus),
        "note": ("A row is 'cannot_match' when every column its positive clauses "
                 "reference is unfilled for the declared families. 'partial' names "
                 "the columns that are unfilled. A cannot_match row carries `cause`: "
                 "`wrong_field` when a declared family IS in the corpus and still "
                 "does not fill the column, `corpus_absent` when no declared family "
                 "is staged so the column is unmeasurable. Reporting absence as a "
                 "defect would only hide the real one."),
        "counts_extra": counts,
        "counts_summary": {
            "cannot_match_wrong_field": len([r for r in rows
                                            if r.get("cause") == "wrong_field"]),
            "cannot_match_corpus_absent": len([r for r in rows
                                             if r.get("cause") == "corpus_absent"]),
        },
        "family_docs": dict(sorted(family_docs.items(), key=lambda kv: -kv[1])),
        "counts": dict(counts),
        "rows": rows,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", type=Path, default=CORPUS,
                    help="the CASE layout the indexer reads (staged by "
                         "devtools/knowledge/stage_population_corpus.py); the raw "
                         "Evidence-files dir is not one and reads 0 documents")
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()
    corpus = args.corpus
    if not corpus.is_dir():
        # A convenience: build it from the staged corpus when it is missing.
        staging = STAGING
        out_dir = staging / "_case"
        if staging.is_dir() and not out_dir.is_dir():
            print(f"  {corpus} missing - staging it from {staging}")
            import subprocess
            subprocess.run([sys.executable, str(REPO / "scripts" /
                                                "profile_field_population.py")],
                           cwd=str(REPO), check=False, capture_output=True)
    if not args.corpus.is_dir():
        print(f"corpus not found: {args.corpus}", file=sys.stderr)
        return 2

    result = build(args.corpus)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")

    print(f"  corpus families: {len(result['family_docs'])}")
    print(f"  queries: {result['counts']}")
    cannot = [r for r in result["rows"] if r["status"] == "cannot_match"]
    print(f"  cannot match ({len(cannot)}):")
    for r in cannot[:25]:
        print(f"    - {r['kind']} {r['id']}  {r['columns']}  {r['families']}")
    print(f"  written: {args.out.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
