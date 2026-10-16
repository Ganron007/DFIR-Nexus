"""IC-11 (Part 9): fact recall per mode - which of a case's verified facts each run reports, and where.

A fact key (kept outside the product, so no agent ever reads it) lists facts as term groups: every group must
be met (AND) by at least one of its terms (OR), case-insensitively, inside ONE output item. For each run the
scorer reads the run's outputs and reports, per fact, the strongest place it appears:

* ``finding``   - a candidate or staged DRAFT (what the examiner is asked to approve);
* ``narrative`` - the run's narrative or composed case (timeline, attack chain, entities, open questions);
* ``board``     - only in intermediate work (Mode 3 settled claims and board claims, dispositions);
* ``missing``   - nowhere.

A mention is not a correct claim: a finding that names the fact to dismiss it still counts as recalled, so
the report lists the matching item's title for the examiner to read. The key's own facts come from the
examiner's review of the evidence, never from a run's output.

    python devtools/eval/fact_recall.py --case CASE-X --key KEY.yaml RUN_ID [RUN_ID ...]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
TIERS = ("finding", "narrative", "board")


def _text(value: Any) -> str:
    return json.dumps(value, default=str, ensure_ascii=False) if not isinstance(value, str) else value


#: What an output STATES. A DRAFT also carries the rows it cites; a term inside a cited row is evidence the
#: output pointed at, not a fact it reported, so the rows are not read.
_STATED = ("title", "observation", "interpretation", "confidence_justification", "benign_alternative", "refutation",
           "value", "entity_value", "item", "reason", "description", "summary")


def _stated(item: Any) -> str:
    if not isinstance(item, dict):
        return _text(item)
    return "\n".join(str(item.get(k) or "") for k in _STATED if item.get(k))


def _items(case_dir: Path, run_id: str) -> dict[str, list[tuple[str, str]]]:
    """(label, text) items of one run, by tier."""
    out: dict[str, list[tuple[str, str]]] = {tier: [] for tier in TIERS}
    record: dict[str, Any] = {}
    for sub in ("mode2_runs", "mode3_runs"):
        path = case_dir / "analysis" / sub / f"{run_id}.json"
        if path.is_file():
            record = json.loads(path.read_text(encoding="utf-8"))
    staging = case_dir / "runs" / run_id / "analysis" / "staging.json"
    if staging.is_file():
        record = json.loads(staging.read_text(encoding="utf-8"))
    if not record:
        raise SystemExit(f"{run_id}: no run record in {case_dir}")
    # Mode 1's staging record keeps the candidate count; its staged DRAFTs are read from findings.json below.
    candidates = record.get("candidates") if isinstance(record.get("candidates"), list) else []
    for cand in candidates:
        if isinstance(cand, dict):
            out["finding"].append((str(cand.get("title") or "")[:120], _stated(cand)))
    findings = case_dir / "findings.json"
    if findings.is_file():
        for draft in json.loads(findings.read_text(encoding="utf-8")):
            if isinstance(draft, dict) and (draft.get("run_id") == run_id or run_id in (draft.get("run_ids") or [])):
                out["finding"].append((f"{draft.get('id')}: {str(draft.get('title') or '')[:110]}", _stated(draft)))
    for key in ("narrative", "summary"):
        if str(record.get(key) or "").strip():
            out["narrative"].append((key, str(record[key])))
    for part, value in (record.get("case") or {}).items():
        for entry in value if isinstance(value, list) else [value]:
            out["narrative"].append((f"case.{part}", _text(entry)))
    for claim in record.get("settled_claims") or []:
        out["board"].append((f"settled ({claim.get('claim_kind') or '?'}): {str(claim.get('title') or '')[:100]}",
                             _stated(claim)))
    for entry in record.get("board") or []:
        for claim in (entry or {}).get("claims") or []:
            out["board"].append((f"board claim ({entry.get('role')}, {claim.get('claim_kind') or '?'})", _stated(claim)))
    for disp in record.get("dispositions") or []:
        out["board"].append(("disposition", _stated(disp)))
    for rejected in record.get("rejected") or []:
        out["board"].append((f"rejected at staging: {str((rejected or {}).get('title') or '')[:100]}", _stated(rejected)))
    return out


def _denies(label: str, text: str) -> bool:
    """An absence claim (Mode 3's `claim_kind: absence`, titled `<subject> - absence: ...`) says a fact was NOT
    found; naming the fact's terms to deny it is not recalling it."""
    low = label.lower()
    return " - absence:" in low or "(absence)" in low or ", absence)" in low or '"claim_kind": "absence"' in text


def _meets(fact: dict[str, Any], text: str) -> bool:
    low = text.lower()
    return all(any(str(term).lower() in low for term in group) for group in fact.get("require") or [])


def score(case_dir: Path, key: dict[str, Any], run_id: str) -> dict[str, Any]:
    items = _items(case_dir, run_id)
    result: dict[str, Any] = {"run_id": run_id, "facts": {}}
    for fact in key.get("facts") or []:
        found = {"tier": "missing", "where": ""}
        for tier in TIERS:
            match = next((label for label, text in items[tier]
                          if not _denies(label, text) and _meets(fact, text)), None)
            if match is not None:
                found = {"tier": tier, "where": match}
                break
        result["facts"][fact["id"]] = found
    counts = {tier: sum(1 for f in result["facts"].values() if f["tier"] == tier) for tier in (*TIERS, "missing")}
    result["counts"] = counts
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--case", required=True, help="case id (cases/<id>) or a case folder")
    ap.add_argument("--key", required=True, help="the fact key (YAML)")
    ap.add_argument("--json", help="write the full result here")
    ap.add_argument("runs", nargs="+")
    args = ap.parse_args(argv)
    case_dir = Path(args.case) if Path(args.case).is_dir() else REPO / "cases" / args.case
    key = yaml.safe_load(Path(args.key).read_text(encoding="utf-8")) or {}
    facts = key.get("facts") or []
    results = [score(case_dir, key, run) for run in args.runs]
    width = max(len(f["id"]) for f in facts) if facts else 4
    print(f"{'fact':{width}s}  " + "  ".join(f"{r['run_id'][:24]:24s}" for r in results))
    for fact in facts:
        print(f"{fact['id']:{width}s}  " + "  ".join(f"{r['facts'][fact['id']]['tier']:24s}" for r in results)
              + f"  {fact.get('statement', '')[:70]}")
    for r in results:
        c = r["counts"]
        print(f"{r['run_id']}: {c['finding']} in findings, {c['narrative']} in the narrative only, "
              f"{c['board']} on the board only, {c['missing']} missing (of {len(facts)})")
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
