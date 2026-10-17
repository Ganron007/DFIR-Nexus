"""IC-9 (Part 9): retrieval rates per run - how many of a run's searches found nothing, flooded, or were refused.

A run's searches are read from its case's audit trail, inside the run's own window (its run record's created and
completed times). With ``--why`` every zero-hit search is run again through the surface (``es_native.es_search``,
read-only) and sorted by the reason its diagnosis gives:

* ``value in the row text``   - a clause's field does not hold the value, the row text does;
* ``outside the family``      - the clause matches rows, none in the family the query names;
* ``ignoring case``           - the value is there, written in another case;
* ``nothing in the case``     - a clause matches no row at all (an absence, or a value the case writes otherwise);
* ``empty combination``       - every clause matches rows on its own; no row matches them together.

The first three are queries the seat could have corrected; the last two are answers.

    python devtools/eval/retrieval_rates.py --case CASE-X [--why] RUN_ID [RUN_ID ...]
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
FLOOD = 10_000


def _ts(value: Any) -> datetime | None:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None


def run_window(case_dir: Path, run_id: str) -> tuple[datetime | None, datetime | None]:
    for sub in ("mode2_runs", "mode3_runs"):
        path = case_dir / "analysis" / sub / f"{run_id}.json"
        if path.is_file():
            rec = json.loads(path.read_text(encoding="utf-8"))
            return _ts(rec.get("created_at") or rec.get("started_at")), _ts(rec.get("completed_at"))
    manifest = case_dir / "runs" / run_id / "manifest.json"
    if manifest.is_file():
        rec = json.loads(manifest.read_text(encoding="utf-8"))
        return _ts(rec.get("created_at")), _ts(rec.get("completed_at"))
    raise SystemExit(f"no run record for {run_id} in {case_dir}")


def searches(case_dir: Path, start: datetime, end: datetime) -> list[dict[str, Any]]:
    out = []
    with (case_dir / "audit" / "nexus.jsonl").open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if '"es_search"' not in line:
                continue
            rec = json.loads(line)
            t = _ts(rec.get("ts"))
            if rec.get("tool") == "es_search" and t and start <= t <= end:
                out.append(rec)
    return out


def reason(diagnosis: dict[str, Any]) -> str:
    rows = diagnosis.get("clauses") or []
    dead = [r for r in rows if r.get("rows") == 0]
    if any(r.get("rows_with_the_value_in_their_text") and not r.get("rows_ignoring_case") for r in dead):
        return "value in the row text"
    if any(r.get("rows_ignoring_case") for r in dead):
        return "ignoring case"
    if dead:
        return "nothing in the case"
    if any(r.get("rows_in_family") == 0 for r in rows):
        return "outside the family"
    return "empty combination"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--case", required=True)
    parser.add_argument("--why", action="store_true", help="re-run each zero-hit search for its diagnosis")
    parser.add_argument("runs", nargs="+")
    args = parser.parse_args(argv)
    case_dir = REPO / "cases" / args.case
    if args.why:
        sys.path.insert(0, str(REPO / "src"))
        from nexus.langgraph import es_native
    for run_id in args.runs:
        start, end = run_window(case_dir, run_id)
        if not (start and end):
            print(f"== {run_id}: the run record has no completed time")
            continue
        calls = searches(case_dir, start, end)
        summary = [c.get("result_summary") or {} for c in calls]
        refused = sum(1 for s in summary if "error" in s)
        zero = [c for c, s in zip(calls, summary, strict=True) if s.get("total") == 0 and "error" not in s]
        flood = sum(1 for s in summary if isinstance(s.get("total"), int) and s["total"] > FLOOD)
        n = max(1, len(calls))
        print(f"== {run_id}: es_search {len(calls)}; zero hits {len(zero)} ({100 * len(zero) / n:.0f}%), "
              f"refused {refused} ({100 * refused / n:.0f}%), over {FLOOD:,} rows {flood} ({100 * flood / n:.0f}%)")
        if not args.why:
            continue
        why: collections.Counter[str] = collections.Counter()
        for call in zero:
            query = (call.get("params") or {}).get("query") or {}
            try:
                result = es_native.es_search(args.case, query, size=1)
            except Exception as exc:  # noqa: BLE001
                why[f"cannot re-run: {type(exc).__name__}"] += 1
                continue
            if result.get("degraded"):
                why["refused now (unknown field)"] += 1
            elif result.get("total"):
                why["matches now (the index changed)"] += 1
            else:
                why[reason(result.get("zero_hit") or {})] += 1
        for label, count in why.most_common():
            print(f"   {count:5}  {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
