"""Replay every refused or failed es_search / es_aggregate call in cases' audits since a time on the current code
(Part 11 rules 17-18): proof that a query-surface fix reaches the real calls on the real indexes. Read-only queries.

    python devtools/runbook/replay_refused.py 2026-10-26T06:36 CASE-0763B990 [CASE-... ...]

Each call prints its params, the error it got then, and now: RUNS NOW, HINT for an unknown field, or STILL plus
the remaining error. Historical `unknown_field` answers are the designed hint and are counted, not replayed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from nexus.langgraph import es_native  # noqa: E402

ROOT = REPO / "cases"


def replay_call(case: str, entry: dict) -> dict:
    """Replay recorded operational parameters, including the same pre-dispatch policy.

    A captured `filter` must never disappear merely because this helper used to
    select only `query`, `size`, and `sort` from a failed request.
    """
    params = dict(entry["params"])
    params.pop("case_id", None)
    if entry.get("rejection_stage"):
        from nexus.langgraph.context_loop import _validate_call_args

        clean, problem, _ = _validate_call_args(entry["tool"], params, entry.get("allowed_tools"))
        if problem:
            raise es_native.ESQueryError(problem)
        params = clean
    if entry["tool"] == "es_search":
        return es_native.es_search(case, **params)
    return es_native.es_aggregate(case, **params)


def main(since: str, cases: list[str]) -> None:
    for case in cases:
        hints = 0
        for f in sorted((ROOT / case / "audit").glob("*.jsonl")):
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    a = json.loads(line)
                except ValueError:
                    continue
                if str(a.get("ts", "")) < since or a.get("tool") not in ("es_search", "es_aggregate"):
                    continue
                err = str((a.get("result_summary") or {}).get("error") or "")
                if not err:
                    continue
                if es_native.is_unknown_field_hint(err):
                    hints += 1
                    continue
                p = dict(a["params"])
                p.pop("case_id", None)
                try:
                    out = replay_call(case, a)
                    error = str(out.get("error") or "")
                    if es_native.is_unknown_field_hint(error):
                        now = f"HINT (unknown_field): {error[:200]}"
                    elif error:
                        now = f"STILL: {error[:200]}"
                    else:
                        now = "RUNS NOW"
                except es_native.ESQueryError as exc:
                    now = f"STILL: {str(exc)[:200]}"
                print(f"{case} {a['audit_id']} {a['tool']}\n   params: {json.dumps(p)[:500]}\n"
                      f"   then: {err[:200]}\n   now:  {now}")
        print(f"{case}: {hints} unknown_field answers (designed hint) since {since}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2:])
