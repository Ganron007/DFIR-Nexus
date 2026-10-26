"""Replay every refused or failed es_search / es_aggregate call in cases' audits since a time on the current code
(Part 11 rules 17-18): proof that a query-surface fix reaches the real calls on the real indexes. Read-only queries.

    python devtools/runbook/replay_refused.py 2026-10-26T06:36 CASE-0763B990 [CASE-... ...]

Each call prints its params, the error it got then, and now: RUNS NOW (with any degraded answer) or STILL plus the
refusal. `unknown_field` answers are the designed degraded hint and are counted, not replayed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
from nexus.langgraph import es_native  # noqa: E402

ROOT = REPO / "cases"


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
                if "cannot match" in err and "ESQueryError" not in err:
                    hints += 1
                    continue
                p = dict(a["params"])
                p.pop("case_id", None)
                try:
                    if a["tool"] == "es_search":
                        out = es_native.es_search(case, p.get("query"), size=p.get("size", 25), sort=p.get("sort"))
                    else:
                        out = es_native.es_aggregate(case, p.get("aggs"), p.get("query"))
                    now = "RUNS NOW" + (f" (degraded: {str(out.get('error'))[:80]})" if out.get("error") else "")
                except es_native.ESQueryError as exc:
                    now = f"STILL: {str(exc)[:200]}"
                print(f"{case} {a['audit_id']} {a['tool']}\n   params: {json.dumps(p)[:500]}\n"
                      f"   then: {err[:200]}\n   now:  {now}")
        print(f"{case}: {hints} unknown_field answers (designed hint) since {since}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2:])
