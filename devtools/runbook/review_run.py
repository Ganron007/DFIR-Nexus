"""Review finished mode runs from the product's own records (Part 11 rule 18): the run log, the run record and every
tool error in the case audit during the run's window. Reads only; runs nothing.

    python devtools/runbook/review_run.py T18-R1z3b:CASE-0763B990:3 [<tag>:<case>:<mode> ...]

The window is the first and last UTC stamp line (`YYYY-MM-DDTHH:MM:SSZ`) of
`cases/<case>/.trace/run-<tag>-mode<N>.log`; a run started per rule 18 writes one at each end. An `unknown_field`
answer is the designed degraded hint naming the right field; every other error is a defect to look at.
"""
from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "cases"
STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z$")
RUN_ID = re.compile(r"(RUN-\S+-interpret-\w+|M2-\d{8}T\d{6}-\w{6}|M3-\d{8}T\d{6}-\w{6})")


def review(tag: str, case: str, mode: str) -> None:
    log = ROOT / case / ".trace" / f"run-{tag}-mode{mode}.log"
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    stamps = [m.group(1) for line in lines if (m := STAMP.match(line.strip().lstrip("﻿")))]
    start, end = (stamps[0], stamps[-1]) if len(stamps) >= 2 else ("", "~")
    exit_line = next((line for line in lines if line.startswith(f"MODE{mode}_EXIT")), "no exit line")
    status = next((line.strip() for line in reversed(lines)
                   if "status=" in line or "  completed  " in line or "  settled  " in line), "")
    found = RUN_ID.search(status or "")
    run_id = found.group(1) if found else ""
    model = ""
    if run_id:
        for rec in [*(ROOT / case / "runs").glob(f"{run_id}/manifest.json"),
                    *(ROOT / case / "analysis").glob(f"mode*_runs/{run_id}/*.json"),
                    *(ROOT / case / "analysis").glob(f"mode*_runs/{run_id}.json")]:
            m = re.search(r'"model":\s*"([^"]+)"', rec.read_text(encoding="utf-8", errors="replace"))
            if m:
                model = m.group(1)
                break
    tracebacks = [i for i, line in enumerate(lines) if "Traceback (most recent call last)" in line]
    errors: collections.Counter[str] = collections.Counter()
    hints = 0
    calls = 0
    for f in (ROOT / case / "audit").glob("*.jsonl"):
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                a = json.loads(line)
            except ValueError:
                continue
            ts = str(a.get("ts", ""))[:19]
            if not start or not (start <= ts <= end):
                continue
            calls += 1
            err = str((a.get("result_summary") or {}).get("error") or "")
            if not err:
                continue
            if "cannot match" in err and "ESQueryError" not in err:
                hints += 1
            else:
                errors[f"{a.get('tool')} [{a.get('audit_id')}]: {err[:140]}"] += 1
    print(f"\n== {tag} mode {mode} [{start} .. {end}] {exit_line}")
    print(f"   {status[:170]}")
    print(f"   model={model or '?'}  audited calls={calls}  unknown-field hints={hints}  "
          f"other tool errors={sum(errors.values())}  tracebacks={len(tracebacks)}")
    for key, count in errors.most_common(20):
        print(f"     {count:3d} x {key}")
    for i in tracebacks[:3]:
        print("   traceback:", " | ".join(x.strip() for x in lines[max(0, i - 1): i + 6])[:300])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    for spec in sys.argv[1:]:
        review(*spec.split(":"))
