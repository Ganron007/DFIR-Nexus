"""For each job a lane log reports as timed out, the jobs that started that many seconds before it (Part 10, P2).

The lane logs "tool RUNNING: <argv>" when a job starts and "tool FAIL: Command timed out after Ns" when it is
killed, without the job's name on the second line; jobs run concurrently, so the candidates are listed.

    python devtools/runbook/lane_timeouts.py cases/<CASE>/.trace/lane-<Tag>.log
"""
from __future__ import annotations

import re
import sys
from datetime import datetime


def main(log: str) -> int:
    started: list[tuple[datetime, str]] = []
    failed: list[tuple[datetime, int]] = []
    with open(log, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if m := re.match(r"^(\d\d:\d\d:\d\d)\s+tool RUNNING: (.*)", line):
                started.append((datetime.strptime(m[1], "%H:%M:%S"), m[2].strip()))
            elif m := re.match(r"^(\d\d:\d\d:\d\d)\s+tool FAIL: Command timed out after (\d+)s", line):
                failed.append((datetime.strptime(m[1], "%H:%M:%S"), int(m[2])))
    for when, secs in failed:
        print(f"{when.time()} timed out after {secs}s; started then:")
        for t, cmd in started:
            if abs((when - t).total_seconds() - secs) <= 15:
                print("    ", cmd[:230])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
