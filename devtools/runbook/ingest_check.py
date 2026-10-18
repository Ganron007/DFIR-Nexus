"""Import files into a throwaway case with a given build; print each file's source and row count (Part 10, P6).

The importer pass's own entry (`timeline_merge.ingest_into_case`) is used, so what this prints is what a lane run
gets. Run it with the current code and with the change to show what a fix changes, file by file.

    python devtools/runbook/ingest_check.py --src <tree>/src FILE [FILE ...]
"""
from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("files", nargs="+", type=Path)
    args = ap.parse_args()
    sys.path.insert(0, args.src)
    from nexus.langgraph.timeline_merge import ingest_into_case  # noqa: PLC0415

    for src in args.files:
        case = Path(tempfile.mkdtemp(prefix="ingest-check-"))
        (case / "audit").mkdir()
        try:
            info = ingest_into_case(src, case)
            print(f"{info.get('source')}\t{info.get('artifacts')}\t{str(info.get('error') or '')[:80]}\t{src}")
        except Exception as exc:  # noqa: BLE001 - a crash is the result being checked
            print(f"EXCEPTION {type(exc).__name__}: {str(exc)[:100]}\t\t\t{src}")
        finally:
            shutil.rmtree(case, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
