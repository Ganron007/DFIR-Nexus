"""Re-stage the importer families so the profile measures the columns KR2c depends on.

The profile run at `c510097` covered 51,602 documents because the population corpus
was laid out as a case that ALSO held the importer lane (`ingest/artifacts.jsonl`, the
D34 columns). Deleting the stale `_case-39112` removed that, so the regenerated profile
measures 25,787 documents and reports every importer column as absent - which would
make KR2c's population gate reject everything.

`stage_ingest_columns.py` (KR2c item 4) built that store from artifacts the case
already contained. It must be staged into the profile's workdir too, so the profile
and the population check measure the SAME corpus.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CORPUS = REPO / "Evidence-files" / "ES-Mapping" / "_population"
# The store KR2c item 4 built for the population corpus.
INGEST_SRC = REPO / "Evidence-files" / "ES-Mapping" / "_population" / "_case-39112" / "ingest" / "artifacts.jsonl"


def main() -> int:
    # The KR2c store was built under `_case-39112`, which the profile's stale-dir
    # sweep removed. Rebuild it the same way `stage_ingest_columns.py` did.
    builder = REPO / "devtools" / "knowledge" / "stage_ingest_columns.py"
    if not builder.is_file():
        print(f"  !! {builder.relative_to(REPO)} missing")
        return 2
    import subprocess

    r = subprocess.run([sys.executable, str(builder)], cwd=str(REPO),
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("  !!" , r.stderr[-300:])
        return 2
    for line in r.stdout.strip().splitlines():
        print("   ", line)

    # Now place that store inside the profile's workdir so `_layout` + the profile see
    # the importer lane. It is an ingest store, not an extraction, which is exactly
    # where the indexer looks for it (`case_dir / 'ingest' / 'artifacts.jsonl'`).
    for case in sorted(CORPUS.glob("_case*")):
        if case.is_dir() and (case / "ingest" / "artifacts.jsonl").is_file():
            continue
        dest = case / "ingest" / "artifacts.jsonl"
        if INGEST_SRC.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(INGEST_SRC, dest)
            print(f"  staged ingest store into {case.name}/ingest/artifacts.jsonl "
                  f"({dest.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
