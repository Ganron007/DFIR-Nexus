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
    # Rebuild the importer store, then place it at a STABLE path inside the corpus so
    # a stale-workdir sweep cannot remove it. It used to live at
    # `_population/_case-39112/ingest/artifacts.jsonl`, which the profile's own cleanup
    # deletes on the next run - so the importer lane silently vanished from the profile
    # (33 -> 26 families) and every D34 column read "not populated".
    builder = REPO / "devtools" / "knowledge" / "stage_ingest_columns.py"
    if not builder.is_file():
        print(f"  !! {builder.relative_to(REPO)} missing")
        return 2
    import subprocess

    r = subprocess.run([sys.executable, str(builder)], cwd=str(REPO),
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("  !!", (r.stderr or r.stdout)[-300:])
        return 2
    for line in r.stdout.strip().splitlines():
        print("   ", line)

    # The builder writes under the KR2c case dir; copy it to the corpus's stable home.
    src = CORPUS / "_case-39112" / "ingest" / "artifacts.jsonl"
    if not src.is_file():
        # a previous run may have left it at the case dir the population check uses
        for cand in CORPUS.glob("_case*/ingest/artifacts.jsonl"):
            src = cand
            break
    if not src.is_file():
        print("  !! the builder produced no ingest store to install")
        return 2
    stable = CORPUS / "_ingest" / "artifacts.jsonl"
    stable.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, stable)
    print(f"  stable copy: {stable.relative_to(REPO)}  "
          f"({stable.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
