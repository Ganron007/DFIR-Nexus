"""Remove the bad-matcher run's leftovers, then re-verify.

`stage_missing_family_samples.py`'s first version staged the Sysmon EvtxECmd CSV for all
27 families, writing `20261006053837_EvtxECmd_Output-sample.csv` into each
`_population/<family>/`. The code is fixed and self-tested, but the FILES it wrote are
still there - and because `_family()` derives a family from the path, a sample in the
wrong directory is read as the wrong family: `srumecmd/…EvtxECmd_Output-sample.csv`
profiles as `evtxecmd`, so `srumecmd` never got its own sample.

This deletes only files whose name is that exact stem, leaving every legitimately staged
sample alone, and reports what it removed.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CORPUS = REPO / "Evidence-files" / "ES-Mapping" / "_population"
#: the exact stem the broken matcher wrote into every family directory
BAD_STEM = "20261006053837_EvtxECmd_Output-sample"


def main() -> int:
    removed: list[Path] = []
    for d in sorted(CORPUS.iterdir()):
        if not d.is_dir() or d.name.startswith(("_case", "_ingest")):
            continue
        for f in sorted(d.glob(f"{BAD_STEM}.*")):
            f.unlink()
            removed.append(f)
    if not removed:
        print("  no leftovers found")
        return 0
    print(f"  removed {len(removed)} file(s) named {BAD_STEM}.*:")
    for f in removed:
        print(f"    {f.parent.name}/{f.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
