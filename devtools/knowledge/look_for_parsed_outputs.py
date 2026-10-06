"""Is there PARSED output in the operator's corpus for the families recorded absent?

KM1 item 5: "Population corpus = the operator's ES-Mapping, plus one sample per missing
family, from paths MAPPING.md already names ... run through the real importer."

27 families are currently recorded absent with a reason. Most of those reasons are
"the corpus stages samples, but none is a format the index scans" - i.e. the RAW
artifacts are there (.pf, .lnk, .db, .evtx, extensionless hives) and the tool's PARSED
output is what is missing. If the operator's ES-Mapping already holds that parsed
output somewhere, staging it grows the profile and removes the absence.

This locates it: for each absent family, does any directory in the ES-Mapping corpus
hold a file whose parsed output the index could scan?
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ES = REPO / "Evidence-files" / "ES-Mapping"
PROF = ES / "es_mappings" / "_population.json"
SCANNED = {".csv", ".txt", ".json", ".jsonl", ".log"}

prof = json.loads(PROF.read_text(encoding="utf-8"))
absent = prof.get("absent_families") or {}
print(f"  families recorded absent: {len(absent)}")
print()

# Any scannable file anywhere under the ES-Mapping corpus whose path names the family.
hits: dict[str, list[Path]] = {}
for fam in sorted(absent):
    low = fam.lower()
    found: list[Path] = []
    for p in ES.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in SCANNED:
            continue
        parts = [q.lower() for q in p.parts]
        if any(low in q or q.startswith(low) for q in parts):
            found.append(p)
    if found:
        hits[fam] = found

print(f"  families with a PARSED output somewhere in the corpus: {len(hits)}")
for fam, paths in sorted(hits.items()):
    tot = sum(p.stat().st_size for p in paths)
    print(f"    {fam:22s} {len(paths):3d} file(s)  {tot / 1024:.0f} KB")
    for p in sorted(paths)[:3]:
        print(f"        {p.relative_to(ES)}")
print()
print(f"  families with no parsed output anywhere: "
      f"{len(set(absent) - set(hits))}")
print("   ", sorted(set(absent) - set(hits))[:24])
