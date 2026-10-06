"""WO-KM1 item 3's missing clause: the evtxecmd generic-column detail.

The profile must record, per (Channel, EventId), which of `PayloadData1-6`,
`ExecutableInfo`, `UserName`, `RemoteHost` are filled, with 2 samples. The real lane
re-ran and produced a 976 MB CSV (749,437 rows, 22 event ids), but the profile's
`evtxecmd_generic_columns` was 0 slots because that CSV was not in the profiled corpus.

This stages a SMALL, honest sample: the CSV's own columns, capped per (Channel,
EventId), so the profile measures the same rows the index would read without copying
a gigabyte into the corpus. The full row counts and per-column fill counts stay in
`_sysmon_population.json` (the real lane's report); the sample is only for the per-event
generic-column semantics.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SRC_CSV = sorted((REPO / "Evidence-files" / "ES-Mapping" / "outputs" / "evtxecmd-sysmon")
                 .glob("*.csv"))
CORPUS = REPO / "Evidence-files" / "ES-Mapping" / "_population"
DEST_FAMILY = "evtxecmd-sysmon"
#: rows per (Channel, EventId) is enough for the profile's per-slot record and its
#: 2 samples; the real lane's report already carries the full counts.
PER_SLOT = 40


def main() -> int:
    if not SRC_CSV:
        print("  no EvtxECmd sysmon output - run devtools/knowledge/stage_sysmon_real_lane.py")
        return 2
    src = SRC_CSV[-1]
    with src.open(encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        header = reader.fieldnames or []
        # EvtxECmd's own generic-column names, as the index derives the family from
        # the path and the columns from the header.
        keep = [h for h in header if h]
        per_slot: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
        for row in reader:
            key = (str(row.get("Channel") or ""), str(row.get("EventId") or ""))
            if len(per_slot[key]) < PER_SLOT:
                per_slot[key].append({h: (row.get(h) or "") for h in keep})
            if len(per_slot) > 40:
                break
    dest = CORPUS / DEST_FAMILY
    dest.mkdir(parents=True, exist_ok=True)
    out = dest / "evtxecmd-sysmon-sample.csv"
    with out.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=keep, extrasaction="ignore")
        w.writeheader()
        for rows in per_slot.values():
            for r in rows:
                w.writerow(r)
    print(f"  slots: {len(per_slot)}  rows: {sum(len(v) for v in per_slot.values())}")
    print(f"  columns: {len(keep)}")
    print(f"  written: {out.relative_to(REPO)}  ({out.stat().st_size / 1024:.0f} KB)")

    # record the sample in the staging manifest so the profile's `_layout` picks it up
    manifest = CORPUS / "_staged.json"
    data = json.loads(manifest.read_text(encoding="utf-8")) if manifest.is_file() else {}
    fams = data.setdefault("families", {})
    fams[DEST_FAMILY] = [str(out)]
    # and it is no longer "absent" for the corpus: the sample is staged
    absent = data.setdefault("absent", {})
    absent.pop(DEST_FAMILY, None)
    manifest.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"  manifest: {DEST_FAMILY} staged; removed from the absent list")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
