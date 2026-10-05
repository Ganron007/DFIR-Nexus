"""WO-KR2c 0d: report what the population corpus can and cannot population-check.

The WO is explicit: "A family or event type with no sample, such as Security 4688, is
recorded as **absent, with the reason**. Do not search for another sample; tell the
operator."

So this does exactly that, mechanically, over `Evidence-files/ES-Mapping/evidence`
(the operator's own corpus). It measures:

- which (Channel, EventId) pairs exist in the parsed EVTX rows, and their counts;
- whether the event types KR2c's field choices depend on (4688 audited process
  creation, Sysmon EID 1) are present.

It writes the answer to `Evidence-files/ES-Mapping/es_mappings/_event_coverage.json`
and prints it. No search for another sample happens here.
"""
from __future__ import annotations

import argparse
import collections
import csv
import io
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CORPUS_EV = REPO / "Evidence-files" / "ES-Mapping" / "evidence" / "evtx"
PARSED = next(iter(sorted((REPO / "Evidence-files" / "ES-Mapping" / "outputs" / "evtxecmd")
                          .glob("*.csv"))), None)
OUT = REPO / "Evidence-files" / "ES-Mapping" / "es_mappings" / "_event_coverage.json"

#: Event types KR2c's field-choice table depends on. A stored query targeting
#: process-creation columns can only be population-checked where these exist.
REQUIRED_EVENTS = {
    ("Security", "4688"): "audited process creation - the command line and target user",
    ("Security", "4624"): "successful logon - the target user and logon type",
    ("Microsoft-Windows-Sysmon/Operational", "1"): "Sysmon process create (Image, ParentImage, CommandLine)",
    ("Microsoft-Windows-Sysmon/Operational", "7"): "Sysmon image loaded",
    ("Microsoft-Windows-Sysmon/Operational", "11"): "Sysmon file create",
    ("Microsoft-Windows-Sysmon/Operational", "13"): "Sysmon registry value set",
    ("Microsoft-Windows-PowerShell/Operational", "4104"): "PowerShell script block",
}


def scan(csv_path: Path | None) -> dict:
    pairs: collections.Counter = collections.Counter()
    channels: collections.Counter = collections.Counter()
    files: list[str] = []
    if csv_path and csv_path.is_file():
        with io.open(csv_path, encoding="utf-8-sig", errors="replace") as fh:
            rows = list(csv.reader(fh))
        hdr = [h.strip().lower() for h in rows[0]]
        i_ev = hdr.index("eventid") if "eventid" in hdr else None
        i_ch = hdr.index("channel") if "channel" in hdr else None
        if i_ev is not None and i_ch is not None:
            for row in rows[1:]:
                if len(row) <= max(i_ev, i_ch):
                    continue
                ch = (row[i_ch] or "").strip()
                ev = (row[i_ev] or "").strip()
                if ch or ev:
                    pairs[(ch, ev)] += 1
                    channels[ch] += 1
        files.append(str(csv_path.name))
    elif CORPUS_EV.is_dir():
        files = [p.name for p in sorted(CORPUS_EV.rglob("*.evtx"))]

    absent: dict[str, str] = {}
    for (channel, event), why in REQUIRED_EVENTS.items():
        hits = [n for (ch, ev), n in pairs.items()
                if ev == event and (ch == channel or ch.startswith(channel))]
        if not hits:
            absent[f"{channel} {event}"] = why

    return {
        "corpus": "Evidence-files/ES-Mapping/evidence (the operator's 18-run debug corpus)",
        "parsed_rows": int(sum(pairs.values())),
        "distinct_channel_event_pairs": len(pairs),
        "channels": dict(sorted(channels.items(), key=lambda kv: -kv[1])),
        "required_events_present": {
            f"{c} {e}": n for (c, e), n in sorted(pairs.items())
            if (c, e) in REQUIRED_EVENTS
        },
        "required_events_absent_with_reason": absent,
        "raw_evtx_staged": files,
        "note": (
            "A field-choice query can only be population-checked for an event type "
            "that is present. Where it is absent the WO says to record the reason and "
            "tell the operator, not to search for another sample."
        ),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--parsed-csv", type=Path, default=PARSED)
    args = ap.parse_args()
    result = scan(args.parsed_csv)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")

    print(f"  parsed rows: {result['parsed_rows']}  "
          f"(channel, EventId) pairs: {result['distinct_channel_event_pairs']}")
    print(f"  channels ({len(result['channels'])}): "
          f"{', '.join(list(result['channels'])[:12])}")
    print("  required events present:", result["required_events_present"] or "none")
    print(f"  ABSENT ({len(result['required_events_absent_with_reason'])}):")
    for key, why in result["required_events_absent_with_reason"].items():
        print(f"    - {key}: {why}")
    print(f"  written: {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
