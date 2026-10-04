#!/usr/bin/env python3
"""WO-KL2 (design time) - measure each needle term's false-positive rate on a clean corpus.

A needle is a search term the product scans for. A term that matches benign,
everyday events is not a clue: it is noise, and it makes the Mode 1 scan and the
Mode 2/3 lead builder report normal activity as suspicious.

This measures the real thing, not an impression:

- it uses the product's own matcher, ``query_pack.needle_in_text``, so the numbers
  mean what the scan would do;
- it reports, per term, **files matched / files scanned** and **events matched /
  events scanned**, so a term that hits every event in one file is distinguishable
  from one that hits a single event in every file;
- it writes a machine-readable report and prints the terms that cross the rate.

The corpus is the Nextron ``evtx-baseline`` clean Windows event logs under
``Evidence-files/_k1-datasets/benign``.

**Honest limitation.** The product's needle scan runs over the tool lane's parsed
rows (EvtxECmd CSV). This reads the raw records' XML rendering, which carries the
same tokens for the purposes of a term match but is not byte-identical. It is a
design-time screen for bad terms, not a measurement of the product.

Design time only: this lives under ``devtools/`` and is never imported by
``src/nexus``. It reads a clean corpus, which contains no case data, so it cannot
leak anything about a development or GATE-H sample.

Usage::

    python devtools/knowledge/measure_needle_fp.py \
        --corpus Evidence-files/_k1-datasets/benign \
        --out devtools/knowledge/needle-fp-report.json \
        [--max-files 0] [--max-file-rate 0.05]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from nexus.langgraph.query_pack import needle_in_text  # noqa: E402

#: XML element and attribute syntax. Its removal keeps the data values, which is
#: what the product's row scan sees; see ``render_records``.
_TAG = re.compile(r"<[^>]*>")

PACK = REPO / "src" / "nexus" / "data" / "knowledge" / "needles" / "generated_needles.yaml"


def load_terms(pack: Path = PACK) -> list[dict]:
    """Every needle term with the provenance the pack already carries."""
    import yaml

    data = yaml.safe_load(pack.read_text(encoding="utf-8")) or {}
    out: list[dict] = []
    for item in data.get("terms") or []:
        if not isinstance(item, dict):
            continue
        term = str(item.get("term") or "").strip()
        if term:
            out.append(item)
    return out


def render_records(path: Path, max_events: int) -> list[str]:
    """One lowercased text blob per event, for term matching.

    **Markup is stripped.** The product's needle scan matches the *values* in the
    tool lane's parsed rows (EvtxECmd CSV), not XML tag or attribute names. Matching
    raw XML would count ``ProcessId`` because it appears as ``<Data Name="ProcessId">``
    and report a field name as a noisy needle. Removing the tags keeps the data
    values, which is what the scan sees.

    ``max_events`` caps the events examined per file. The corpus is ~2 GB across
    1026 files, and a term that fires on benign data fires in the early events of a
    file too; the cap is recorded in the report so the number is read for what it
    is. ``0`` means every event.

    ``Evtx`` (python-evtx) is a design-time dependency; it is not a product
    dependency. A file that will not parse is reported by the caller, not
    treated as empty - an unreadable file must not look like a clean one.
    """
    from Evtx.Evtx import Evtx

    blobs: list[str] = []
    total = 0
    with Evtx(str(path)) as log:
        for record in log.records():
            total += 1
            if max_events and len(blobs) >= max_events:
                # Count the rest without rendering it: iteration is cheap, the XML
                # parse is not, and the cap is reported in the result.
                continue
            try:
                xml = record.xml()
            except Exception:  # noqa: BLE001 - one bad record must not lose the file
                continue
            blobs.append(_TAG.sub(" ", xml).lower())
    return blobs, total


def measure(corpus: Path, max_files: int, terms: list[dict], max_events: int) -> dict:
    files = sorted(corpus.rglob("*.evtx"))
    if max_files:
        files = files[:max_files]

    # A term can only match a blob that contains its first AND last character.
    # That is a necessary condition, so skipping on it changes no count, and it
    # turns the inner loop from a substring scan per term into a set lookup for
    # most terms - without it the run is O(terms x events) substring scans.
    needles = [(t["term"], t["term"][0], t["term"][-1]) for t in terms]

    hits = {t["term"]: 0 for t in terms}
    files_hit = {t["term"]: 0 for t in terms}
    events = 0
    skipped_by_cap = 0
    unreadable: list[str] = []
    started = time.monotonic()

    for i, path in enumerate(files, 1):
        try:
            blobs, total = render_records(path, max_events)
        except Exception as exc:  # noqa: BLE001
            unreadable.append(f"{path.name}: {type(exc).__name__}: {exc}"[:200])
            continue
        skipped_by_cap += max(0, total - len(blobs))
        events += len(blobs)
        hit_here: set[str] = set()
        for blob in blobs:
            chars = set(blob)
            for term, first, last in needles:
                if first not in chars or last not in chars:
                    continue
                if needle_in_text(blob, term):
                    hits[term] += 1
                    hit_here.add(term)
        for term in hit_here:
            files_hit[term] += 1
        if i % 100 == 0:
            print(f"  {i}/{len(files)} files, {events} events "
                  f"({time.monotonic() - started:.0f}s)", flush=True)

    return {
        "corpus": str(corpus),
        "files_scanned": len(files) - len(unreadable),
        "files_unreadable": len(unreadable),
        "unreadable": unreadable[:20],
        "events_scanned": events,
        "max_events_per_file": max_events,
        "events_skipped_by_cap": skipped_by_cap,
        "terms": [
            {
                "term": t["term"],
                "kind": t.get("kind"),
                "subject": t.get("subject"),
                "techniques": t.get("techniques") or [],
                "files_hit": files_hit[t["term"]],
                "events_hit": hits[t["term"]],
            }
            for t in terms
        ],
        "wall_s": round(time.monotonic() - started, 1),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--out", type=Path,
                        default=REPO / "devtools" / "knowledge" / "needle-fp-report.json")
    parser.add_argument("--max-files", type=int, default=0,
                        help="0 = every file in the corpus")
    parser.add_argument("--max-events", type=int, default=300,
                        help="events examined per file; 0 = every event")
    parser.add_argument("--max-file-rate", type=float, default=0.05,
                        help="report terms hitting more than this share of files")
    args = parser.parse_args(argv)

    if not args.corpus.is_dir():
        print(f"corpus not found: {args.corpus}", file=sys.stderr)
        return 2

    terms = load_terms()
    print(f"corpus: {args.corpus}")
    print(f"terms : {len(terms)} from {PACK.name}")

    report = measure(args.corpus, args.max_files, terms, args.max_events)
    scanned = max(1, report["files_scanned"])
    for row in report["terms"]:
        row["file_rate"] = round(row["files_hit"] / scanned, 4)

    noisy = sorted(
        (r for r in report["terms"] if r["file_rate"] > args.max_file_rate),
        key=lambda r: -r["file_rate"],
    )
    report["max_file_rate"] = args.max_file_rate
    report["noisy_terms"] = [r["term"] for r in noisy]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")

    print()
    print(f"files : {report['files_scanned']} scanned, "
          f"{report['files_unreadable']} unreadable")
    print(f"events: {report['events_scanned']} examined "
          f"({report['events_skipped_by_cap']} past the {args.max_events}-event cap)")
    print(f"terms firing on > {args.max_file_rate:.0%} of files: {len(noisy)}")
    for r in noisy[:25]:
        print(f"   {r['file_rate']:6.1%}  {r['term'][:60]:60s} {r['kind']}")
    print()
    print(f"report: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
