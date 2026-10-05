"""WO-KM1 item 3: the field-population profile, mechanical, no ES.

The WO: `scripts/profile_field_population.py` runs **`iter_index_docs`** over the
population corpus - "Those are exactly the documents the index receives, and no ES is
needed" - and writes `Evidence-files/ES-Mapping/es_mappings/_population.json`:

- per family, as the index names it (`zeek`, not `ingest-zeek`);
- per column: rows, filled, distinct, and 3 sanitized samples;
- for `evtxecmd`, ALSO per (Channel, EventId): which of `PayloadData1-6`,
  `ExecutableInfo`, `UserName`, `RemoteHost` are filled, with 2 samples.

This is forbidden-item 11's foundation: a claim of validity must be shown on
POPULATED fields, not on what the registry declares.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

CORPUS = REPO / "Evidence-files" / "ES-Mapping" / "_population"
OUT = REPO / "Evidence-files" / "ES-Mapping" / "es_mappings" / "_population.json"

#: The generic EvtxECmd columns whose meaning depends on the event.
GENERIC = ("PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
           "PayloadData5", "PayloadData6", "ExecutableInfo", "UserName",
           "RemoteHost")
SAMPLES_PER_COLUMN = 3


def _sanitize(value: Any) -> str:
    """A short, path-free, hash-free sample: provenance, never evidence."""
    text = str(value or "").strip()
    if len(text) > 120:
        text = text[:117] + "..."
    # machine paths and share names are provenance metadata (MAPPING.md notes that
    # `SourceFile`, `RecordID`, etc. carry them), not evidence the examiner needs
    for marker in ("\\\\", "/Users/", "/var/", "/opt/", "C:\\", "H:\\", "I:\\"):
        if marker in text:
            return "<redacted-path>"
    return text


def _layout(corpus: Path, case_dir: Path) -> dict[str, int]:
    """Place every corpus file where an index scan would find it, under its family.

    The indexer walks a **case** directory: `_family()` derives the family from the
    path (the `_FAMILY_HINTS` list, then the parent's name), not from the file's
    contents. So the profile has to reproduce that layout, or the profile would
    report 0 families - which is exactly what happened on the first run, before the
    corpus was laid out as a case.

    Paths that carry a family hint keep their shape; the rest are placed under the
    family the staging script recorded.
    """
    import json

    staged = json.loads((corpus / "_staged.json").read_text(encoding="utf-8")) \
        if (corpus / "_staged.json").exists() else {"families": {}}
    # The indexer scans only these extensions (query_pack.iter_extraction_files).
    # Staging an `.evtx` or `.bin` here would put raw binary in a place designed
    # for parsed rows, which is both useless for the profile and untruthful about
    # what the index receives.
    SCANNED = {".csv", ".txt", ".json", ".jsonl", ".log"}
    placed = 0
    skipped: list[str] = []
    for family, paths in staged.get("families", {}).items():
        for rel in paths:
            src = Path(rel)
            if not src.is_file() or src.suffix.lower() not in SCANNED:
                skipped.append(f"{src.name} ({src.suffix.lower() or 'no-ext'})")
                continue
            # The indexer derives the family from the path (`_family()`), so the
            # destination directory must contain the family name - otherwise the
            # profiling run reports 0 families while the files are all present.
            target = case_dir / "extractions" / family
            target.mkdir(parents=True, exist_ok=True)
            final = target / src.name
            n = 1
            while final.exists():
                n += 1
                final = target / f"{n}-{src.name}"
            try:
                shutil.copy2(src, final)
            except (PermissionError, OSError) as exc:
                skipped.append(f"{src.name}: {type(exc).__name__}")
                continue
            placed += 1
    return {"placed": placed, "skipped": skipped}


def profile(case_dir: Path) -> dict[str, Any]:
    from nexus.langgraph.case_index import iter_index_docs

    per_family: dict[str, dict[str, dict[str, Any]]] = defaultdict(lambda: defaultdict(
        lambda: {"rows": 0, "filled": 0, "distinct": set(), "samples": []}))
    totals = Counter()
    family_docs: dict[str, int] = Counter()

    for doc in iter_index_docs(case_dir):
        fam = str(doc.get("family") or "")
        if not fam:
            continue
        family_docs[fam] += 1
        totals[fam] += 1
        fields = doc.get("fields") if isinstance(doc.get("fields"), dict) else {}
        for column, value in fields.items():
            if value in (None, "", [], {}):
                continue
            bucket = per_family[fam][str(column)]
            bucket["filled"] += 1
            bucket["rows"] += 1
            bucket["distinct"].add(str(value))
            if len(bucket["samples"]) < SAMPLES_PER_COLUMN:
                sample = _sanitize(value)
                if sample and sample not in bucket["samples"]:
                    bucket["samples"].append(sample)
        # the row text is a column too: it is what a full-text search matches
        text = str(doc.get("text") or "")
        if text:
            bucket = per_family[fam]["__text__"]
            bucket["filled"] += 1

    families: dict[str, Any] = {}
    for fam in sorted(per_family):
        docs = family_docs[fam]
        cols: dict[str, Any] = {}
        for column in sorted(per_family[fam]):
            c = per_family[fam][column]
            cols[column] = {
                "docs": docs,
                "rows": c["rows"] or docs,
                "filled": c["filled"],
                "distinct": len(c["distinct"]),
                "samples": c["samples"],
            }
        families[fam] = {"docs": docs, "columns": cols}
    return {"docs": dict(totals), "families": families}


def profile_evtx_detail(case_dir: Path) -> dict[str, Any]:
    """For evtxecmd, per (Channel, EventId): which generic columns are filled."""
    from nexus.langgraph.case_index import iter_index_docs

    detail: dict[str, dict[str, Any]] = {}
    for doc in iter_index_docs(case_dir):
        if str(doc.get("family") or "") != "evtxecmd":
            continue
        fields = doc.get("fields") if isinstance(doc.get("fields"), dict) else {}
        key = f"{fields.get('Channel', '')}|{fields.get('EventId', '') or doc.get('event_id', '')}"
        slot = detail.setdefault(key, {g: {"filled": 0, "samples": []} for g in GENERIC})
        slot["__docs__"] = slot.get("__docs__", 0) + 1
        for column in GENERIC:
            value = fields.get(column)
            if value in (None, "", []):
                continue
            entry = slot[column]
            entry["filled"] += 1
            if len(entry["samples"]) < 2:
                sample = _sanitize(value)
                if sample and sample not in entry["samples"]:
                    entry["samples"].append(sample)
    return detail


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--workdir", type=Path,
                        help="temp case dir to build; defaults to the corpus's _case")
    args = parser.parse_args(argv)

    if not args.corpus.is_dir():
        print(f"corpus not found: {args.corpus} - run stage_population_corpus.py",
              file=sys.stderr)
        return 2

    workdir = args.workdir or (args.corpus / "_case")
    if workdir.exists():
        import shutil as _sh

        try:
            _sh.rmtree(workdir)
        except (PermissionError, OSError):
            # a stale run can leave a file open elsewhere; a fresh name still lets
            # the profile run and the reason is reported rather than swallowed.
            workdir = args.corpus / f"_case-{os.getpid()}"
    workdir.mkdir(parents=True)
    placed = _layout(args.corpus, workdir)
    if not placed["placed"]:
        print("no corpus files were placed; is the corpus staged?", file=sys.stderr)
        return 2

    result = profile(workdir)
    evtx = profile_evtx_detail(workdir)
    placed = _layout(args.corpus, workdir)
    payload = {
        "generator": "scripts/profile_field_population.py",
        "corpus": str(args.corpus),
        "note": ("Documents as the index receives them, per family as the index names it. "
                 "A column listed here is populated on real evidence; a registry column "
                 "not listed is declared, not populated."),
        "families": result["families"],
        "evtxecmd_generic_columns": evtx,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")

    n_fam = len(payload["families"])
    n_cols = sum(len(f["columns"]) for f in payload["families"].values())
    print(f"  families profiled: {n_fam}   columns: {n_cols}")
    print(f"  placed {placed['placed']} file(s) into {workdir.name}")
    if placed.get("skipped"):
        print(f"  skipped {len(placed['skipped'])} unreadable file(s)")
    print(f"  evtxecmd (Channel|EventId) slots: {len(evtx)}")
    print(f"  written: {OUT.relative_to(REPO)}  ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
