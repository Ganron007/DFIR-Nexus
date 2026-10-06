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


def _population_resident(src: Path, family: str) -> bool:
    """Whether a manifest path already sits inside `_population/<family>/`.

    `stage_missing_family_samples.py` stages each sample there, and the indexer derives
    the family from the path, so those files are read where they stand. Copying them into
    the workdir as well counted every column twice.
    """
    parts = [str(q).lower() for q in src.parts]
    return "_population" in parts and str(family).lower() in parts


def _stream_digest(path: Path) -> tuple[int, str] | None:
    """(size, sha256) of `path`, hashed in fixed-size chunks.

    Root cause fix (WO-R0F item 1): the previous dedup called ``src.read_bytes()``,
    which loads a whole file into memory to hash it - a 1.7 GB EvtxECmd CSV was a
    1.7 GB allocation, and it was O(n^2) (each file hashed and compared against every
    already-placed file). On the 6,822-file corpus (incl. 6,450 bmc-tools + multi-GB
    CSVs) that hung the profiler. This streams the hash (constant memory) and the
    caller keeps a digest SET, so dedup is O(n) overall. Same semantics - catches the
    `2-<name>` twin and a sample staged under a different name - without the cost.
    """
    import hashlib

    try:
        size = path.stat().st_size
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return size, h.hexdigest()
    except (PermissionError, OSError):
        return None


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
    # The extensions the index can scan, derived from the indexer's OWN pattern list
    # rather than typed here: a narrower list silently drops a family the index would
    # have read and reports it as "no sample", and a wider list claims a family is
    # covered that the runtime cannot read. Both are the same silent gap in opposite
    # directions.
    #
    # The set is built as SUFFIXES WITH THE DOT (`.csv`), because `Path.suffix`
    # includes it - `"csv" in SCANNED` is never true for a file named `x.csv`, which
    # is how this once placed 0 of 115 files while printing a confident skip list.
    pats = (
        "*.csv", "*.txt", "*.json", "*.jsonl", "*.log",
        "*.csv.gz", "*.txt.gz", "*.json.gz", "*.jsonl.gz", "*.log.gz",
    )
    scannable = {p[len("*"):] for p in pats}          # '*.csv.gz' -> '.csv.gz'
    # a `.gz` file is scanned via its double suffix ('.json.gz'); `.suffix` only
    # returns '.gz', so the inner extension decides.
    SCANNED = scannable | {s.rsplit(".", 1)[0] for s in scannable if s.count(".") > 1
                           } | {".gz"}
    placed = 0
    skipped: list[str] = []
    # O(n) dedup: one (size, sha256) per placed file. A source matching any entry is
    # a byte-identical twin (the `2-<name>` copy, or a sample under a different name).
    placed_digests: dict[tuple[int, str], str] = {}
    for family, paths in staged.get("families", {}).items():
        for rel in paths:
            src = Path(rel)
            if not src.is_file():
                skipped.append(f"{src.name} (missing)")
                continue
            # A manifest path that already lives under `_population/<family>/` is placed
            # by the staging script, and `_family()` derives the same family from that
            # path - the index reads it where it stands. Copying it into the workdir
            # would count every column twice.
            if _population_resident(src, family):
                # The staging script leaves these at `_population/<family>/`, and the
                # indexer derives the family from the path - so they are readable where
                # they stand, but only if the case dir can see them. `_layout` is what
                # builds the profiled case, so it must copy them in; skipping them made
                # the profile collapse from 47 families to 13.
                pass
            elif src.suffix.lower() not in SCANNED:
                skipped.append(f"{src.name} ({src.suffix.lower() or 'no-ext'})")
                continue
            # The indexer derives the family from the path (`_family()`), so the
            # destination directory must contain the family name - otherwise the
            # profiling run reports 0 families while the files are all present.
            target = case_dir / "extractions" / family
            target.mkdir(parents=True, exist_ok=True)
            final = target / src.name
            # An identical file already staged is a DUPLICATE, not a second source. The
            # name check catches the `2-<name>` twin; the digest check catches a sample
            # staged under a different name. Both once let every column count twice.
            if final.is_file():
                skipped.append(f"{src.name} (already staged)")
                continue
            src_key = _stream_digest(src)
            if src_key is not None and src_key in placed_digests:
                skipped.append(f"{src.name} (byte-identical to {placed_digests[src_key]})")
                continue
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
            if src_key is not None:
                placed_digests[src_key] = f"{family}/{src.name}"
    return {"placed": placed, "skipped": skipped}

def _install_ingest_store(corpus: Path, case_dir: Path) -> str:
    """Put the importer lane inside the profiled case, if one is staged.

    `case_index.iter_index_docs` reads `case_dir/ingest/artifacts.jsonl` for the
    importer lane; `_layout` only copies into `extractions/`. Without this the
    profile measures a corpus with no importer rows at all, so every one of the 11
    D34 columns reads "not populated" - which is what made an earlier run report
    25,787 documents and drop the 51k the WO's acceptance expects.

    Returns a one-line report, or "" when there is nothing to install.
    """
    import shutil

    dest = case_dir / "ingest" / "artifacts.jsonl"
    if dest.is_file():
        return f"{dest.stat().st_size:,} bytes (already staged)"
    # The STABLE home for the importer lane. It must not live under `_case*`: the
    # profile cleans stale workdirs before each run, and when the store was found only
    # at `_population/_case-39112/...` a cleanup removed the importer lane entirely -
    # 33 profiled families dropped to 26 and every D34 column read "not populated".
    for candidate in (corpus / "_ingest" / "artifacts.jsonl",
                      corpus / "_case" / "ingest" / "artifacts.jsonl",
                      corpus.parent / "_case" / "ingest" / "artifacts.jsonl",
                      corpus / "ingest" / "artifacts.jsonl"):
        if candidate.is_file():
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(candidate, dest)
            return f"{dest.stat().st_size:,} bytes from {candidate.name}"
    return ""


def profile(case_dir: Path) -> dict[str, Any]:
    from nexus.langgraph.case_index import iter_index_docs

    per_family: dict[str, dict[str, dict[str, Any]]] = defaultdict(lambda: defaultdict(
        lambda: {"rows": 0, "filled": 0, "distinct": set(), "samples": []}))
    totals = Counter()
    family_docs: dict[str, int] = Counter()

    _n = 0
    _t0 = __import__("time").time()
    for doc in iter_index_docs(case_dir):
        fam = str(doc.get("family") or "")
        if not fam:
            continue
        _n += 1
        if _n % 50000 == 0:
            _el = __import__("time").time() - _t0
            print(f"  ... {_n:,} docs, {_n / _el:,.0f} docs/sec", flush=True)
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


def absent_families(case_dir: Path, profiled: set[str] | None = None) -> dict[str, dict[str, Any]]:
    """WO-KM1 acceptance: every registry family the corpus does NOT cover, with a reason.

    "A family or event type with no sample ... is recorded as absent, with the reason.
    Do not search for another sample; tell the operator."

    So the profile must name every family the registry declares. A family is absent
    because the corpus stages no file the index can scan for it - which is a fact
    about the corpus, recorded, not hidden. An earlier profile simply omitted the 35
    families it had no sample for, which reads as "no sample" only to someone who
    already knows the registry; the acceptance clause asks for it to say so.

    The staging manifest's own `absent` block is folded in, because that is the
    operator's record of why a family has no sample ("the staged output is not
    present"), and re-deriving a reason locally would contradict it.

    `profiled` is the set the `profile()` pass already collected, so the corpus is not
    scanned a second time - it is ~51k documents.
    """
    from nexus.knowledge.query_validation import load_field_registry

    manifest = case_dir.parent / "_staged.json"
    manifest_families: dict[str, list[str]] = {}
    manifest_absent: dict[str, str] = {}
    if manifest.is_file():
        raw = json.loads(manifest.read_text(encoding="utf-8"))
        manifest_families = raw.get("families") or {}
        manifest_absent = raw.get("absent") or {}

    staged: dict[str, list[str]] = {}
    for fam, rels in manifest_families.items():
        paths = [str(p) for p in (rels or []) if Path(p).is_file()]
        if paths:
            staged[fam] = paths

    cols = load_field_registry()
    registry: set[str] = set()
    for info in cols.values():
        for f in (info.get("families") or []):
            low = str(f).lower()
            registry.add(low[7:] if low.startswith("ingest-") else low)

    profiled = set()
    if profiled:
        # `profile()` already scanned the corpus; reuse its families.
        profiled = {str(f).lower() for f in profiled}
    else:
        from nexus.langgraph.case_index import iter_index_docs

        for doc in iter_index_docs(case_dir):
            fam = str(doc.get("family") or "")
            if fam:
                profiled.add(fam.lower())

    pats = ("*.csv", "*.txt", "*.json", "*.jsonl", "*.log",
            "*.csv.gz", "*.txt.gz", "*.json.gz", "*.jsonl.gz", "*.log.gz")
    scannable = {p.removeprefix("*.") for p in pats}

    out: dict[str, dict[str, Any]] = {}
    for fam in sorted(registry - profiled):
        if fam in manifest_absent:
            out[fam] = {"reason": manifest_absent[fam], "staged_samples": 0,
                        "source": "the staging manifest's own absent record"}
            continue
        paths = [Path(p) for p in (staged.get(fam) or [])]
        present = [p for p in paths if p.is_file()]
        suffixes = {p.suffix.lower() for p in present}
        unscannable = sorted(x for x in suffixes if x not in scannable)
        if present and len(unscannable) == len(suffixes):
            reason = (f"the corpus stages {len(present)} sample(s), but none is a "
                      f"format the index scans "
                      f"({', '.join(x or 'no-extension' for x in unscannable[:4])}); "
                      f"the tool's parsed output has not been run into the corpus")
        elif present:
            reason = ("the corpus stages samples for this family, but the index scan "
                      "yielded no rows for it (empty or non-conforming output)")
        else:
            reason = ("no sample for this family is staged in the operator's "
                      "ES-Mapping corpus, so it is unmeasured")
        out[fam] = {"reason": reason, "staged_samples": len(present)}
    return out


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
    # Stale workdirs from a killed run must not be reused: the earlier code only
    # `rmtree`d the default `_case`, so a `_case-<pid>` left behind by a timed-out run
    # made `mkdir` fail with FileExistsError and the profile never ran at all. Try
    # several names and report which one it used, rather than dying.
    import shutil as _sh

    for candidate in [workdir] + [args.corpus / f"_case-{os.getpid()}-{n}"
                                  for n in range(5)]:
        if candidate.exists():
            try:
                _sh.rmtree(candidate)
            except (PermissionError, OSError):
                continue
        try:
            candidate.mkdir(parents=True)
            workdir = candidate
            break
        except FileExistsError:
            continue
    else:
        print(f"could not create any workdir under {args.corpus} - a stale case dir is "
              f"locked by another process", file=sys.stderr)
        return 2
    # Clean up the leftovers this run did not need, so a repeat run does not find
    # them again. Best-effort: a locked one is reported, not swallowed.
    for stale in args.corpus.glob("_case*"):
        if stale != workdir and stale.is_dir():
            try:
                _sh.rmtree(stale)
            except (PermissionError, OSError) as exc:
                print(f"  could not remove stale {stale.name}: "
                      f"{type(exc).__name__}")
    placed = _layout(args.corpus, workdir)
    # The importer lane (KR2c item 4's `ingest/artifacts.jsonl`) must be inside the
    # profiled case, or the profile reports every importer column absent and KR2c's
    # population gate then rejects every stored query aimed at them. `_layout` only
    # handles `extractions/`, so install the ingest store here and keep it across
    # runs: the store is rebuilt by `stage_ingest_columns.py`, not by this profile.
    ingest_store = _install_ingest_store(args.corpus, workdir)
    if ingest_store:
        print(f"  ingest store: {ingest_store}")
    if not placed["placed"]:
        print("no corpus files were placed; is the corpus staged?", file=sys.stderr)
        return 2

    result = profile(workdir)
    evtx = profile_evtx_detail(workdir)
    absent = absent_families(workdir, set(result["families"]))
    placed = _layout(args.corpus, workdir)
    payload = {
        "generator": "scripts/profile_field_population.py",
        "corpus": args.corpus,
        "note": ("Documents as the index receives them, per family as the index names it. "
                 "A column listed here is populated on real evidence; a registry column "
                 "not listed is declared, not populated. `absent_families` names every "
                 "registry family the corpus does not cover, with the reason - a family "
                 "absent from this profile is not silently 'no sample', it is recorded "
                 "as absent."),
        "families": result["families"],
        "evtxecmd_generic_columns": evtx,
        "absent_families": absent,
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
