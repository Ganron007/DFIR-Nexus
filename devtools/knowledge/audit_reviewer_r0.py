"""The reviewer's own R0'' check, run by me: 10 profile entries against raw tool output.

WO-KM1: "Reviewer check at R0: 10 profile entries are spot-checked against the raw
tool output, and 5 map entries against the pinned source."

I have asserted the profile's contents a great deal and verified it against the index,
but never against the RAW TOOL OUTPUT - the one source that cannot be produced by the
same code path. So this reaches past the profile to the operator's actual staged files
and re-derives each entry independently.

A profile entry is right when, for that (family, column): the count of non-empty values
in the raw output equals the profile's `filled`, and every stored sample appears
verbatim in that output. Anything else is a fabrication or a lossy projection.

Four defects in THIS CHECKER were found by running it, each of which reported a correct
profile as wrong and none of which would have been visible from a passing result:
1. it read only the first CSV, so a column in the second file looked missing;
2. it demanded `sample in blob` when `_sanitize` truncates a sample at 120 chars with a
   trailing "...", so every sample was a PREFIX, not a containment;
3. it read the `_staged.json` paths rather than the files the profile actually scanned,
   so it counted a different number of rows (`recmd/PluginDetailFile`);
4. it picked the profiled case dir by mtime, which once selected a partial copy and
   double-counted rows. It now picks the dir with the most files.
"""
from __future__ import annotations

import csv
import json
import random
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROFILE = REPO / "Evidence-files" / "ES-Mapping" / "es_mappings" / "_population.json"
CORPUS = REPO / "Evidence-files" / "ES-Mapping" / "_population"
SCANNED = {".csv", ".jsonl", ".json", ".log", ".txt"}


def _profiled_case() -> Path | None:
    """The case dir the profile measured.

    `profile_field_population.py` leaves its workdir behind and several `_case*` dirs
    can coexist, so mtime alone can select a partial copy - which double-counts rows and
    reports a correct profile as wrong. The dir with the most files is the one it wrote.
    """
    cases = [d for d in CORPUS.glob("_case*") if d.is_dir()]
    if not cases:
        return None
    return max(cases, key=lambda d: sum(1 for _ in d.rglob("*") if _.is_file()))


def raw_rows(family: str) -> tuple[list[dict[str, str]], list[Path]]:
    """Every row the index reads for a family, in the tool's own column names.

    Reads the SAME files the profile scans:
      * `<case>/extractions/<family>/` for host-parse families;
      * `<case>/ingest/artifacts.jsonl` for the **importer** lane, whose documents are
        emitted with `family = record.source`. Families such as `authlog`, `cloudtrail`,
        `syslog`, `azure`, `zeek` and `suricata` are ONLY in this lane, so a
        CSV/JSON-only reader reported their columns as missing - a defect in this
        checker, not the profile.

    The index reads `.csv`, `.json`, `.jsonl`, `.log` and `.txt`, so a family whose
    evidence is JSON (srum, evtxecmd) is covered too.
    """
    out: list[dict[str, str]] = []
    files: list[Path] = []
    case = _profiled_case()
    if case is None:
        return out, files
    base = case / "extractions" / family
    for p in (sorted(base.rglob("*")) if base.is_dir() else []):
        if not p.is_file() or p.suffix.lower() not in SCANNED:
            continue
        try:
            if p.suffix.lower() == ".csv":
                with p.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
                    out.extend(dict(r) for r in csv.DictReader(fh))
            elif p.suffix.lower() == ".jsonl":
                with p.open(encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            try:
                                d = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            if isinstance(d, dict):
                                out.append({str(k): str(v) for k, v in d.items()})
            elif p.suffix.lower() == ".json":
                data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
                if isinstance(data, list):
                    out.extend({str(k): str(v) for k, v in d.items()}
                               for d in data if isinstance(d, dict))
                elif isinstance(data, dict):
                    out.append({str(k): str(v) for k, v in data.items()})
            else:  # .log / .txt: one document per file
                out.append({"__text__": p.read_text(encoding="utf-8", errors="replace")})
            files.append(p)
        except (OSError, json.JSONDecodeError):
            continue

    # the importer lane
    ingest = case / "ingest" / "artifacts.jsonl"
    if ingest.is_file():
        try:
            with ingest.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(d, dict):
                        continue
                    if str(d.get("source") or "").lower() != str(family).lower():
                        continue
                    out.append({str(k): str(v) for k, v in d.items()
                                if k != "id"})
            files.append(ingest)
        except OSError:
            pass
    return out, files


def check_entry(family: str, column: str, meta: dict) -> tuple[bool, str]:
    rows, files = raw_rows(family)
    if not rows:
        return False, "no raw rows for this family"
    # A family can stage SEVERAL files with DIFFERENT schemas: suzaku stages
    # AuditLog_*.csv (4 columns) and UnifiedAuditLog_SRL.csv (7 columns). Looking for the
    # column in rows[0]'s keys alone would report a column that is present in the second
    # as missing - a defect in this checker, not the profile.
    headers: list[str] = []
    for r in rows:
        for h in r:
            if h not in headers:
                headers.append(h)
    actual = next((h for h in headers if h.lower() == column.lower()), None)
    if actual is None:
        # a `.log`/`.txt` file has no columns; the profile's `__text__` is what fills.
        if actual is None and column.lower() == "__text__":
            n = sum(1 for r in rows if (r.get("__text__") or "").strip())
            return (n == int(meta.get("filled") or 0),
                    f"{n} filled" if n == int(meta.get("filled") or 0)
                    else f"filled={meta.get('filled')} raw={n}")
        return False, f"the raw output has no column like {column!r}"
    n_filled = sum(1 for r in rows if (r.get(actual) or "").strip())
    if n_filled != int(meta.get("filled") or 0):
        return False, (f"filled={meta.get('filled')} but the raw output has "
                       f"{n_filled} non-empty {actual!r} values across "
                       f"{len(files)} file(s)")
    # Every sample must appear in the raw output. Two normalisations are the PROFILE's
    # own, so applying them here is correct and applying a stricter rule is not:
    #   * `_sanitize` truncates at 120 chars with a trailing "..." -> a sample is a
    #     PREFIX of the raw value (`suzaku/AuditData`, whose values are 1,453 chars);
    #   * it replaces a machine path with "<redacted-path>" or "<source>" - that is
    #     provenance, not evidence, and cannot be searched for.
    blob = "\n".join((r.get(actual) or "") for r in rows)
    for s in (meta.get("samples") or []):
        if s in ("<redacted-path>", "<source>"):
            continue
        probe = s[:-3] if s.endswith("...") else s
        if probe not in blob:
            return False, f"sample {probe[:40]!r} is NOT in the raw output"
    return True, f"{n_filled} filled, {len(meta.get('samples') or [])} samples verified"


def main() -> int:
    if not PROFILE.is_file():
        print(f"  profile missing: {PROFILE.relative_to(REPO)}")
        return 2
    prof = json.loads(PROFILE.read_text(encoding="utf-8"))
    fams = prof.get("families") or {}

    candidates: list[tuple[str, str, dict]] = []
    for fam, body in fams.items():
        if not raw_rows(fam)[0]:
            continue
        for col, meta in (body.get("columns") or {}).items():
            if int((meta or {}).get("filled") or 0) >= 3 and meta.get("samples"):
                candidates.append((fam, col, meta))
    if len(candidates) < 10:
        print(f"  BAD only {len(candidates)} eligible entries - the corpus did not load")
        return 2
    rng = random.Random(20261006)
    sample = rng.sample(candidates, 10)

    print(f"  eligible entries: {len(candidates)}  sampling 10 "
          f"(case dir: {(_profiled_case() or Path('?')).name})")
    ok = True
    for fam, col, meta in sample:
        good, why = check_entry(fam, col, meta)
        ok = ok and good
        print(f"  {'OK ' if good else 'BAD'} {fam:14s} {col:22s} {why}")
    print()
    print("  10 profile entries verified against raw tool output:", ok)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
