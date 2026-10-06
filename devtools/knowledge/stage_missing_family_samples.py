"""WO-KM1 item 5: one sample per missing family, from paths the corpus already names.

18 of the 27 families recorded absent DO have parsed output in the operator's
ES-Mapping corpus (`outputs/<tool>/...csv`) - the raw artifacts were never the problem,
the tool's PARSED output simply was not staged. KM1 item 5 says to fill exactly this gap
"from paths MAPPING.md already names", so this stages the best sample per family and
removes it from the absent list. Families with no parsed output stay absent, with their
reason - the WO explicitly forbids substituting a sample.

The matching rule is deliberately narrow, because a loose one fabricates coverage:

    f == `evtxecmd-sysmon/20261006053837_EvtxECmd_Output.csv` (the Sysmon lane's output)

must NOT match `kape`, `elastic`, `threatfox` or any of the other 23 families that have
no parsed output. A first version tested `parent in (low, parent_family)`, which is
trivially true whenever `parent_family == parent` - so it matched every file whose
parent directory shares its own name, staged one EVTX CSV for 27 families, and reported
ZERO absent. That is the failure mode this whole work order exists to prevent, so the
rule is now:

  a file matches a family when SOME COMPONENT of its path IS the family name
  (exactly, or `<family>-<suffix>`), where `sift-vol` also counts as `vol`;

  and the stem is never matched alone.

Self-tests at the bottom pin the negative.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ES = REPO / "Evidence-files" / "ES-Mapping"
CORPUS = ES / "_population"
PROF = ES / "es_mappings" / "_population.json"

#: rows to take from a very large CSV. Enough for the profile's per-column record, its
#: samples and the evtxecmd detail, without copying hundreds of MB into the corpus.
ROW_CAP = 2000
#: bytes beyond which a CSV is considered "large" and capped
LARGE = 8 * 1024 * 1024
#: suffixes the index scans
SCANNED = {".csv", ".txt", ".jsonl", ".json", ".log"}
#: files that are processing metadata rather than tool output
_NOT_OUTPUT = ("stderr", "stdout", "run", "debug", "esent")


def _components(path: Path) -> set[str]:
    """Every name-bearing component, normalised: `sift-vol` also yields `vol`."""
    out: set[str] = set()
    for part in path.parts:
        low = str(part).lower()
        if not low or low.endswith((".csv", ".txt", ".json", ".jsonl", ".log", ".gz")):
            continue
        out.add(low)
        for prefix in ("sift-", "sift_"):
            if low.startswith(prefix):
                out.add(low[len(prefix):])
        # `<family>-<suffix>` and `<family>_<suffix>`
        for sep in ("-", "_"):
            head = low.split(sep, 1)[0]
            if head and head != low:
                out.add(head)
    return out


def matches(path: Path, family: str) -> bool:
    """Whether a file is this family's own output. Narrow on purpose - see module doc."""
    low = str(family).lower()
    if path.suffix.lower() not in SCANNED:
        return False
    if "_population" in path.parts:
        return False
    return low in _components(path)


def _data_rows(path: Path) -> int:
    try:
        if path.suffix.lower() == ".csv":
            with path.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
                return max(0, sum(1 for _ in csv.reader(fh)) - 1)
        with path.open(encoding="utf-8-sig", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def best_sample(family: str) -> Path | None:
    """The most informative single scannable file for a family, or None."""
    candidates = [p for p in ES.rglob("*") if p.is_file() and matches(p, family)]
    if not candidates:
        return None

    def is_output(p: Path) -> bool:
        n = p.name.lower()
        return not any(s in n for s in _NOT_OUTPUT)

    data_csv = [p for p in candidates
                if p.suffix.lower() == ".csv" and is_output(p) and _data_rows(p) > 0]
    if data_csv:
        return max(data_csv, key=lambda p: p.stat().st_size)
    data_any = [p for p in candidates if is_output(p) and _data_rows(p) > 0]
    pool = data_any or [p for p in candidates if is_output(p)] or candidates
    return max(pool, key=lambda p: p.stat().st_size)


def cap_rows(src: Path, dest: Path) -> int:
    """Copy `src` to `dest`, capping a very large CSV at ROW_CAP rows."""
    if src.suffix.lower() != ".csv" or src.stat().st_size <= LARGE:
        dest.write_bytes(src.read_bytes())
        with src.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
            return max(0, sum(1 for _ in csv.reader(fh)) - 1)
    with src.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
        rows = list(csv.reader(fh))
    header = rows[0]
    kept = rows[1:1 + ROW_CAP]
    with dest.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(kept)
    return len(kept)


def _selftest() -> bool:
    """The negative cases that a loose matcher gets wrong."""
    sysmon = ES / "outputs/evtxecmd-sysmon/20261006053837_EvtxECmd_Output.csv"
    cases = [
        (sysmon, "kape", False),
        (sysmon, "elastic", False),
        (sysmon, "threatfox", False),
        (sysmon, "virustotal", False),
        (sysmon, "security_onion", False),
        (ES / "outputs/recmd/20260921222606/recmd-SOFTWARE_VolumeInfoCache.csv",
         "vol", False),
        (ES / "outputs/sift-vol/vol-pslist.txt", "vol", True),
        (ES / "outputs/pecmd/prefetch.csv", "pecmd", True),
        (ES / "outputs/appcompat/appcompat.csv", "appcompat", True),
        # `outputs/sift-tsk/fls.txt` is TSK output: the component is `sift-tsk`, which
        # normalises to `tsk`, so it matches `tsk` and NOT `fls`. Recording both is what
        # pins the rule - the first version staged a TSK listing as `fls` evidence
        # because it matched the file name loosely.
        (ES / "outputs/sift-tsk/fls.txt", "tsk", True),
        (ES / "outputs/sift-tsk/fls.txt", "fls", False),
        (ES / "outputs/threatfox/threatfox.json.zip", "threatfox", False),
    ]
    bad = [(p, fam, want) for p, fam, want in cases if matches(p, fam) != want]
    for p, fam, want in bad:
        print(f"    MISMATCH {fam}: {p.name} -> expected {want}")
    return not bad


def main() -> int:
    if not _selftest():
        print("  BAD the matcher's self-test failed; staging nothing")
        return 2

    prof = json.loads(PROF.read_text(encoding="utf-8"))
    absent = prof.get("absent_families") or {}

    manifest_path = CORPUS / "_staged.json"
    manifest = (json.loads(manifest_path.read_text(encoding="utf-8"))
                if manifest_path.is_file() else {"families": {}, "absent": {}})
    fams = manifest.setdefault("families", {})
    man_absent = manifest.setdefault("absent", {})

    staged, still = [], []
    for fam in sorted(absent):
        src = best_sample(fam)
        if src is None:
            still.append(fam)
            continue
        dest_dir = CORPUS / fam
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / f"{src.stem[:48]}-sample{src.suffix.lower()}"
        n = cap_rows(src, dest)
        fams[fam] = [str(dest)]
        man_absent.pop(fam, None)
        staged.append((fam, src, n, dest.stat().st_size))

    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"  staged one sample for {len(staged)} families:")
    for fam, src, n, size in staged:
        print(f"    {fam:18s} {n:>6,d} rows {size / 1024:>7.0f} KB <- "
              f"{src.relative_to(ES)}")
    print()
    print(f"  still absent (no parsed output anywhere in the corpus): {len(still)}")
    print("   ", still)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
