#!/usr/bin/env python
"""Blind evidence: copy files to neutral names, keep the name map OUTSIDE the case.

WO-V10, optional companion to the operator manifest. GATE-H uses random,
unknown samples, and such a sample often arrives named after what it is
(`T1003-lsass-dump.evtx`, `Campaign-H-step-3/`, …). A name like that is the
answer walking into the case: the parser copies the source path into the row,
any reader sees it, and a model that reads it is being told the technique.

This copies each input file to a neutral name and writes the mapping beside the
output directory — **never inside a case**, or the answer would simply move.
Pair it with `accuracy_run.py --manifest`, which labels by SHA-256 so the
neutral names cost nothing: the hash is unchanged by a rename.

    python scripts/blind_evidence.py SRC_DIR --out blinded/
    python scripts/blind_evidence.py a.evtx b.evtx --out blinded/ --map names.json

Read-only with respect to the sources. The map is the only record of the
original names, so keep it outside the case beside `--out`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path


def _is_case_dir(path: Path) -> bool:
    """A case directory carries its identity: CASE.yaml or the evidence registry."""
    try:
        return path.is_dir() and (
            (path / "CASE.yaml").is_file()
            or (path / "evidence.json").is_file()
            or (path / "findings.json").is_file()
        )
    except OSError:
        return False


def _inside_a_case(path: Path) -> Path | None:
    """The nearest case directory containing *path*, if any."""
    for candidate in [path, *path.parents]:
        if _is_case_dir(candidate):
            return candidate
    return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_sources(paths: list[str]) -> list[Path]:
    """Every file named, or every file under a named directory (recursive)."""
    out: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            out.extend(sorted(p for p in path.rglob("*") if p.is_file()))
        elif path.is_file():
            out.append(path)
    return out


def blind(sources: list[Path], out_dir: Path, *, prefix: str = "sample") -> list[dict]:
    """Copy each source to ``<out>/<prefix>-NNNN<suffix>``; return the map rows."""
    out_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict] = []
    for index, source in enumerate(sources, start=1):
        # Keep the suffix: parsers dispatch on it, and it says nothing about
        # which sample this is once the stem is neutral.
        neutral = f"{prefix}-{index:04d}{source.suffix.lower()}"
        target = out_dir / neutral
        if target.exists():
            raise FileExistsError(f"refusing to overwrite {target}")
        shutil.copy2(source, target)
        rows.append({
            "blind": neutral,
            "source_name": source.name,
            "source_dir": str(source.parent),
            "sha256": _sha256(target),
            "bytes": target.stat().st_size,
        })
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", nargs="+", help="files or directories to blind")
    parser.add_argument("--out", required=True, help="directory for the neutral copies")
    parser.add_argument(
        "--map",
        default="",
        help="name-map path (default: <out>/../<out-name>-name-map.json, beside the output)",
    )
    parser.add_argument("--prefix", default="sample", help="neutral stem (default: sample)")
    args = parser.parse_args(argv)

    out_dir = Path(args.out)
    map_path = Path(args.map) if args.map else out_dir.resolve().parent / f"{out_dir.name}-name-map.json"

    # The map must not land inside the case, or the blinding is undone.
    for label, where in (("--out", out_dir), ("--map", map_path)):
        case = _inside_a_case(where.resolve())
        if case is not None:
            print(
                f"refusing to write {label} inside a case directory ({case}): "
                "the name map must live outside the case",
                file=sys.stderr,
            )
            return 2

    sources = iter_sources(args.sources)
    if not sources:
        print("no files to blind", file=sys.stderr)
        return 2

    rows = blind(sources, out_dir, prefix=args.prefix)
    map_path.parent.mkdir(parents=True, exist_ok=True)
    map_path.write_text(
        json.dumps(
            {
                "created_at": datetime.now(UTC).isoformat(),
                "out_dir": str(out_dir),
                "prefix": args.prefix,
                "count": len(rows),
                "files": rows,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    print(f"blinded {len(rows)} file(s) -> {out_dir}")
    print(f"name map: {map_path}")
    print("next: accuracy_run.py --manifest <manifest> (labels by sha256, so renames are free)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
