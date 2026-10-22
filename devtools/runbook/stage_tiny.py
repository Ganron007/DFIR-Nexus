"""Stage the tiny cases (TIER1-WORK-ORDERS Part 11) from the sealed selection, with neutral names.

    python devtools/runbook/stage_tiny.py --selection E:\\Evidence_files\\_tiny_sealed\\tiny-selection.yaml [--only T01,T02] [--check]

Each file is copied, verified by SHA-256 against its source, and marked read-only: a tool that must write works
on its own copy (D291). A staged path that contains a leak word (the selection's global list, or the case's own
``leak_terms``) stops the case before anything is copied. Writes:

- the public manifest (``public_manifest``): each case's group, route, evidence kinds, SIFT inputs, file count and
  bytes, and a file list with hashes (``tiny/<Txx>-files.tsv`` beside it). It names no source;
- the sealed map (``sealed_map``): staged path, source path and hash, read only to score a finished group.

Re-running is safe: an identical file is left as it is; a different file at a staged path stops the case.
``--check`` re-hashes the staged files against the public file lists and copies nothing; it reads only the public
manifest, so it needs no ``--selection``:

    python devtools/runbook/stage_tiny.py --check [--only T01]
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

import yaml

CHUNK = 1 << 20


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(CHUNK):
            h.update(block)
    return h.hexdigest()


def expand(src: str, sources: dict[str, str]) -> str:
    for key, value in sources.items():
        src = src.replace("{" + key + "}", value)
    return src


def plan_item(item: dict, sources: dict[str, str]) -> list[tuple[Path, str]]:
    """(source file, staged path relative to the case folder) for one selection item.

    The staged path is ``dst`` followed by the name the source carries (or the item's ``rename``)."""
    src = expand(item["src"], sources)
    dst = item.get("dst", "")
    exclude = [e.replace("\\", "/").strip("/") for e in item.get("exclude", [])]
    out: list[tuple[Path, str]] = []
    if any(ch in src for ch in "*?"):
        matches = sorted(Path(p) for p in glob.glob(src) if Path(p).is_file())
        if not matches:
            raise SystemExit(f"no file matches {src}")
        rename = item.get("rename")
        for n, path in enumerate(matches, start=1):
            name = rename.format(n=n) if rename else path.name
            out.append((path, dst + name))
        return out
    path = Path(src)
    if path.is_dir():
        for sub in sorted(p for p in path.rglob("*") if p.is_file()):
            rel = sub.relative_to(path).as_posix()
            if any(rel == e or rel.startswith(e + "/") for e in exclude):
                continue
            out.append((sub, dst + rel))
        if not out:
            raise SystemExit(f"no file under {src}")
        return out
    if not path.is_file():
        raise SystemExit(f"missing source {src}")
    return [(path, dst + path.name if dst.endswith("/") or not dst else dst)]


def leaks(rel: str, terms: set[str]) -> list[str]:
    tokens = {t for t in re.split(r"[^0-9a-z]+", rel.lower()) if t}
    return sorted(tokens & terms)


def copy_verified(src: Path, dest: Path) -> str:
    dest.parent.mkdir(parents=True, exist_ok=True)
    h = hashlib.sha256()
    tmp = dest.with_name(dest.name + ".staging")
    with src.open("rb") as fin, tmp.open("wb") as fout:
        while block := fin.read(CHUNK):
            h.update(block)
            fout.write(block)
    digest = h.hexdigest()
    if sha256(tmp) != digest:
        tmp.unlink()
        raise SystemExit(f"copy of {src} does not hash to its source")
    os.replace(tmp, dest)
    os.utime(dest, (src.stat().st_atime, src.stat().st_mtime))
    os.chmod(dest, stat.S_IREAD)
    return digest


def stage_case(cid: str, spec: dict, sel: dict, root: Path) -> dict:
    terms = {t.lower() for t in sel.get("global_leak_terms", [])} | {t.lower() for t in spec.get("leak_terms", [])}
    planned: list[tuple[Path, str]] = []
    checked: list[str] = []
    for item in spec["items"]:
        pairs = plan_item(item, sel["sources"])
        planned.extend(pairs)
        # names_are_evidence: the source's own names are the evidence's (a shortcut named after its target, a
        # prefetch file after its program, a task after its name) and are kept; only the folder chosen here is
        # checked. Otherwise every staged name is checked.
        checked.extend([item.get("dst", "")] if item.get("names_are_evidence") else [rel for _, rel in pairs])
    seen: set[str] = set()
    for _, rel in planned:
        if rel in seen:
            raise SystemExit(f"{cid}: two sources stage to {rel}")
        seen.add(rel)
    for rel in checked:
        hit = leaks(rel, terms)
        if hit:
            raise SystemExit(f"{cid}: staged path {rel!r} contains {hit}; give it a neutral name in the selection")
    rows = []
    for src, rel in planned:
        dest = root / cid / rel
        if dest.exists():
            digest = sha256(dest)
            if digest != sha256(src):
                raise SystemExit(f"{cid}: {rel} is already staged with different content; not overwriting evidence")
        else:
            digest = copy_verified(src, dest)
        rows.append((rel, dest.stat().st_size, digest, str(src)))
    return {"rows": rows}


def write_outputs(sel: dict, staged: dict[str, dict], root: Path) -> None:
    manifest_path = Path(sel["public_manifest"])
    lists = manifest_path.parent / "tiny"
    lists.mkdir(parents=True, exist_ok=True)
    manifest = {}
    if manifest_path.is_file():
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8")) or {}
    cases = manifest.setdefault("cases", {})
    for cid, result in staged.items():
        spec = sel["cases"][cid]
        rows = result["rows"]
        tsv = lists / f"{cid}-files.tsv"
        tsv.write_text("path\tbytes\tsha256\n" + "".join(f"{r}\t{b}\t{h}\n" for r, b, h, _ in rows),
                       encoding="utf-8", newline="\n")
        entry = cases.setdefault(cid, {})
        entry.update({
            "group": spec["group"],
            "route": spec["route"],
            "kinds": spec["kinds"],
            "folder": str(root / cid),
            "sift_inputs": spec.get("sift", []),
            "files": len(rows),
            "bytes": sum(b for _, b, _, _ in rows),
            "file_list": str(tsv),
        })
        entry.setdefault("case_id", None)
    manifest["note"] = ("Public manifest of the tiny cases (Part 11). It names no source; the sources are sealed. "
                        "case_id is written by devtools/runbook/tiny_cases.ps1.")
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False, allow_unicode=True), encoding="utf-8",
                             newline="\n")
    sealed = Path(sel["sealed_map"])
    old = {}
    if sealed.is_file():
        for line in sealed.read_text(encoding="utf-8").splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) == 4:
                old[(parts[0], parts[1])] = line
    for cid, result in staged.items():
        for k in [k for k in old if k[0] == cid]:
            del old[k]
        for rel, _, digest, src in result["rows"]:
            old[(cid, rel)] = f"{cid}\t{rel}\t{src}\t{digest}"
    sealed.write_text("case\tstaged\tsource\tsha256\n" + "".join(v + "\n" for _, v in sorted(old.items())),
                      encoding="utf-8", newline="\n")


def check(manifest_path: Path, only: set[str]) -> int:
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    bad = 0
    for cid, entry in manifest["cases"].items():
        if only and cid not in only:
            continue
        folder = Path(entry["folder"])
        for line in Path(entry["file_list"]).read_text(encoding="utf-8").splitlines()[1:]:
            rel, _, digest = line.split("\t")
            path = folder / rel
            if not path.is_file() or sha256(path) != digest:
                print(f"{cid}: {rel} missing or changed")
                bad += 1
        print(f"{cid}: checked")
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selection")
    ap.add_argument("--only", default="")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    only = {c.strip() for c in args.only.split(",") if c.strip()}
    if args.check:
        return check(Path(__file__).resolve().parents[2] / "Docs" / "internal" / "eval" / "tiny-cases.yaml", only)
    if not args.selection:
        ap.error("--selection (the sealed selection) is required to stage")
    sel = yaml.safe_load(Path(args.selection).read_text(encoding="utf-8"))
    root = Path(sel["staging_root"])
    staged = {}
    for cid, spec in sel["cases"].items():
        if only and cid not in only:
            continue
        staged[cid] = stage_case(cid, spec, sel, root)
        rows = staged[cid]["rows"]
        print(f"{cid}: {len(rows)} files, {sum(r[1] for r in rows) / 1e6:.1f} MB")
    write_outputs(sel, staged, root)
    return 0


if __name__ == "__main__":
    sys.exit(main())
