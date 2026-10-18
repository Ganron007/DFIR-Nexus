"""Archives in the evidence are expanded before the lane plans, and their contents planned like registered evidence.

Collections arrive archived: sample S08 is fifteen hosts' triage collections, each a .7z holding a drive tree
(``<host>/C/Windows/...``), and S09 keeps an EventLogs.7z whose Security logs differ from the loose ones beside it. The
lane planned none of it: the Windows planner saw an archive file, and the importer pass read zip and tar only, file by
file, so the event logs and hives inside never reached the tools that parse them (2026-10-18).

Each archive is expanded once into ``<case>/evidence/_expanded/<name>-<digest>/`` beside the case's evidence (not a
tool-output folder, so the lane plans it as evidence and the index never reads it as rows of its own). A file the
archive holds that is byte for byte a file already in the registered evidence is not kept twice. Every path the
archive names must land inside the expansion folder, or nothing is kept. The archive's SHA-256 and the expanded files
are recorded in ``.expanded.json``; an expansion whose archive is unchanged is reused.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

ARCHIVE_SUFFIXES = (".7z", ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".rar")
_MARKER = ".expanded.json"


def is_archive(path: Path) -> bool:
    name = path.name.lower()
    return path.is_file() and name.endswith(ARCHIVE_SUFFIXES)


def find_archives(paths: list[str]) -> list[Path]:
    """The archive files in the registered evidence: a registered archive, or one inside a registered folder."""
    out: list[Path] = []
    for raw in paths:
        p = Path(str(raw))
        if p.is_file() and is_archive(p):
            out.append(p)
        elif p.is_dir():
            for root, _dirs, files in os.walk(p, followlinks=False):
                out.extend(Path(root) / f for f in sorted(files) if is_archive(Path(root) / f))
    return out


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _seven_zip() -> str | None:
    return shutil.which("7z") or shutil.which("7za") or next(
        (str(p) for p in (Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "7-Zip" / "7z.exe",)
         if p.is_file()), None)


def _extract(archive: Path, dest: Path) -> None:
    """Extract ``archive`` into ``dest`` (7-Zip when present, else Python's zip and tar readers)."""
    seven = _seven_zip()
    if seven:
        # The member paths first: an absolute path or a '..' part could write outside `dest` before any check after.
        listing = subprocess.run([seven, "l", "-slt", "-ba", str(archive)], capture_output=True, text=True,
                                 timeout=600)
        if listing.returncode != 0:
            raise RuntimeError(f"7-Zip could not list the archive: {(listing.stderr or '').strip()[-300:]}")
        for line in listing.stdout.splitlines():
            if line.startswith("Path = "):
                member = line[len("Path = "):].replace("\\", "/")
                if member.startswith("/") or (len(member) > 1 and member[1] == ":") or ".." in member.split("/"):
                    raise RuntimeError(f"the archive names a path outside its folder ({member[:120]}); not expanded")
        proc = subprocess.run([seven, "x", "-y", "-bd", f"-o{dest}", str(archive)],
                              capture_output=True, text=True, timeout=7200)
        if proc.returncode != 0:
            raise RuntimeError(f"7-Zip rc={proc.returncode}: {(proc.stderr or proc.stdout or '').strip()[-300:]}")
        return
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as z:
            z.extractall(dest)
        return
    if tarfile.is_tarfile(archive):
        with tarfile.open(archive) as t:
            t.extractall(dest, filter="data")
        return
    raise RuntimeError(f"no extractor for {archive.name} (7-Zip is not installed)")


def _inside(dest: Path) -> bool:
    """Every extracted path resolves inside ``dest`` (no '..', absolute or link escape)."""
    root = dest.resolve()
    for p in dest.rglob("*"):
        try:
            p.resolve().relative_to(root)
        except ValueError:
            return False
    return True


def _evidence_digests(paths: list[str], archives: set[Path]) -> set[tuple[int, str]]:
    """(size, SHA-256) of every registered evidence file that is not an archive."""
    out: set[tuple[int, str]] = set()
    for raw in paths:
        p = Path(str(raw))
        files = [p] if p.is_file() else ([f for f in p.rglob("*") if f.is_file()] if p.is_dir() else [])
        for f in files:
            if f in archives or "_expanded" in f.parts:
                continue
            try:
                out.add((f.stat().st_size, _sha256(f)))
            except OSError:
                continue
    return out


def expand_archives(paths: list[str], case_dir: Path) -> list[dict[str, Any]]:
    """Expand each archive in the registered evidence; one record per archive (status OK or FAIL, with the root)."""
    archives = find_archives(paths)
    if not archives:
        return []
    base = Path(case_dir) / "evidence" / "_expanded"
    known: set[tuple[int, str]] | None = None
    records: list[dict[str, Any]] = []
    for archive in archives:
        digest = hashlib.sha1(str(archive.resolve()).encode("utf-8", "replace")).hexdigest()[:10]
        stem = archive.name.split(".")[0] or "archive"
        dest = base / f"{stem}-{digest}"
        record: dict[str, Any] = {"archive": str(archive), "root": str(dest), "status": "FAIL", "files": 0,
                                  "duplicates": 0, "reason": ""}
        try:
            archive_sha = _sha256(archive)
            marker = dest / _MARKER
            if marker.is_file():
                prior = json.loads(marker.read_text(encoding="utf-8"))
                if prior.get("archive_sha256") == archive_sha:
                    records.append({**record, **{k: prior[k] for k in ("files", "duplicates")}, "status": "OK",
                                    "reason": "expanded earlier; the archive is unchanged"})
                    continue
            work = dest.with_name(dest.name + ".part")
            shutil.rmtree(work, ignore_errors=True)
            work.mkdir(parents=True)
            _extract(archive, work)
            if not _inside(work):
                shutil.rmtree(work, ignore_errors=True)
                raise RuntimeError("the archive names a path outside its folder; nothing was kept")
            if known is None:
                known = _evidence_digests(paths, set(archives))
            kept: list[dict[str, Any]] = []
            duplicates = 0
            for f in sorted(p for p in work.rglob("*") if p.is_file()):
                size, sha = f.stat().st_size, _sha256(f)
                if (size, sha) in known:
                    f.unlink()
                    duplicates += 1
                    continue
                kept.append({"path": f.relative_to(work).as_posix(), "size": size, "sha256": sha})
            shutil.rmtree(dest, ignore_errors=True)
            work.rename(dest)
            (dest / _MARKER).write_text(json.dumps({
                "archive": str(archive), "archive_sha256": archive_sha, "files": len(kept),
                "duplicates": duplicates, "kept": kept,
            }, indent=1), encoding="utf-8")
            record.update(status="OK", files=len(kept), duplicates=duplicates,
                          reason=f"{len(kept)} file(s) expanded" + (f", {duplicates} identical to evidence already "
                                                                     "registered" if duplicates else ""))
        except Exception as exc:  # noqa: BLE001 - one archive that cannot be read is a gate row, not a lane failure
            log.warning("archive %s not expanded: %s", archive, exc)
            record["reason"] = str(exc)[:300]
        records.append(record)
    return records


def archive_gate_rows(records: list[dict[str, Any]]) -> list[dict[str, str]]:
    """The gate's row for each archive: expanded, or not read with the reason."""
    return [{"tool": "expand", "purpose": f"expand {r['archive']}", "family": "archive",
             "status": "OK" if r["status"] == "OK" else "FAIL", "reason": r["reason"]} for r in records]
