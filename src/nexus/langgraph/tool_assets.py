"""Citable metadata for binary products of image-extraction tools (D483).

The tools recover the images. This catalog describes their actual files, without interpreting their contents.
It is written inside the lane after successful extraction and is linked to that tool call's audit id. Backing
files participate in index freshness and verification, and indexing refuses a catalog whose files have changed.
"""
from __future__ import annotations

import csv
import hashlib
import json
import tempfile
from collections.abc import Iterable, Iterator
from pathlib import Path

from nexus.langgraph.timestamps import NO_EVENT_TIME_FIELD
from nexus.utils.atomic import replace

PRODUCERS = frozenset({"bmc-tools", "thumbcache_viewer"})
CATALOG_DIR = "asset_catalog"
RECORD_TYPE = "extracted_file_metadata"
COLUMNS = ("artifact_type", "file_path", "file_size", "file_hash_sha256", "source_tool", "source_audit_id",
           NO_EVENT_TIME_FIELD)


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _owned_file(root: Path, relative: str) -> Path:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("extracted-file catalog path must be relative to its extraction root")
    path = (root / rel).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError(f"extracted-file catalog source is absent or outside its run: {relative}")
    return path


def is_catalog(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return False
    return len(parts) == 3 and parts[0] in PRODUCERS and parts[1] == CATALOG_DIR and path.suffix == ".csv"


def write_catalog(tool: str, paths: Iterable[str], root: Path, audit_id: str, *, job_key: tuple) -> Path | None:
    """Catalog this successful job's binary products; never turn a tool's empty output into success."""
    if tool not in PRODUCERS:
        return None
    from fnmatch import fnmatchcase

    from nexus.langgraph.query_pack import EXTRACTION_PATTERNS

    root = root.resolve()
    files = sorted({Path(p).resolve() for p in paths
                    if not any(fnmatchcase(Path(p).name.lower(), pattern) for pattern in EXTRACTION_PATTERNS)})
    if not files:
        return None
    if not audit_id or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in audit_id):
        raise ValueError("extracted-file metadata requires the producing tool's audit id")
    # A retry updates the same job's catalog, rather than indexing its images twice under two audit ids.
    key = hashlib.sha256(json.dumps(job_key, separators=(",", ":")).encode()).hexdigest()
    destination = root / tool / CATALOG_DIR / f"{key}.csv"
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="", dir=destination.parent,
                                         prefix="_assets-", suffix=".tmp", delete=False) as stream:
            temp_path = Path(stream.name)
            writer = csv.DictWriter(stream, fieldnames=COLUMNS)
            writer.writeheader()
            for path in files:
                relative = path.relative_to(root).as_posix()  # an output outside this run is an error
                path = _owned_file(root, relative)
                writer.writerow({
                    "artifact_type": RECORD_TYPE, "file_path": relative, "file_size": path.stat().st_size,
                    "file_hash_sha256": _digest(path), "source_tool": tool, "source_audit_id": audit_id,
                    NO_EVENT_TIME_FIELD: "true",
                })
        replace(temp_path, destination)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()
    return destination


def validate_catalog_row(path: Path, root: Path, fields: dict | None) -> None:
    """A metadata citation describes the bytes the tool produced, never a changed or missing file."""
    if not is_catalog(path, root):
        return
    fields = fields or {}
    if fields.get("artifact_type") != RECORD_TYPE or fields.get("source_tool") != path.relative_to(root).parts[0]:
        raise ValueError(f"invalid extracted-file catalog row: {path.name}")
    asset = _owned_file(root, str(fields.get("file_path") or ""))
    if asset.stat().st_size != int(fields.get("file_size", -1)) or _digest(asset) != fields.get("file_hash_sha256"):
        raise ValueError(f"extracted file changed after the tool cataloged it: {fields.get('file_path')}")


def _catalog_rows(root: Path) -> Iterator[tuple[Path, dict]]:
    for tool in sorted(PRODUCERS):
        for catalog in sorted((root / tool / CATALOG_DIR).glob("*.csv")):
            with catalog.open(encoding="utf-8", newline="") as stream:
                for row in csv.DictReader(stream):
                    yield catalog, row


def catalog_inputs(root: Path) -> Iterator[Path]:
    """Backing files whose bytes the catalog describes, for freshness and index verify's source hashes."""
    for _catalog, row in _catalog_rows(root):
        relative = row.get("file_path") or ""
        _owned_file(root, relative)
        yield root / relative


def validate_catalogs(root: Path) -> None:
    """Validate before any index deletion, including incremental rebuilds whose change is only a backing image."""
    for catalog, row in _catalog_rows(root):
        validate_catalog_row(catalog, root, row)
