"""Unified evidence registry service — SQLite is the system of record.

All evidence write paths (Examiner Portal, MCP ``evidence_register``, tool
output sidecars) register through this module so there is exactly one
authoritative list per case. ``evidence.json`` remains a flat mirror for
legacy consumers (report CLI, MCP list/verify); ``evidence_registry.json``
is a legacy artefact that is imported one time and then ignored.

Why this module exists: the portal used to read ``evidence_registry.json``
while every modern write path produced ``evidence.json`` — registered
evidence never appeared in the UI. One reader, one writer, one truth.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any

from nexus.config import settings

log = logging.getLogger(__name__)

_FLAT_FILES = ("evidence.json", "evidence_registry.json")


def hash_evidence_path(path: Path) -> tuple[str, int, int]:
    """Deterministic SHA-256 for a file or directory tree + counts.

    Semantics must stay byte-identical to ``nexus.case_manager._hash_evidence_path``
    so the same path registered through the portal or MCP yields the same
    digest (there is a parity test guarding this).
    """
    path = Path(path)
    if path.is_file():
        return _hash_file(path), 1, path.stat().st_size
    if not path.is_dir():
        raise FileNotFoundError(f"Evidence path not found: {path}")
    manifest = hashlib.sha256()
    count = 0
    total_bytes = 0
    children = sorted(
        (p for p in path.rglob("*") if p.is_file()),
        key=lambda p: p.relative_to(path).as_posix(),
    )
    for child in children:
        relative = child.relative_to(path).as_posix()
        size = child.stat().st_size
        file_hash = _hash_file(child)
        manifest.update(f"{relative}\0{size}\0{file_hash}\n".encode())
        count += 1
        total_bytes += size
    return manifest.hexdigest(), count, total_bytes


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _manager():
    from nexus.case import CaseManager

    return CaseManager(settings.cases_root / "cases.db")


def list_evidence(case_dir: Path) -> list[dict[str, Any]]:
    """Return registered evidence for a case from the SQLite system of record.

    If SQLite has no evidence rows for the case, the flat registries
    (``evidence.json`` / legacy ``evidence_registry.json``) are imported one
    time before listing.
    """
    case_dir = Path(case_dir)
    mgr = _manager()
    try:
        records = mgr.list_evidence(case_dir.name)
        if not records:
            _backfill_flat(case_dir, mgr)
            records = mgr.list_evidence(case_dir.name)
        return [_serialize(record) for record in records]
    finally:
        mgr.close()


def register_evidence(
    case_dir: Path,
    path_str: str,
    description: str = "",
    examiner: str = "system",
) -> dict[str, Any]:
    """Register a file or directory into the case's SQLite evidence registry.

    Idempotent for unchanged content; raises ``ValueError`` when the same path
    is re-registered with changed content.
    """
    case_dir = Path(case_dir)
    evidence_path = Path(path_str).resolve()
    if not evidence_path.exists():
        raise FileNotFoundError(f"Evidence path not found: {path_str}")
    digest, file_count, total_bytes = hash_evidence_path(evidence_path)

    mgr = _manager()
    try:
        canonical = os.path.normcase(str(evidence_path))
        for record in mgr.list_evidence(case_dir.name):
            if os.path.normcase(str(record.file_path or "")) != canonical:
                continue
            if record.file_hash_sha256 == digest:
                return {
                    "status": "already_registered",
                    "path": str(evidence_path),
                    "sha256": digest,
                    "files": file_count,
                    "total_bytes": total_bytes,
                    "registered_at": (
                        record.collected_at.isoformat() if record.collected_at else ""
                    ),
                    "evidence_id": record.id,
                }
            raise ValueError(
                "Evidence path is already registered but its content changed; "
                "preserve it and register the changed copy from a new path"
            )

        if mgr.get_case(case_dir.name) is None:
            raise ValueError(f"Case not found in registry: {case_dir.name}")

        record = mgr.add_evidence(
            case_id=case_dir.name,
            name=evidence_path.name,
            description=description[:500],
            file_path=str(evidence_path),
            file_hash_sha256=digest,
            collected_by=examiner,
            metadata={
                "kind": "file" if evidence_path.is_file() else "directory",
                "files": file_count,
                "total_bytes": total_bytes,
            },
        )
        return {
            "status": "registered",
            "path": str(evidence_path),
            "sha256": digest,
            "files": file_count,
            "total_bytes": total_bytes,
            "evidence_id": record.id if record else "",
            "registered_at": (
                record.collected_at.isoformat() if record and record.collected_at else ""
            ),
        }
    finally:
        mgr.close()


def verify_evidence(case_dir: Path) -> dict[str, Any]:
    """Re-hash every registered item and compare against the recorded digest."""
    results: list[dict[str, Any]] = []
    all_ok = True
    for record in list_evidence(case_dir):
        fpath = Path(record["path"]) if record.get("path") else None
        if not fpath or not fpath.exists():
            results.append({
                "name": record.get("name", ""),
                "file_path": record.get("path", ""),
                "valid": False,
                "error": "File not found on disk",
            })
            all_ok = False
            continue
        try:
            digest, _count, _total = hash_evidence_path(fpath)
            valid = digest == record.get("sha256")
            results.append({
                "name": record.get("name", ""),
                "file_path": str(fpath),
                "valid": valid,
                "expected_hash": record.get("sha256", ""),
                "actual_hash": digest,
            })
            all_ok = all_ok and valid
        except OSError as exc:
            results.append({
                "name": record.get("name", ""),
                "file_path": str(fpath),
                "valid": False,
                "error": str(exc),
            })
            all_ok = False
    return {"ok": True, "status": "verified" if all_ok else "issues_found", "results": results}


def _serialize(record) -> dict[str, Any]:
    """Mirror the flat ``evidence.json`` shape (portal + legacy consumers)."""
    meta = dict(record.metadata or {})
    return {
        "id": record.id,
        "path": record.file_path or "",
        "sha256": record.file_hash_sha256 or "",
        "description": record.description or record.name,
        "examiner": record.collected_by,
        "registered_at": (
            record.collected_at.isoformat() if record.collected_at else ""
        ),
        "status": "registered",
        "name": record.name,
        "kind": str(meta.get("kind") or ("directory" if meta.get("files") else "file")),
        "files": meta.get("files"),
        "total_bytes": meta.get("total_bytes"),
        "host": meta.get("host") or "",
        "user": meta.get("user") or "",
        "source_ip": meta.get("source_ip") or "",
        "dest_ip": meta.get("dest_ip") or "",
        "process_name": meta.get("process_name") or "",
        "technique_ids": meta.get("technique_ids") or [],
    }


def _backfill_flat(case_dir: Path, mgr) -> None:
    """Import flat evidence registries into SQLite (one-time legacy migration)."""
    from nexus.case.compat import dict_to_evidence

    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name in _FLAT_FILES:
        path = case_dir / name
        if not path.is_file():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        items = raw if isinstance(raw, list) else (raw.get("files") or raw.get("items") or [])
        for item in items:
            if not isinstance(item, dict):
                continue
            canonical = os.path.normcase(str(item.get("path") or ""))
            if not canonical or canonical in seen:
                continue
            seen.add(canonical)
            entries.append(item)
    if not entries:
        return

    if mgr.get_case(case_dir.name) is None:
        meta: dict[str, Any] = {}
        meta_path = case_dir / "CASE.yaml"
        if meta_path.is_file():
            try:
                import yaml

                loaded = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
                if isinstance(loaded, dict):
                    meta = loaded
            except Exception:  # noqa: BLE001 — backfill is best-effort
                meta = {}
        with contextlib.suppress(ValueError):
            mgr.create_case(
                name=str(meta.get("name") or case_dir.name),
                description=str(meta.get("description") or ""),
                created_by=str(meta.get("created_by") or "system"),
                case_id=case_dir.name,
            )

    for item in entries:
        record = dict_to_evidence({**item, "case_id": case_dir.name})
        try:
            mgr.store.save_evidence(record)
        except Exception as exc:  # noqa: BLE001 — never fail a list on backfill
            log.warning("Evidence backfill failed for %s: %s", item.get("path"), exc)
    log.info("Backfilled %d flat evidence entries for %s", len(entries), case_dir.name)
