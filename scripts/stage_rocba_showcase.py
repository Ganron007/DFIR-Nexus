#!/usr/bin/env python3
"""Stage a Rocba-only showcase evidence pack (FOR500 / fredr).

Sources (one environment — no CADRE monitor, no linux01, no 508 Amadey):
  H:\\                 mounted Rocba_Triage (C\\ extract)
  E:\\Evidence_files\\500   course bundle (Precooked, Cloud_Logs, Memory, E01)

Writes:
  Evidence-files/showcase/rocba-500/
    MANIFEST.md
    SOURCES.json
    host/          -> junction or copy of staged rocba-fredr (or fresh from H:)
    precooked/     -> E:\\…\\500\\Precooked (selected)
    cloud/         -> E:\\…\\500\\Cloud_Logs
    memory/        -> pointers + any small dumps
    kape/          -> optional mft.csv junction

Usage:
  python scripts/stage_rocba_showcase.py
  python scripts/stage_rocba_showcase.py --refresh-from-h
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "Evidence-files" / "showcase" / "rocba-500"
EXISTING_HOST = ROOT / "Evidence-files" / "01-windows" / "rocba-fredr"
EXISTING_KAPE = ROOT / "Evidence-files" / "01-windows" / "kape-out"
EXISTING_PRECOOKED = ROOT / "Evidence-files" / "01-windows" / "500-precooked"

H_ROOT = Path("H:/C")
E_500 = Path(r"E:\Evidence_files\500")


def sha256_file(path: Path, limit: int | None = 64 * 1024 * 1024) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    n = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            n += len(chunk)
            if limit is not None and n >= limit:
                return h.hexdigest() + f" (first {n} bytes)"
    return h.hexdigest()


def _is_linkish(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
    except OSError:
        pass
    # Windows junction: not always reported as symlink
    try:
        return bool(path.exists() and not os.path.isdir(path.resolve()) and path.is_dir())
    except OSError:
        return path.exists()


def junction_or_copy(src: Path, dst: Path) -> str:
    if dst.exists() or dst.is_symlink():
        return "exists"
    dst.parent.mkdir(parents=True, exist_ok=True)
    if not src.exists():
        return "missing-src"
    if sys.platform == "win32" and src.is_dir():
        cp = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(dst), str(src)],
            capture_output=True,
            text=True,
        )
        if cp.returncode == 0:
            return "junction"
    if src.is_dir():
        shutil.copytree(src, dst, dirs_exist_ok=True)
        return "copytree"
    shutil.copy2(src, dst)
    return "copy"


def copy_file(src: Path, dst: Path) -> str:
    if not src.is_file():
        return "missing"
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() and dst.stat().st_size == src.stat().st_size:
        return "skip-same"
    shutil.copy2(src, dst)
    return "copied"


def refresh_key_from_h(host: Path) -> list[str]:
    """Pull a few authoritative files from mounted H: into host/."""
    notes: list[str] = []
    if not H_ROOT.is_dir():
        return ["H:/C not mounted — skip refresh"]
    mapping = [
        (H_ROOT / "Windows/System32/winevt/Logs/Security.evtx", host / "evtx/Security.evtx"),
        (H_ROOT / "Windows/System32/winevt/Logs/System.evtx", host / "evtx/System.evtx"),
        (H_ROOT / "Windows/AppCompat/Programs/Amcache.hve", host / "amcache/Amcache.hve"),
        (H_ROOT / "Windows/System32/config/SYSTEM", host / "registry/SYSTEM"),
        (H_ROOT / "Windows/System32/config/SOFTWARE", host / "registry/SOFTWARE"),
        (H_ROOT / "Windows/System32/sru/SRUDB.dat", host / "srum/SRUDB.dat"),
        (H_ROOT / "$MFT", host / "ntfs/$MFT"),
    ]
    chrome = H_ROOT / "Users/fredr/AppData/Local/Google/Chrome/User Data/Default/History"
    if chrome.is_file():
        mapping.append((chrome, host / "browser/Chrome-History"))
    for src, dst in mapping:
        try:
            if not src.exists():
                notes.append(f"missing {src}")
                continue
            # if host is a junction to rocba-fredr, writing updates that tree — OK
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            notes.append(f"refreshed {dst.relative_to(host)}")
        except Exception as exc:
            notes.append(f"fail {src.name}: {exc}")
    return notes


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh-from-h", action="store_true", help="Re-copy key files from H:/C")
    ap.add_argument("--force", action="store_true", help="Remove OUT and rebuild")
    args = ap.parse_args()

    if args.force and OUT.exists():
        # Only remove non-junction children carefully
        shutil.rmtree(OUT, ignore_errors=True)

    OUT.mkdir(parents=True, exist_ok=True)
    actions: dict[str, str] = {}

    # host/
    host = OUT / "host"
    if EXISTING_HOST.is_dir():
        actions["host"] = junction_or_copy(EXISTING_HOST, host)
    elif H_ROOT.is_dir():
        host.mkdir(exist_ok=True)
        actions["host"] = "empty-dir-will-refresh"
    else:
        actions["host"] = "MISSING — need H: or Evidence-files/01-windows/rocba-fredr"

    if args.refresh_from_h or actions.get("host") == "empty-dir-will-refresh":
        for note in refresh_key_from_h(host if host.exists() else EXISTING_HOST):
            actions[f"h-refresh:{note[:80]}"] = "ok"

    # precooked/
    precooked = OUT / "precooked"
    if E_500.joinpath("Precooked").is_dir():
        actions["precooked"] = junction_or_copy(E_500 / "Precooked", precooked)
    elif EXISTING_PRECOOKED.is_dir():
        actions["precooked"] = junction_or_copy(EXISTING_PRECOOKED, precooked)
    else:
        actions["precooked"] = "missing"

    # cloud/
    cloud = OUT / "cloud"
    cloud.mkdir(exist_ok=True)
    for name in ("AuditLog_2020-09-10_2020-10-04.csv", "UnifiedAuditLog_SRL.csv"):
        src = E_500 / "Cloud_Logs" / name
        actions[f"cloud/{name}"] = copy_file(src, cloud / name)

    # kape/
    kape = OUT / "kape"
    if EXISTING_KAPE.joinpath("mft.csv").is_file():
        actions["kape/mft.csv"] = junction_or_copy(EXISTING_KAPE, kape)
    elif (E_500 / "Exercises" / "MFT").is_dir():
        actions["kape"] = junction_or_copy(E_500 / "Exercises" / "MFT", kape)
    else:
        actions["kape"] = "missing"

    # memory/ — pointers only for multi-GB files
    memory = OUT / "memory"
    memory.mkdir(exist_ok=True)
    pointers = {
        "Rocba-Memory.raw": E_500 / "Rocba-Memory.raw",
        "Rocba-Triage.vhdx": E_500 / "Rocba-Triage.vhdx",
        "rocba-cdrive.e01": E_500 / "C-Drive" / "rocba-cdrive.e01",
        "H_mount": Path("H:/"),
    }
    ptr_doc = []
    for label, p in pointers.items():
        exists = p.exists()
        size = p.stat().st_size if p.is_file() else None
        ptr_doc.append({
            "label": label,
            "path": str(p),
            "exists": exists,
            "bytes": size,
            "note": "Not copied into pack (size). Case run may reference absolute path.",
        })
    (memory / "POINTERS.json").write_text(json.dumps(ptr_doc, indent=2), encoding="utf-8")
    actions["memory/POINTERS.json"] = "written"

    # Explicit EXCLUSIONS so we never mix labs
    exclusions = [
        "Evidence-files/04-network/monitor-live (CADRE .55 Zeek/Suricata)",
        "Evidence-files/03-linux (linux01)",
        "Evidence-files/02-memory/rocba-508/vol3-amadey (FOR508 Amadey — different case)",
        "Evidence-files/01-windows/504-win10-ws",
        "Yamato public EVTX packs (unrelated)",
    ]

    sources = {
        "staged_at": datetime.now(UTC).isoformat(),
        "environment": "FOR500 Rocba / user fredr",
        "pack_root": str(OUT),
        "actions": actions,
        "pointers": ptr_doc,
        "exclusions": exclusions,
        "host_case_txt": (EXISTING_HOST / "CASE.txt").read_text(encoding="utf-8", errors="replace")
        if (EXISTING_HOST / "CASE.txt").is_file() else None,
    }
    (OUT / "SOURCES.json").write_text(json.dumps(sources, indent=2), encoding="utf-8")

    # MANIFEST
    host_files = []
    if host.is_dir():
        for p in sorted(host.rglob("*")):
            if p.is_file() and p.stat().st_size < 200_000_000:
                host_files.append(f"- `{p.relative_to(OUT).as_posix()}` ({p.stat().st_size} B)")
            elif p.is_file():
                host_files.append(f"- `{p.relative_to(OUT).as_posix()}` ({p.stat().st_size} B) [large]")

    lines = [
        "# Showcase pack — Rocba 500 (fredr)",
        "",
        f"Staged: `{sources['staged_at']}`",
        "",
        "## Environment (single case)",
        "",
        "| Field | Value |",
        "|-------|-------|",
        "| Course / case | FOR500 Rocba |",
        "| Host user | `fredr` |",
        "| Disk triage mount | `H:\\` (volume Rocba_Triage) → `H:\\C` |",
        "| Course bundle | `E:\\Evidence_files\\500` |",
        "| Pack root | `Evidence-files/showcase/rocba-500/` |",
        "",
        "## What is in this pack",
        "",
        "### host/ — Windows triage artifacts",
        "",
        *(host_files[:80] if host_files else ["- _(empty — run with --refresh-from-h)_"]),
        "",
        f"_… listing capped; see tree under `{OUT / 'host'}`._",
        "",
        "### precooked/ — EZ / course precooked outputs",
        "",
        "- PECmd / LECmd / RBCmd / JumpList CSVs",
        "- Chrome.xlsx / Edge.xlsx / SRUM xlsx",
        "- EventLogs/ (Security + archives)",
        "",
        "### cloud/ — M365 / Unified Audit (same Rocba cloud labs)",
        "",
        "- `AuditLog_2020-09-10_2020-10-04.csv`",
        "- `UnifiedAuditLog_SRL.csv`",
        "",
        "### kape/ — MFT bodyfile / CSV",
        "",
        "- `mft.csv` (when staged)",
        "",
        "### memory/ — pointers only",
        "",
        "| Label | Path | Present |",
        "|-------|------|---------|",
    ]
    for row in ptr_doc:
        lines.append(
            f"| {row['label']} | `{row['path']}` | {'yes' if row['exists'] else 'NO'} |"
        )
    lines += [
        "",
        "## Explicitly excluded (other environments)",
        "",
    ]
    for ex in exclusions:
        lines.append(f"- {ex}")
    lines += [
        "",
        "## Next: case run",
        "",
        "```text",
        "python scripts/e2e_rocba_showcase.py",
        "```",
        "",
        "Produces a DFIR Report–style narrative from **only** this pack.",
        "",
    ]
    (OUT / "MANIFEST.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"PACK {OUT}")
    for k, v in actions.items():
        print(f"  {k}: {v}")
    print(f"MANIFEST {OUT / 'MANIFEST.md'}")
    return 0 if actions.get("host") not in (None, "MISSING — need H: or Evidence-files/01-windows/rocba-fredr") else 1


if __name__ == "__main__":
    raise SystemExit(main())
