"""WO-KL2b (design time): rebuild the CAR pack from MITRE's repository.

`needles/car_analytics.yaml` mapped CAR ids to the **wrong** analytics. Verified
against the pinned snapshot of `github.com/mitre-attack/car` (commit recorded
below): **CAR-2014-11-004 is "Remote PowerShell Sessions"**, but the pack said
"Process Creation with Command Line" - and two LSASS analytics cited
CAR-2014-11-008, which is "Command Launched from WinLogon". Every CAR-cited
behavioural analytic inherited a wrong mapping.

This rebuilds the pack from the source: real ids, titles, ATT&CK coverage and
pseudocode, each carrying `source_key`. `--check` proves the file on disk is what
the snapshot produces.

The snapshot is read straight from the object database (`git show HEAD:<path>`)
rather than a working tree: the CAR repository contains a `docs/` path with a
colon in it, which Windows cannot check out.

Usage::

    python devtools/knowledge/car_import.py [--check]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "src" / "nexus" / "data" / "knowledge" / "needles" / "car_analytics.yaml"


def _snapshots() -> Path:
    return Path(os.environ.get("NEXUS_KL2B_SNAPSHOTS")
                or (Path(os.environ.get("TEMP", "/tmp")) / "kl2b-snapshots"))


def _git(car: Path, *args: str) -> str:
    # The CAR files are UTF-8; the Windows default codec (cp1252) cannot decode
    # some of them, which silently dropped 11 analytics on the first run.
    out = subprocess.run(["git", "-C", str(car), *args], capture_output=True,
                         text=True, encoding="utf-8", errors="replace", check=False)
    return out.stdout or ""


def build() -> dict[str, Any]:
    car = _snapshots() / "car"
    if not (car / ".git").exists():
        raise SystemExit(
            f"CAR snapshot not found at {car}. Clone github.com/mitre-attack/car there "
            f"and set NEXUS_KL2B_SNAPSHOTS.")

    listing = _git(car, "ls-tree", "-r", "--name-only", "HEAD", "analytics").split()
    paths = sorted(p for p in listing if p.endswith((".yaml", ".yml")))
    commit = _git(car, "rev-parse", "HEAD").strip()

    packs: list[dict[str, Any]] = []
    skipped: list[str] = []
    for path in paths:
        raw = _git(car, "show", f"HEAD:{path}")
        doc = yaml.safe_load(raw) if raw.strip() else None
        if not isinstance(doc, dict):
            skipped.append(path)
            continue
        ident = str(doc.get("id") or "").strip()
        if not ident:
            skipped.append(path)
            continue
        coverage = doc.get("coverage") or []
        techniques: list[str] = []
        tactics: list[str] = []
        for cov in coverage:
            if not isinstance(cov, dict):
                continue
            if cov.get("technique"):
                techniques.append(str(cov["technique"]))
            techniques.extend(str(s) for s in (cov.get("subtechniques") or []))
            tactics.extend(str(t) for t in (cov.get("tactics") or []))
        implementations = doc.get("implementations") or []
        pseudocode = ""
        if implementations and isinstance(implementations[0], dict):
            pseudocode = str(implementations[0].get("code") or "").strip()[:4000]
        data_model = doc.get("data_model_references") or []
        model_names: list[str] = []
        for ref in data_model:
            if isinstance(ref, dict):
                model_names.append(str(ref.get("model") or ""))
            elif isinstance(ref, str):
                model_names.append(ref)
        packs.append({
            "analytic": ident,
            "name": str(doc.get("title") or "").strip(),
            "technique": (techniques[0] if techniques else ""),
            "techniques": sorted(set(t for t in techniques if t)),
            "tactics": sorted({t for t in tactics if t}),
            "data_model": [m for m in model_names if m],
            "description": str(doc.get("description") or "").strip()[:1200],
            "pseudocode": pseudocode,
            "source_key": path,
        })

    packs.sort(key=lambda p: p["analytic"])
    return {
        "version": 2,
        "generated": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "generator": "devtools/knowledge/car_import.py",
        "description": ("MITRE Cyber Analytics Repository, imported from the pinned snapshot. "
                        "Do not edit by hand - re-run the importer."),
        "source": "https://github.com/mitre-attack/car",
        "source_version": commit,
        "source_key": "analytics/*.yaml",
        "skipped": skipped,
        "packs": packs,
    }


def _comparable(payload: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in payload.items() if k != "generated"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    payload = build()
    print(f"  CAR analytics: {len(payload['packs'])}  @{payload['source_version'][:10]}")
    known = {p['analytic'] for p in payload['packs']}
    for aid in ("CAR-2014-11-004", "CAR-2014-11-008"):
        title = next((p['name'] for p in payload['packs'] if p['analytic'] == aid), None)
        print(f"  {aid}: {title!r}")

    if args.check:
        on_disk = yaml.safe_load(OUT.read_text(encoding="utf-8")) or {}
        if _comparable(on_disk) != _comparable(payload):
            print("DRIFT: car_analytics.yaml is not what the snapshot produces", file=sys.stderr)
            return 1
        print("car_analytics.yaml matches the snapshot")
        return 0

    OUT.write_text(
        "# WO-KL2b - MITRE CAR, imported from a pinned snapshot.\n"
        "# Generator: devtools/knowledge/car_import.py. Do not edit by hand.\n"
        + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=1000),
        encoding="utf-8",
    )
    print(f"written: {OUT.relative_to(REPO)}  ({OUT.stat().st_size // 1024} KB)")
    # A sanitity check that would have caught the old pack.
    assert "CAR-2014-11-004" in known, "the pack must contain the ids it cites"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
