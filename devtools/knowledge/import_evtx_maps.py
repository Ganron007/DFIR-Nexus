"""WO-KL1b item 4: import the EvtxECmd maps from a pinned snapshot.

The mapping records EvtxECmd's `PayloadData1-6` as names with one (often empty)
example, but their content depends on the event ID. A knowledge query against
`fields.PayloadData1` on a Security 4624 row and a PowerShell 4100 row means two
different things, so a "generic column" needs its template.

`devtools/knowledge/import_evtx_maps.py` reads EZTools/evtx `Maps/*.map` at a pinned
commit (with per-file SHA-256), and writes
`src/nexus/data/schema/evtxecmd_maps.yaml`: per Channel + EventId, what each
`PayloadData*` / `ExecutableInfo` / `UserName` / `RemoteHost` holds - the map's value
template, e.g. `Target: %TargetDomainName%\\%TargetUserName%`.

Each entry carries `source`, `source_version` and `source_key`.

Usage::

    python devtools/knowledge/import_evtx_maps.py [--check]
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "src" / "nexus" / "data" / "schema" / "evtxecmd_maps.yaml"

#: The generic columns the WO names.
GENERIC = ("PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4",
           "PayloadData5", "PayloadData6", "ExecutableInfo", "UserName", "RemoteHost")


def _snapshots() -> Path:
    return Path(__file__).resolve().parents[2].parent.parent and (
        Path(__import__("os").environ.get("NEXUS_KL2B_SNAPSHOTS")
            or (Path(__import__("os").environ.get("TEMP", "/tmp")) / "kl2b-snapshots"))
    )


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build() -> dict[str, Any]:
    snap = _snapshots() / "evtx" / "evtx" / "Maps"
    if not snap.is_dir():
        raise SystemExit(
            f"EvtxECmd maps snapshot not found at {snap}. Clone "
            f"github.com/EricZimmerman/evtx there (NEXUS_KL2B_SNAPSHOTS).")
    repo = _snapshots() / "evtx" / "evtx"
    commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False).stdout.strip()

    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    problems: list[str] = []
    for path in sorted(snap.glob("*.map")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{path.name}: {type(exc).__name__}")
            continue
        if not isinstance(doc, dict):
            continue
        channel = str(doc.get("Channel") or "").strip().strip('"')
        provider = str(doc.get("Provider") or "").strip()
        event_id = str(doc.get("EventId") or "").strip()
        key = (channel, event_id)
        if key in seen:
            continue
        seen.add(key)
        columns: dict[str, dict[str, Any]] = {}
        for item in doc.get("Maps") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("Property") or "").strip()
            if name not in GENERIC:
                continue
            template = str(item.get("PropertyValue") or "").strip()
            values = [v for v in (item.get("Values") or []) if isinstance(v, dict)]
            columns[name] = {
                "template": template,
                # the XPath the map resolves and the refinement regex, so the
                # template is not a guess but the parser's own extraction
                "sources": [
                    {"xpath": str(v.get("Value") or ""), "refine": str(v.get("Refine") or "")}
                    for v in values[:4]
                ],
            }
        entries.append({
            "channel": channel,
            "provider": provider,
            "event_id": event_id,
            "description": str(doc.get("Description") or "").strip(),
            "source_key": path.name,
            "columns": columns,
        })

    entries.sort(key=lambda e: (e["channel"], e["event_id"]))
    return {
        "version": 1,
        "generated": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "generator": "devtools/knowledge/import_evtx_maps.py",
        "description": ("EvtxECmd maps imported from a pinned snapshot. A generic column's "
                        "template is what the map resolves, so its meaning is per "
                        "(Channel, EventId) - not a single per-column example."),
        "source": "https://github.com/EricZimmerman/evtx",
        "source_version": commit,
        "source_key": "Maps/*.map",
        "counts": {
            "entries": len(entries),
            "unparsed": len(problems),
            "entries_with_generic_columns": sum(1 for e in entries if e["columns"]),
        },
        "unparsed": problems[:20],
        "packs": entries,
    }


def _comparable(payload: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in payload.items() if k != "generated"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    payload = build()
    counts = payload["counts"]
    print(f"  EvtxECmd maps @{payload['source_version'][:10]}  "
          f"{counts['entries']} (Channel, EventId) entries, "
          f"{counts['entries_with_generic_columns']} with generic columns, "
          f"{counts['unparsed']} unparsed")

    if args.check:
        on_disk = yaml.safe_load(OUT.read_text(encoding="utf-8")) or {} if OUT.is_file() else {}
        if _comparable(on_disk) != _comparable(payload):
            print("DRIFT: evtxecmd_maps.yaml is not what the snapshot produces", file=sys.stderr)
            return 1
        print("evtxecmd_maps.yaml matches the snapshot")
        return 0

    OUT.write_text(
        "# WO-KL1b - EvtxECmd maps, imported from a pinned snapshot.\n"
        "# Generator: devtools/knowledge/import_evtx_maps.py. Do not edit by hand.\n"
        + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=1000),
        encoding="utf-8",
    )
    print(f"  written: {OUT.relative_to(REPO)}  ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
