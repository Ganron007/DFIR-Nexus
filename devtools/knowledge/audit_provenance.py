"""WO-KL2b (design time): provenance audit of every pack under data/knowledge.

Classifies each file as **generated from a pinned source** (it names a source and a
version/commit/hash, or a generator writes it) or **hand-written**. A hand-written
pack that carries external ids or hashes is the KL2b problem: it must be regenerated
by an importer or stripped of those ids.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
ROOT = REPO / "src" / "nexus" / "data" / "knowledge"

#: Fields that indicate the file says where it came from. `itm_version` /
#: `mitre_version` mark the ITM vendor bundle, which publishes its own versions.
_PROV_KEYS = ("source", "source_url", "source_version", "generator", "commit", "version",
              "itm_version", "mitre_version")
#: Evidence that a file asserts external facts by id or hash.
_ID_PATTERNS = {
    "sha256": re.compile(r"\b[0-9a-f]{64}\b"),
    "sha1": re.compile(r"\b[0-9a-f]{40}\b"),
    "md5": re.compile(r"\b[0-9a-f]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,}\b"),
    "car": re.compile(r"\bCAR-\d{4}-\d{2}-\d{3}\b"),
    "sigma": re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"),
}


def _scan(path: Path) -> tuple[dict[str, Any], str]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return {}, "unreadable"
    if isinstance(doc, dict):
        keys = {str(k) for k in doc}
        prov = sorted(keys & set(_PROV_KEYS))
        gen = str(doc.get("generator") or "")
        # A STIX bundle is vendor data (MITRE ATT&CK / MBC / ITM), not hand-written:
        # it carries its own spec version and is refreshed as a unit.
        if str(doc.get("type") or "") == "bundle" or "spec_version" in keys:
            prov = sorted(set(prov) | {"spec_version"})
    else:
        prov, gen = [], ""
    return {"prov": prov, "generator": gen}, ""


def main() -> int:
    rows: list[dict[str, Any]] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.suffix not in (".yaml", ".yml", ".json"):
            continue
        meta, err = _scan(path)
        found: dict[str, int] = {}
        if not meta.get("prov"):
            # Only scan for embedded ids when the file does NOT already declare a
            # source; a vendor bundle's ids are expected and the regex over MITRE's
            # STIX (179k uuids) is the slowest thing in this audit.
            text = path.read_text(encoding="utf-8", errors="replace")
            found = {name: len(rx.findall(text)) for name, rx in _ID_PATTERNS.items()}
            found = {k: v for k, v in found.items() if v}
        generated = bool(meta.get("generator")) or bool(meta.get("prov"))
        rows.append({
            "path": path.relative_to(ROOT).as_posix(),
            "kb": path.stat().st_size // 1024,
            "generated": generated,
            "prov": meta.get("prov") or [],
            "ids": found,
            "err": err,
        })

    gen = [r for r in rows if r["generated"]]
    hand = [r for r in rows if not r["generated"]]
    risky = [r for r in hand if r["ids"]]
    print(f"  files: {len(rows)}  generated: {len(gen)}  hand-written: {len(hand)}")
    print(f"  hand-written that assert external ids/hashes: {len(risky)}")
    print()
    print("  --- hand-written with external ids (the KL2b problem) ---")
    for r in sorted(risky, key=lambda r: -sum(r["ids"].values()))[:24]:
        print(f"    {r['path']:56s} {r['ids']}")
    print()
    print("  --- generated from a pinned source ---")
    for r in gen:
        print(f"    {r['path']:56s} prov={r['prov']}")
    (Path(__file__).parent / "provenance-audit.json").write_text(
        json.dumps(rows, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
