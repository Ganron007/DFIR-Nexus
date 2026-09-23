"""Compile MITRE MBC v3 (STIX 2.1 Malware Behavior Extension) into a registry.

Source: https://github.com/MBCProject/mbc-stix2.1 (`mbc/mbc.json`,
Apache-2.0, (C) The MITRE Corporation - attribution in ``mbc/NOTICE.txt``).
MBC is the malware-capability complement of ATT&CK: objectives (OBxxxx macro /
OCxxxx micro), behaviors (Bxxxx), methods (Bxxxx.xxx), malware families
(Xxxxx) and their capa/YARA detection rules.

The raw STIX bundle is gitignored; the compiled ``mbc_registry.yaml`` is
committed.

Usage:
    python scripts/build_mbc_registry.py            # use cached raw or fetch
    python scripts/build_mbc_registry.py --fetch    # force re-download
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MBC_DIR = ROOT / "src" / "nexus" / "data" / "knowledge" / "mbc"
RAW_PATH = MBC_DIR / "mbc.json"
OUT_PATH = MBC_DIR / "mbc_registry.yaml"
RAW_URL = "https://raw.githubusercontent.com/MBCProject/mbc-stix2.1/main/mbc/mbc.json"

_HTML_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def _clean(text: str, cap: int) -> str:
    text = _HTML_TAG.sub(" ", str(text or ""))
    return _WS.sub(" ", text).strip()[:cap]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest().upper()


def _fetch() -> None:
    print(f"fetching {RAW_URL}")
    with urllib.request.urlopen(RAW_URL, timeout=300) as r:
        data = r.read()
    RAW_PATH.write_bytes(data)
    print(f"wrote {RAW_PATH} ({len(data) / 1e6:.1f} MB)")


def _obj_id(obj: dict) -> str:
    return str((obj.get("obj_defn") or {}).get("external_id") or "").strip()


def _obj_desc(obj: dict) -> str:
    return str((obj.get("obj_defn") or {}).get("description") or "")


def _malware_ext(obj: dict) -> dict:
    for ext in (obj.get("extensions") or {}).values():
        if isinstance(ext, dict) and isinstance(ext.get("obj_defn"), dict):
            return ext
    return {}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="force re-download")
    args = parser.parse_args()

    MBC_DIR.mkdir(parents=True, exist_ok=True)
    if args.fetch or not RAW_PATH.is_file():
        _fetch()

    import yaml

    data = json.loads(RAW_PATH.read_text(encoding="utf-8"))
    objects = data.get("objects") or []
    by_stix = {str(o.get("id")): o for o in objects}

    objectives: dict[str, dict] = {}
    behaviors: dict[str, dict] = {}
    methods: dict[str, dict] = {}
    families: dict[str, dict] = {}

    for obj in objects:
        otype = obj.get("type")
        if otype == "malware-objective":
            oid = _obj_id(obj)
            if not oid:
                continue
            objectives[oid] = {
                "id": oid,
                "name": str(obj.get("name") or ""),
                "description": _clean(_obj_desc(obj), 300),
                "micro": bool(obj.get("micro")),
            }
        elif otype == "malware-behavior":
            bid = _obj_id(obj)
            if not bid:
                continue
            rules = [
                {
                    "rule_name": str(r.get("rule_name") or "")[:120],
                    "rule_type": str(r.get("rule_type") or ""),
                    "url": str(r.get("url") or ""),
                }
                for r in (obj.get("detection_rules") or [])
                if isinstance(r, dict) and r.get("rule_name")
            ]
            behaviors[bid] = {
                "id": bid,
                "name": str(obj.get("name") or ""),
                "description": _clean(_obj_desc(obj), 300),
                "version": str(obj.get("obj_version") or ""),
                "objectives": [
                    _obj_id(by_stix.get(str(ref), {}))
                    for ref in (obj.get("objective_refs") or [])
                ],
                "methods": [],
                "detection_rules": rules,
                "families": [],
            }
        elif otype == "malware-method":
            mid = _obj_id(obj)
            if not mid:
                continue
            parent = _obj_id(by_stix.get(str(obj.get("behavior_ref")), {}))
            methods[mid] = {
                "id": mid,
                "name": str(obj.get("name") or ""),
                "description": _clean(_obj_desc(obj), 240),
                "behavior": parent,
            }
        elif otype == "malware":
            ext = _malware_ext(obj)
            fid = str((ext.get("obj_defn") or {}).get("external_id") or "").strip()
            if not fid:
                continue
            families[fid] = {
                "id": fid,
                "name": str(obj.get("name") or ""),
                "description": _clean((ext.get("obj_defn") or {}).get("description"), 300),
                "platforms": [str(p) for p in (ext.get("platforms") or [])],
                "year": str(ext.get("year") or ""),
                "behaviors": [],
            }

    # method -> behavior link + behavior -> family links (uses relationships)
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        rtype = str(obj.get("relationship_type") or "")
        if rtype == "uses":
            src = by_stix.get(str(obj.get("source_ref")), {})
            dst = by_stix.get(str(obj.get("target_ref")), {})
            if src.get("type") == "malware" and dst.get("type") == "malware-behavior":
                fid = str(
                    (_malware_ext(src).get("obj_defn") or {}).get("external_id") or ""
                ).strip()
                bid = _obj_id(dst)
                if fid in families and bid in behaviors:
                    if fid not in families[fid]["behaviors"]:
                        families[fid]["behaviors"].append(bid)
                    if fid not in behaviors[bid]["families"]:
                        behaviors[bid]["families"].append(fid)

    for mid, method in methods.items():
        parent = method["behavior"]
        if parent in behaviors:
            behaviors[parent]["methods"].append({"id": mid, "name": method["name"]})

    registry = {
        "version": "v3 (STIX 2.1 Malware Behavior Extension)",
        "source": "https://github.com/MBCProject/mbc-stix2.1",
        "license": "Apache-2.0 (C) The MITRE Corporation - see mbc/NOTICE.txt",
        "raw_sha256": _sha256(RAW_PATH),
        "generated": datetime.now(UTC).isoformat(),
        "counts": {
            "objectives": len(objectives),
            "behaviors": len(behaviors),
            "methods": len(methods),
            "families": len(families),
            "detection_rules": sum(len(b["detection_rules"]) for b in behaviors.values()),
        },
        "objectives": sorted(objectives.values(), key=lambda o: o["id"]),
        "behaviors": sorted(behaviors.values(), key=lambda b: b["id"]),
        "methods": sorted(methods.values(), key=lambda m: m["id"]),
        "families": sorted(families.values(), key=lambda f: f["id"]),
    }
    OUT_PATH.write_text(
        yaml.safe_dump(registry, sort_keys=False, allow_unicode=True, width=120),
        encoding="utf-8",
    )
    print(f"wrote {OUT_PATH} ({OUT_PATH.stat().st_size / 1e3:.0f} KB)")
    print("counts:", json.dumps(registry["counts"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
