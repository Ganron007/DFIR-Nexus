"""Compile MITRE ATT&CK (enterprise + ICS + mobile) into a deep registry YAML.

Upgrades the shallow sync (``sources/attack_techniques.yaml``: id/name/tactics/
platforms) to what v19 actually ships - resolved through the STIX relationship
graph:

- techniques: description, tactics, platforms, sub-technique parents,
  deprecated/revoked flags + ``revoked-by`` redirects;
- **detection strategies** (``x-mitre-detection-strategy`` + ``x-mitre-analytic``)
  - ATT&CK's detection guidance, the external analog of ITM's Detections;
- **mitigations** (``mitigates`` -> course-of-action);
- **procedure examples** (``uses`` -> intrusion-set/malware/tool/campaign).

Source: https://github.com/mitre-attack/attack-stix-data (CC BY 4.0, © The MITRE
Corporation - attribution in ``attack/NOTICE.txt``). Raw JSON files are
gitignored; this compiled YAML is committed and versioned by the hashes below.

Usage:
    python scripts/build_attack_registry.py            # use cached JSON or fetch
    python scripts/build_attack_registry.py --fetch    # force re-download
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ATTACK_DIR = ROOT / "src" / "nexus" / "data" / "knowledge" / "attack"
OUT_PATH = ATTACK_DIR / "attack_registry.yaml"

BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
MATRICES = {
    "enterprise": f"{BASE}/enterprise-attack/enterprise-attack.json",
    "ics": f"{BASE}/ics-attack/ics-attack.json",
    "mobile": f"{BASE}/mobile-attack/mobile-attack.json",
}

_HTML_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")

_DESC_CAP = 350
_ANALYTIC_CAP = 220
_MAX_STRATEGIES = 2
_MAX_ANALYTICS = 2
_MAX_MITIGATIONS = 4
_MAX_PROCEDURES = 6


def _clean(text: str, cap: int) -> str:
    text = _HTML_TAG.sub(" ", str(text or ""))
    text = text.replace("&nbsp;", " ").replace("&amp;", "&")
    return _WS.sub(" ", text).strip()[:cap]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest().upper()


def _fetch(name: str, url: str) -> Path:
    path = ATTACK_DIR / f"{name}-attack.json"
    if path.is_file():
        return path
    print(f"fetching {name}: {url}")
    with urllib.request.urlopen(url, timeout=300) as r:
        data = r.read()
    path.write_bytes(data)
    print(f"  wrote {path.name} ({len(data) / 1e6:.1f} MB)")
    return path


def _ext_id(obj: dict) -> str:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return ""


def _tactics(obj: dict) -> list[str]:
    out: list[str] = []
    for phase in obj.get("kill_chain_phases") or []:
        name = str(phase.get("phase_name") or "").strip()
        if name and name not in out:
            out.append(name)
    return out


def compile_matrix(path: Path, matrix: str, techniques: dict[str, dict]) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    objects = data.get("objects") or []
    by_stix = {str(o.get("id")): o for o in objects}

    strategies = {
        str(o.get("id")): o for o in objects
        if o.get("type") == "x-mitre-detection-strategy"
    }
    analytics = {
        str(o.get("id")): o for o in objects
        if o.get("type") == "x-mitre-analytic"
    }
    counts = {
        "techniques": 0, "strategies": 0, "analytics": 0,
        "mitigations": 0, "procedures": 0,
    }

    # technique -> links
    tech_strategies: dict[str, list[str]] = defaultdict(list)
    tech_mitigations: dict[str, list[str]] = defaultdict(list)
    tech_procedures: dict[str, list[str]] = defaultdict(list)
    parents: dict[str, str] = {}
    revoked_by: dict[str, str] = {}

    for rel in objects:
        if rel.get("type") != "relationship":
            continue
        rtype = str(rel.get("relationship_type") or "")
        src, dst = str(rel.get("source_ref") or ""), str(rel.get("target_ref") or "")
        if rtype == "detects" and src in strategies:
            sid = _ext_id(strategies[src]) or src.split("--")[-1][:12]
            tech_strategies[dst].append(sid)
        elif rtype == "mitigates":
            mid = _ext_id(by_stix.get(src, {}))
            if mid:
                tech_mitigations[dst].append(mid)
        elif rtype == "uses":
            tech_procedures[dst].append(src)
        elif rtype == "subtechnique-of":
            parents[src] = _ext_id(by_stix.get(dst, {})) or dst
        elif rtype == "revoked-by":
            revoked_by[src] = _ext_id(by_stix.get(dst, {})) or dst

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        tid = _ext_id(obj)
        if not tid:
            continue
        counts["techniques"] += 1
        stix_id = str(obj.get("id"))
        row = techniques.setdefault(tid, {
            "id": tid,
            "name": str(obj.get("name") or "").strip(),
            "matrices": [],
            "tactics": [],
            "platforms": [str(p) for p in (obj.get("x_mitre_platforms") or [])],
            "sub": bool(obj.get("x_mitre_is_subtechnique")),
            "parent": "",
            "revoked": False,
            "deprecated": False,
            "revoked_by": "",
            "description": _clean(obj.get("description"), _DESC_CAP),
            "detection": [],
            "mitigations": [],
            "procedures": [],
        })
        if matrix not in row["matrices"]:
            row["matrices"].append(matrix)
        for tactic in _tactics(obj):
            if tactic not in row["tactics"]:
                row["tactics"].append(tactic)
        row["revoked"] = bool(obj.get("revoked")) or row["revoked"]
        row["deprecated"] = bool(obj.get("x_mitre_deprecated")) or row["deprecated"]
        if parents.get(stix_id) and not row["parent"]:
            row["parent"] = parents[stix_id]
        if revoked_by.get(stix_id) and not row["revoked_by"]:
            row["revoked_by"] = revoked_by[stix_id]

        # Detection strategies -> analytics (names + platform + short text).
        for sid in tech_strategies.get(stix_id, [])[:_MAX_STRATEGIES]:
            strategy = next(
                (s for s in strategies.values() if (_ext_id(s) or "") == sid), None
            )
            if strategy is None:
                continue
            entry = {
                "id": sid,
                "name": _clean(strategy.get("name"), 160),
                "analytics": [],
            }
            for aref in (strategy.get("x_mitre_analytic_refs") or [])[:_MAX_ANALYTICS]:
                ana = analytics.get(str(aref))
                if not ana:
                    continue
                logs = [
                    _clean((ls or {}).get("name"), 60)
                    for ls in (ana.get("x_mitre_log_source_references") or [])
                ]
                entry["analytics"].append({
                    "name": _clean(ana.get("name"), 80),
                    "platforms": [str(p) for p in (ana.get("x_mitre_platforms") or [])],
                    "description": _clean(ana.get("description"), _ANALYTIC_CAP),
                    "log_sources": [x for x in logs if x][:3],
                })
                counts["analytics"] += 1
            counts["strategies"] += 1
            row["detection"].append(entry)

        # Mitigations + procedures (names only, capped).
        for mid in tech_mitigations.get(stix_id, []):
            mit = next(
                (o for o in objects
                 if o.get("type") == "course-of-action" and _ext_id(o) == mid),
                None,
            )
            if mit and len(row["mitigations"]) < _MAX_MITIGATIONS:
                row["mitigations"].append({
                    "id": mid, "name": _clean(mit.get("name"), 120),
                })
                counts["mitigations"] += 1
        seen_proc: set[str] = set()
        for src in tech_procedures.get(stix_id, []):
            src_obj = by_stix.get(src)
            if not src_obj:
                continue
            name = str(src_obj.get("name") or "").strip()
            if not name or name in seen_proc:
                continue
            seen_proc.add(name)
            if len(row["procedures"]) >= _MAX_PROCEDURES:
                break
            row["procedures"].append({
                "name": name[:120],
                "type": str(src_obj.get("type") or ""),
                "id": _ext_id(src_obj),
            })
            counts["procedures"] += 1

    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="force re-download")
    args = parser.parse_args()

    ATTACK_DIR.mkdir(parents=True, exist_ok=True)
    if args.fetch:
        for name in MATRICES:
            (ATTACK_DIR / f"{name}-attack.json").unlink(missing_ok=True)

    techniques: dict[str, dict] = {}
    per_matrix: dict[str, dict] = {}
    hashes: dict[str, str] = {}
    for name, url in MATRICES.items():
        path = _fetch(name, url)
        hashes[name] = _sha256(path)
        per_matrix[name] = compile_matrix(path, name, techniques)

    active = [t for t in techniques.values() if not t["revoked"] and not t["deprecated"]]
    strategies_total = len({d["id"] for t in techniques.values() for d in t["detection"]})
    registry = {
        "version": "v19 (attack-stix-data master)",
        "source": "https://github.com/mitre-attack/attack-stix-data",
        "license": "CC BY 4.0 (c) The MITRE Corporation - see attack/NOTICE.txt",
        "raw_sha256": hashes,
        "generated": datetime.now(UTC).isoformat(),
        "counts": {
            "techniques": len(techniques),
            "active": len(active),
            "subtechniques": sum(1 for t in techniques.values() if t["sub"]),
            "revoked": sum(1 for t in techniques.values() if t["revoked"]),
            "deprecated": sum(1 for t in techniques.values() if t["deprecated"]),
            "detection_strategies": strategies_total,
            "per_matrix": per_matrix,
        },
        "techniques": sorted(techniques.values(), key=lambda t: t["id"]),
    }

    import yaml

    OUT_PATH.write_text(
        yaml.safe_dump(registry, sort_keys=False, allow_unicode=True, width=120),
        encoding="utf-8",
    )
    print(f"wrote {OUT_PATH} ({OUT_PATH.stat().st_size / 1e6:.2f} MB)")
    print("counts:", json.dumps(registry["counts"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
