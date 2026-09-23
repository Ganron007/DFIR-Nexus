"""Compile MITRE ATLAS (AI/ML adversarial threat landscape) into a registry.

Source: https://github.com/mitre-atlas/atlas-data (`dist/ATLAS.yaml`,
Apache-2.0, (C) 2021-2026 MITRE - attribution in ``atlas/NOTICE.txt``).
ATLAS is the AI-era counterpart of ATT&CK: tactics (AML.TAxxxx), techniques
(AML.Txxxx incl. sub-techniques), mitigations (AML.Mxxxx) and case studies
(AML.CSxxxx), with ATT&CK cross-references on part of the techniques.

The raw YAML is gitignored; the compiled ``atlas_registry.yaml`` is committed.

Usage:
    python scripts/build_atlas_registry.py            # use cached raw or fetch
    python scripts/build_atlas_registry.py --fetch    # force re-download
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
ATLAS_DIR = ROOT / "src" / "nexus" / "data" / "knowledge" / "atlas"
RAW_PATH = ATLAS_DIR / "ATLAS.yaml"
OUT_PATH = ATLAS_DIR / "atlas_registry.yaml"
RAW_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"

_HTML_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def _clean(text: str, cap: int) -> str:
    text = _HTML_TAG.sub(" ", str(text or ""))
    text = text.replace("&nbsp;", " ").replace("&amp;", "&")
    return _WS.sub(" ", text).strip()[:cap]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest().upper()


def _fetch() -> None:
    print(f"fetching {RAW_URL}")
    with urllib.request.urlopen(RAW_URL, timeout=180) as r:
        data = r.read()
    RAW_PATH.write_bytes(data)
    print(f"wrote {RAW_PATH} ({len(data) / 1e3:.0f} KB)")


def _attack_refs(value) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in value if isinstance(value, list) else ([value] if value else []):
        if isinstance(item, dict) and item.get("id"):
            out.append({
                "id": str(item.get("id")),
                "url": str(item.get("url") or ""),
            })
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="force re-download")
    args = parser.parse_args()

    ATLAS_DIR.mkdir(parents=True, exist_ok=True)
    if args.fetch or not RAW_PATH.is_file():
        _fetch()

    import yaml

    data = yaml.safe_load(RAW_PATH.read_text(encoding="utf-8"))
    matrices = data.get("matrices") or []
    matrix = matrices[0] if matrices else {}

    tactics = [
        {
            "id": str(t.get("id")),
            "name": str(t.get("name") or ""),
            "description": _clean(t.get("description"), 300),
        }
        for t in (matrix.get("tactics") or []) if t.get("id")
    ]
    techniques = [
        {
            "id": str(t.get("id")),
            "name": str(t.get("name") or ""),
            "description": _clean(t.get("description"), 400),
            "tactics": [str(x) for x in (t.get("tactics") or []) if x],
            "maturity": str(t.get("maturity") or ""),
            "sub": str(t.get("id")).count(".") >= 2,
            "attack_refs": _attack_refs(t.get("ATT&CK-reference")),
        }
        for t in (matrix.get("techniques") or []) if t.get("id")
    ]
    mitigations = [
        {
            "id": str(m.get("id")),
            "name": str(m.get("name") or ""),
            "description": _clean(m.get("description"), 300),
            "category": str(m.get("category") or ""),
            "ml_lifecycle": [str(x) for x in (m.get("ml-lifecycle") or [])],
            "techniques": [
                {"id": str(x.get("id")), "use": _clean(x.get("use"), 160)}
                for x in (m.get("techniques") or []) if isinstance(x, dict) and x.get("id")
            ],
        }
        for m in (matrix.get("mitigations") or []) if m.get("id")
    ]
    case_studies = [
        {
            "id": str(c.get("id")),
            "name": str(c.get("name") or ""),
            "summary": _clean(c.get("summary"), 300),
            "incident_date": str(c.get("incident-date") or ""),
            "actor": _clean(c.get("actor"), 120),
            "target": _clean(c.get("target"), 160),
            "type": str(c.get("case-study-type") or ""),
        }
        for c in (data.get("case-studies") or []) if c.get("id")
    ]

    registry = {
        "version": str(data.get("version") or ""),
        "source": "https://github.com/mitre-atlas/atlas-data",
        "license": "Apache-2.0 (C) 2021-2026 MITRE - see atlas/NOTICE.txt",
        "raw_sha256": _sha256(RAW_PATH),
        "generated": datetime.now(UTC).isoformat(),
        "counts": {
            "tactics": len(tactics),
            "techniques": len(techniques),
            "subtechniques": sum(1 for t in techniques if t["sub"]),
            "mitigations": len(mitigations),
            "case_studies": len(case_studies),
            "attack_refs": sum(len(t["attack_refs"]) for t in techniques),
        },
        "tactics": tactics,
        "techniques": techniques,
        "mitigations": mitigations,
        "case_studies": case_studies,
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
