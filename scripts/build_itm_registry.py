"""Compile the Insider Threat Matrix JSON into a light registry YAML.

Source: https://github.com/forscie/insider-threat-matrix (Apache-2.0,
Forscie Limited - NOTICE retained next to the raw JSON). The raw JSON is
gitignored; this script fetches it when missing (sha256-pinned) and writes
``src/nexus/data/knowledge/itm/itm_registry.yaml`` - the shape the loader,
prompt block and ID validation consume.

Usage:
    python scripts/build_itm_registry.py            # use cached JSON or fetch
    python scripts/build_itm_registry.py --fetch    # force re-download
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
ITM_DIR = ROOT / "src" / "nexus" / "data" / "knowledge" / "itm"
RAW_PATH = ITM_DIR / "insider-threat-matrix.json"
OUT_PATH = ITM_DIR / "itm_registry.yaml"

RAW_URL = (
    "https://raw.githubusercontent.com/forscie/insider-threat-matrix/main/"
    "insider-threat-matrix.json"
)
# Pinned 2026-09-23 (v2.13.0, ATT&CK 19.2). Drift is reported, never silent.
EXPECTED_SHA256 = "963ED8945E85A3A600E4B13DC77AC4D53FC058D8E368AF3BA7DF7916C23A2E48"

_HTML_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def _clean(text: str, cap: int = 600) -> str:
    text = _HTML_TAG.sub(" ", str(text or ""))
    text = text.replace("&nbsp;", " ").replace("&amp;", "&")
    text = text.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
    return _WS.sub(" ", text).strip()[:cap]


def _fetch() -> None:
    print(f"fetching {RAW_URL}")
    with urllib.request.urlopen(RAW_URL, timeout=120) as r:
        data = r.read()
    RAW_PATH.write_bytes(data)
    print(f"wrote {RAW_PATH} ({len(data)} bytes)")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest().upper()


def _attack_refs(items) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        ref = str(item.get("ref") or "").strip()
        if not ref:
            continue
        out.append({
            "ref": ref,
            "name": str(item.get("name") or "").strip(),
            "url": str(item.get("url") or "").strip(),
        })
    return out


def _short_objects(items, key_cap: int = 120) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        oid = str(item.get("id") or "").strip()
        if not oid:
            continue
        out.append({
            "id": oid,
            "title": str(item.get("title") or "").strip()[:key_cap],
        })
    return out


def compile_registry(raw: dict) -> dict:
    articles_out: list[dict] = []
    counts = {"articles": 0, "sections": 0, "subsections": 0,
              "detections": 0, "preventions": 0, "attack_maps": 0}
    for article in raw.get("articles") or []:
        aid = str(article.get("id") or "").strip()
        if not aid:
            continue
        counts["articles"] += 1
        sections_out: list[dict] = []
        for section in article.get("sections") or []:
            sid = str(section.get("id") or "").strip()
            if not sid:
                continue
            counts["sections"] += 1
            subs = _short_objects(section.get("subsections"))
            dets = _short_objects(section.get("detections"))
            prevs = _short_objects(section.get("preventions"))
            maps = _attack_refs(section.get("mitre"))
            counts["subsections"] += len(subs)
            counts["detections"] += len(dets)
            counts["preventions"] += len(prevs)
            counts["attack_maps"] += len(maps)
            platforms = [
                str(p.get("name"))
                for p in (section.get("platforms") or [])
                if isinstance(p, dict) and p.get("name")
            ]
            sections_out.append({
                "id": sid,
                "title": str(section.get("title") or "").strip()[:160],
                "article": aid,
                "stage": str(article.get("title") or "").strip(),
                "description": _clean(
                    section.get("description_text") or section.get("description")
                ),
                "platforms": platforms,
                "attack": maps,
                "subsections": subs,
                "detections": dets,
                "preventions": prevs,
            })
        articles_out.append({
            "id": aid,
            "title": str(article.get("title") or "").strip(),
            "description": _clean(
                article.get("description_text") or article.get("description"), 400
            ),
            "attack": _attack_refs(article.get("mitre")),
            "sections": sections_out,
        })
    return {
        "version": str(raw.get("itm_version") or ""),
        "mitre_version": str(raw.get("mitre_version") or ""),
        "source": "https://insiderthreatmatrix.org/",
        "repo": "https://github.com/forscie/insider-threat-matrix",
        "license": "Apache-2.0 (Forscie Limited; see itm/NOTICE.txt)",
        "raw_sha256": _sha256(RAW_PATH),
        "generated": datetime.now(UTC).isoformat(),
        "counts": counts,
        "articles": articles_out,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true", help="force re-download")
    args = parser.parse_args()

    ITM_DIR.mkdir(parents=True, exist_ok=True)
    if args.fetch or not RAW_PATH.is_file():
        _fetch()
    digest = _sha256(RAW_PATH)
    if digest != EXPECTED_SHA256:
        print(f"WARNING: raw ITM JSON drifted from the pinned hash\n  pinned: {EXPECTED_SHA256}\n  actual: {digest}")

    raw = json.loads(RAW_PATH.read_text(encoding="utf-8"))
    registry = compile_registry(raw)

    import yaml

    OUT_PATH.write_text(
        yaml.safe_dump(registry, sort_keys=False, allow_unicode=True, width=100),
        encoding="utf-8",
    )
    size = OUT_PATH.stat().st_size
    print(f"wrote {OUT_PATH} ({size} bytes)")
    print("counts:", registry["counts"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
