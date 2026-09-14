"""Sync proven upstream knowledge feeds into machine-aligned knowledge files.

WP 9.4 — keeps the curated `needles/*.yaml` (hand-tuned) and adds a synced
`knowledge/sources/` layer that mirrors the upstream projects, with provenance
(source URL + fetch date + count) so refreshes are reproducible and auditable.

Sources (all first-party / canonical):
  lolbas    https://lolbas-project.github.io/api/lolbas.json          (JSON API)
  gtfobins  https://github.com/GTFOBins/GTFOBins.github.io            (repo tarball -> _gtfobins/*)
  wadcoms   https://github.com/WADComs/WADComs.github.io              (repo -> _data/items.yml)
  attack    https://github.com/mitre-attack/attack-stix-data           (enterprise/mobile/ics STIX)
  cisa_kev  https://www.cisa.gov/.../known_exploited_vulnerabilities.json

Usage:
    python scripts\\sync_knowledge_sources.py            # all sources
    python scripts\\sync_knowledge_sources.py --only lolbas,cisa_kev
"""
from __future__ import annotations

import argparse
import io
import json
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

import yaml

_UA = "Mozilla/5.0 (DFIR-Nexus knowledge sync; local research)"
_REPO = Path(__file__).resolve().parents[1]
_SOURCES = _REPO / "src" / "nexus" / "data" / "knowledge" / "sources"

_LOLBAS = "https://lolbas-project.github.io/api/lolbas.json"
_GTFOBINS_TAR = "https://codeload.github.com/GTFOBins/GTFOBins.github.io/tar.gz/refs/heads/master"
_WADCOMS_TAR = "https://codeload.github.com/WADComs/WADComs.github.io/tar.gz/refs/heads/master"
_ATTACK = {
    "enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
    "ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
}
_KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (canonical hosts)
        return r.read()


def _write(name: str, payload: dict) -> Path:
    _SOURCES.mkdir(parents=True, exist_ok=True)
    path = _SOURCES / f"{name}.yaml"
    path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=1000),
                    encoding="utf-8")
    return path


def _header(source: str, url: str, count: int, extra: dict | None = None) -> dict:
    head = {
        "version": 1,
        "kind": "synced_source",
        "source": source,
        "url": url,
        "fetched": time.strftime("%Y-%m-%d"),
        "count": count,
    }
    if extra:
        head.update(extra)
    return head


def sync_lolbas() -> Path:
    data = json.loads(_get(_LOLBAS).decode("utf-8", "replace"))
    entries = []
    for item in data:
        commands = [str(c.get("Command", "")).strip() for c in (item.get("Commands") or [])
                    if str(c.get("Command", "")).strip()]
        entries.append({
            "binary": str(item.get("Name") or ""),
            "description": str(item.get("Description") or "")[:300],
            "commands": commands[:12],
            "paths": [str(p) for p in (item.get("Full_Path") or [])][:6],
            "attack": [str(t) for t in (item.get("MitreID") or [])],
        })
    return _write("lolbas", {**_header("lolbas-project", _LOLBAS, len(entries)), "entries": entries})


def _yaml_front(text: str) -> dict:
    """Parse YAML frontmatter tolerating GTFOBins' ``...`` terminator and
    WADComs' closing ``---``."""
    text = text.lstrip("\ufeff").lstrip()
    if text.startswith("---"):
        text = text[3:]
    text = text.rstrip()
    if text.endswith("..."):
        text = text[:-3]
    idx = text.find("\n---")
    if idx != -1:
        text = text[:idx]
    try:
        data = yaml.safe_load(text)
    except Exception:  # noqa: BLE001
        return {}
    return data if isinstance(data, dict) else {}


def sync_gtfobins() -> Path:
    blob = _get(_GTFOBINS_TAR, timeout=180)
    entries = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile() or "/_gtfobins/" not in member.name:
                continue
            raw = tf.extractfile(member)
            if raw is None:
                continue
            meta = _yaml_front(raw.read().decode("utf-8", "replace"))
            fns = meta.get("functions")
            if not isinstance(fns, dict):
                continue
            name = member.name.rsplit("/", 1)[-1]
            entries.append({
                "binary": name,
                "functions": sorted(str(k) for k in fns),
                "contexts": sorted({c for v in fns.values() if isinstance(v, list)
                                    for item in v if isinstance(item, dict)
                                    for c in (item.get("contexts") or {})}),
            })
    entries.sort(key=lambda e: e["binary"])
    return _write("gtfobins", {
        **_header("GTFOBins", "https://gtfobins.github.io/", len(entries)),
        "entries": entries,
    })


def sync_wadcoms() -> Path:
    blob = _get(_WADCOMS_TAR, timeout=180)
    entries = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile() or "/_wadcoms/" not in member.name:
                continue
            if not member.name.endswith(".md"):
                continue
            raw = tf.extractfile(member)
            if raw is None:
                continue
            meta = _yaml_front(raw.read().decode("utf-8", "replace"))
            cmd = str(meta.get("command") or "").strip()
            if not cmd:
                continue
            name = member.name.rsplit("/", 1)[-1][:-3]
            entries.append({
                "name": name[:120],
                "command": cmd[:400],
                "description": str(meta.get("description") or "")[:240],
                "os": str(meta.get("OS") or ""),
                "services": [str(s) for s in (meta.get("Services") or [])] if isinstance(meta.get("Services"), list) else [],
                "attack_types": [str(a) for a in (meta.get("AttackTypes") or [])] if isinstance(meta.get("AttackTypes"), list) else [],
            })
    entries.sort(key=lambda e: e["name"].lower())
    return _write("wadcoms", {
        **_header("WADComs", "https://wadcoms.github.io/", len(entries)), "entries": entries})


def sync_attack() -> Path:
    entries: dict[str, dict] = {}
    for matrix, url in _ATTACK.items():
        bundle = json.loads(_get(url, timeout=180).decode("utf-8", "replace"))
        for obj in bundle.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            ext_id = ""
            for ref in (obj.get("external_references") or []):
                if ref.get("source_name") == "mitre-attack":
                    ext_id = str(ref.get("external_id") or "")
                    break
            if not ext_id:
                continue
            tactics = sorted({p.get("phase_name", "") for p in (obj.get("kill_chain_phases") or [])
                              if p.get("phase_name")})
            rec = entries.setdefault(ext_id, {
                "technique": ext_id,
                "name": str(obj.get("name") or ""),
                "matrices": [],
                "tactics": [],
                "platforms": [],
            })
            rec["matrices"] = sorted(set(rec["matrices"] + [matrix]))
            rec["tactics"] = sorted(set(rec["tactics"] + tactics))
            rec["platforms"] = sorted(set(rec["platforms"] + [str(p) for p in (obj.get("x_mitre_platforms") or [])]))
    rows = [entries[k] for k in sorted(entries)]
    return _write("attack_techniques", {
        **_header("MITRE ATT&CK", "https://github.com/mitre-attack/attack-stix-data", len(rows),
                 {"matrices": sorted(_ATTACK.keys())}),
        "entries": rows,
    })


def sync_cisa_kev() -> Path:
    data = json.loads(_get(_KEV, timeout=120).decode("utf-8", "replace"))
    rows = []
    for v in data.get("vulnerabilities", []):
        rows.append({
            "cve": str(v.get("cveID") or ""),
            "vendor": str(v.get("vendorProject") or ""),
            "product": str(v.get("product") or ""),
            "name": str(v.get("vulnerabilityName") or "")[:160],
            "dateAdded": str(v.get("dateAdded") or ""),
            "ransomware": str(v.get("knownRansomwareCampaignUse") or ""),
        })
    rows.sort(key=lambda r: r.get("dateAdded", ""), reverse=True)
    return _write("cisa_kev", {
        **_header("CISA KEV", _KEV, len(rows), {"catalogVersion": data.get("catalogVersion")}),
        "entries": rows,
    })


SYNCERS = {
    "lolbas": sync_lolbas,
    "gtfobins": sync_gtfobins,
    "wadcoms": sync_wadcoms,
    "attack": sync_attack,
    "cisa_kev": sync_cisa_kev,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--only", default=None, help="comma-separated subset, e.g. lolbas,cisa_kev")
    args = ap.parse_args()
    wanted = [s.strip() for s in args.only.split(",")] if args.only else list(SYNCERS)
    ok = 0
    for name in wanted:
        fn = SYNCERS.get(name)
        if fn is None:
            print(f"unknown source: {name}", file=sys.stderr)
            continue
        try:
            path = fn()
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            print(f"sync {name}: {data.get('count')} entries -> {path.name}")
            ok += 1
        except Exception as exc:  # noqa: BLE001
            print(f"FAIL {name}: {type(exc).__name__} {exc}", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
